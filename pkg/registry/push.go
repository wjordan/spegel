package registry

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/leases"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/containerd/v2/core/remotes/docker"
	"github.com/containerd/containerd/v2/pkg/labels"
	"github.com/containerd/errdefs"
	"github.com/google/uuid"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/spegel-org/spegel/pkg/httpx"
	"github.com/spegel-org/spegel/pkg/oci"
)

// Add a 10-minute temporary lease to newly created content and images.
func (r *Registry) withLease(ctx context.Context) (context.Context, error) {
	cd, ok := r.ociStore.(*oci.Containerd)
	if !ok {
		return nil, errors.New("lease requires containerd store")
	}
	cdc, err := cd.Client()
	if err != nil {
		return nil, err
	}
	lease := cdc.LeasesService()

	l, err := lease.Create(ctx, leases.WithRandomID(), leases.WithExpiration(10*time.Minute))
	if err != nil {
		return nil, fmt.Errorf("failed to create lease: %w", err)
	}
	return leases.WithLease(ctx, l.ID), nil
}

func (r *Registry) pushHandler(rw httpx.ResponseWriter, req *http.Request) {
	rw.SetHandler("push")

	if !r.pushEnabled {
		rw.WriteError(http.StatusMethodNotAllowed, oci.NewDistributionError(oci.ErrCodeUnsupported, "push endpoints disabled", nil))
		return
	}

	// Check basic authentication
	if r.username != "" || r.password != "" {
		username, password, _ := req.BasicAuth()
		if r.username != username || r.password != password {
			rw.WriteError(http.StatusUnauthorized, oci.NewDistributionError(oci.ErrCodeUnauthorized, "invalid credentials", nil))
			return
		}
	}

	// Parse out path components from request.
	dist, err := oci.ParseDistributionPath(req.URL)
	if err != nil {
		rw.WriteError(http.StatusNotFound, fmt.Errorf("could not parse path according to OCI distribution spec: %w", err))
		return
	}

	cdc, cs, err := r.getContainerdClient()
	if err != nil {
		rw.WriteError(http.StatusMethodNotAllowed, oci.NewDistributionError(oci.ErrCodeUnsupported, err.Error(), nil))
		return
	}

	if dist.Kind == oci.DistributionKindUpload {
		if req.Method == http.MethodPost && dist.Session == "" {
			if string(dist.Digest) == "" {
				r.handleBlobUploadStart(rw, req, dist, cs)
			} else {
				r.handleBlobUploadMonolithic(rw, req, dist, cs)
			}
			return
		}
		if dist.Session != "" {
			switch req.Method {
			case http.MethodPatch:
				r.handleBlobUploadChunk(rw, req, dist, cs)
				return
			case http.MethodPut:
				r.handleBlobUploadCommit(rw, req, dist, cs)
				return
			case http.MethodGet:
				r.handleBlobUploadGet(rw, req, dist, cs)
				return
			}
		}

	}

	if dist.Kind == oci.DistributionKindManifest && req.Method == http.MethodPut {
		r.handleManifestPut(rw, req, dist, cdc)
		return
	}

	rw.WriteError(http.StatusNotFound, oci.NewDistributionError(oci.ErrCodeUnsupported, "unsupported push endpoint", nil))
}

func (r *Registry) getContainerdClient() (*client.Client, content.Store, error) {
	cd, ok := r.ociStore.(*oci.Containerd)
	if !ok {
		return nil, nil, errors.New("push requires containerd store")
	}
	cdc, err := cd.Client()
	if err != nil {
		return nil, nil, err
	}
	return cdc, cdc.ContentStore(), nil
}

func (r *Registry) handleBlobUploadMonolithic(rw httpx.ResponseWriter, req *http.Request, dist oci.DistributionPath, cs content.Store) {
	expected := dist.Digest
	if err := expected.Validate(); err != nil {
		rw.WriteError(http.StatusBadRequest, oci.NewDistributionError(oci.ErrCodeDigestInvalid, "invalid digest", err.Error()))
		return
	}
	ctx, err := r.withLease(req.Context())
	if err != nil {
		rw.WriteError(http.StatusInternalServerError, err)
		return
	}

	w, err := cs.Writer(ctx, content.WithRef("spegel-upload:"+uuid.NewString()))
	if err != nil {
		rw.WriteError(http.StatusInternalServerError, err)
		return
	}
	defer w.Close()

	hasher := expected.Algorithm().Digester()
	n, err := io.Copy(io.MultiWriter(w, hasher.Hash()), req.Body)
	if err != nil {
		rw.WriteError(http.StatusInternalServerError, err)
		return
	}
	computed := hasher.Digest()
	if computed != expected {
		rw.WriteError(http.StatusBadRequest, oci.NewDistributionError(oci.ErrCodeDigestInvalid, "payload digest mismatch", nil))
		return
	}
	label := map[string]string{labels.LabelDistributionSource + "." + dist.Registry: dist.Name}
	if err := w.Commit(ctx, n, expected, content.WithLabels(label)); err != nil {
		rw.WriteError(http.StatusInternalServerError, err)
		return
	}

	rw.Header().Set(oci.HeaderDockerDigest, expected.String())
	rw.Header().Set("Location", "/v2/"+dist.Name+"/blobs/"+expected.String())
	rw.Header().Set(httpx.HeaderContentLength, "0")
	rw.WriteHeader(http.StatusCreated)
}

func (r *Registry) handleBlobUploadStart(rw httpx.ResponseWriter, req *http.Request, dist oci.DistributionPath, cs content.Store) {
	id := uuid.NewString()
	w, err := cs.Writer(req.Context(), content.WithRef("spegel-upload:"+id))
	if err != nil {
		rw.WriteError(http.StatusInternalServerError, err)
		return
	}
	_ = w.Close()
	rw.Header().Set("Location", "/v2/"+dist.Name+"/blobs/uploads/"+id)
	rw.Header().Set("Docker-Upload-UUID", id)
	rw.Header().Set("Range", "0-")
	rw.Header().Set(httpx.HeaderContentLength, "0")
	rw.WriteHeader(http.StatusAccepted)
}

func (r *Registry) handleBlobUploadChunk(rw httpx.ResponseWriter, req *http.Request, dist oci.DistributionPath, cs content.Store) {
	ctx, err := r.withLease(req.Context())
	if err != nil {
		rw.WriteError(http.StatusInternalServerError, err)
		return
	}

	w, err := cs.Writer(ctx, content.WithRef("spegel-upload:"+dist.Session))
	if err != nil {
		rw.WriteError(http.StatusNotFound, oci.NewDistributionError(oci.ErrCodeBlobUploadUnknown, "unknown upload session", nil))
		return
	}
	if _, err = io.Copy(w, req.Body); err != nil {
		rw.WriteError(http.StatusInternalServerError, err)
		return
	}

	status, err := w.Status()
	if err != nil {
		rw.WriteError(http.StatusInternalServerError, err)
		return
	}

	rw.Header().Set("Location", "/v2/"+dist.Name+"/blobs/uploads/"+dist.Session)
	rw.Header().Set("Range", "0-"+strconv.FormatInt(max(0, status.Offset-1), 10))
	rw.Header().Set("Docker-Upload-UUID", dist.Session)
	rw.Header().Set(httpx.HeaderContentLength, "0")
	rw.WriteHeader(http.StatusAccepted)
}

func (r *Registry) handleBlobUploadCommit(rw httpx.ResponseWriter, req *http.Request, dist oci.DistributionPath, cs content.Store) {
	if err := dist.Digest.Validate(); err != nil {
		rw.WriteError(http.StatusBadRequest, oci.NewDistributionError(oci.ErrCodeDigestInvalid, "invalid digest", err.Error()))
		return
	}
	ctx, err := r.withLease(req.Context())
	if err != nil {
		rw.WriteError(http.StatusInternalServerError, err)
		return
	}
	desc := ocispec.Descriptor{Digest: dist.Digest}
	w, err := cs.Writer(ctx, content.WithRef("spegel-upload:"+dist.Session), content.WithDescriptor(desc))
	if err != nil {
		rw.WriteError(http.StatusNotFound, oci.NewDistributionError(oci.ErrCodeBlobUploadUnknown, "unknown upload session", nil))
		return
	}
	defer w.Close()

	// final chunk
	if _, err = io.Copy(w, req.Body); err != nil {
		rw.WriteError(http.StatusInternalServerError, err)
		return
	}
	status, err := w.Status()
	if err != nil {
		rw.WriteError(http.StatusInternalServerError, err)
		return
	}

	label := map[string]string{labels.LabelDistributionSource + "." + dist.Registry: dist.Name}
	if err = w.Commit(ctx, status.Offset, dist.Digest, content.WithLabels(label)); err != nil && !errdefs.IsAlreadyExists(err) {
		rw.WriteError(http.StatusInternalServerError, err)
		return
	}

	rw.Header().Set(oci.HeaderDockerDigest, dist.Digest.String())
	rw.Header().Set("Location", "/v2/"+dist.Name+"/blobs/"+dist.Digest.String())
	rw.Header().Set(httpx.HeaderContentLength, "0")
	rw.WriteHeader(http.StatusCreated)
}

func (r *Registry) handleBlobUploadGet(rw httpx.ResponseWriter, req *http.Request, dist oci.DistributionPath, cs content.Store) {
	ctx, err := r.withLease(req.Context())
	if err != nil {
		rw.WriteError(http.StatusInternalServerError, err)
		return
	}
	status, err := cs.Status(ctx, "spegel-upload:"+dist.Session)
	if err != nil && errdefs.IsNotFound(err) {
		rw.WriteError(http.StatusNotFound, oci.NewDistributionError(oci.ErrCodeBlobUploadUnknown, "unknown upload session", nil))
		return
	} else if err != nil {
		rw.WriteError(http.StatusInternalServerError, err)
		return
	}

	rw.Header().Set("Range", "0-"+strconv.FormatInt(max(0, status.Offset-1), 10))
	rw.Header().Set("Location", "/v2/"+dist.Name+"/blobs/uploads/"+dist.Session)
	rw.Header().Set("Docker-Upload-UUID", dist.Session)
	rw.Header().Set(httpx.HeaderContentLength, "0")
	rw.WriteHeader(http.StatusNoContent)
}

func (r *Registry) handleManifestPut(rw httpx.ResponseWriter, req *http.Request, dist oci.DistributionPath, client *client.Client) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		rw.WriteError(http.StatusInternalServerError, err)
		return
	}
	mediaType := req.Header.Get(httpx.HeaderContentType)
	if mediaType == "" {
		mediaType, err = oci.DetermineMediaType(body)
		if err != nil {
			rw.WriteError(http.StatusBadRequest, oci.NewDistributionError(oci.ErrCodeManifestInvalid, "cannot determine manifest media type", nil))
			return
		}
	}
	dgst := digest.FromBytes(body)
	size := int64(len(body))
	desc := ocispec.Descriptor{MediaType: mediaType, Digest: dgst, Size: size}

	ctx, err := r.withLease(req.Context())
	if err != nil {
		rw.WriteError(http.StatusInternalServerError, err)
		return
	}

	cs := client.ContentStore()
	w, err := cs.Writer(ctx, content.WithRef(dist.Reference()))
	if err != nil && !errdefs.IsAlreadyExists(err) {
		rw.WriteError(http.StatusInternalServerError, err)
		return
	}
	if err == nil {
		defer w.Close()
		if _, err := io.Copy(w, bytes.NewReader(body)); err != nil {
			rw.WriteError(http.StatusInternalServerError, err)
			return
		}
		label := map[string]string{labels.LabelDistributionSource + "." + dist.Registry: dist.Name}
		if err := w.Commit(ctx, size, dgst, content.WithLabels(label)); err != nil && !errdefs.IsAlreadyExists(err) {
			rw.WriteError(http.StatusInternalServerError, err)
			return
		}
	}

	ref := dist.Reference()
	if dist.Digest != "" {
		ref = fmt.Sprintf("%s/%s@%s", dist.Registry, dist.Name, dist.Digest)
	}
	if _, err = client.ImageService().Create(ctx, (images.Image{Name: ref, Target: desc})); err != nil && !errdefs.IsAlreadyExists(err) {
		rw.WriteError(http.StatusInternalServerError, err)
		return
	}

	rw.Header().Set(oci.HeaderDockerDigest, dgst.String())
	rw.Header().Set("Location", "/v2/"+dist.Name+"/manifests/"+dgst.String())
	rw.Header().Set(httpx.HeaderContentLength, "0")
	rw.WriteHeader(http.StatusCreated)
	pushHeaders := req.Header.Clone()
	go func() {
		log := r.log.WithName("backgroundPush").WithValues("ref", ref, "desc", desc)
		log.Info("Starting upstream image push")
		ctx := context.Background()

		pusher, err := docker.NewResolver(docker.ResolverOptions{Headers: pushHeaders}).Pusher(ctx, ref)
		if err != nil {
			log.Error(err, "failed to get pusher")
			return
		}

		if err := remotes.PushContent(ctx, pusher, desc, cs, nil, nil, nil); err != nil {
			log.Error(err, "failed to push image upstream")
			return
		}
		log.Info("Finished upstream image push")
	}()
}
