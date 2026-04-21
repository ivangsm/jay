package proto

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/ivangsm/jay/internal/objops"
	"github.com/ivangsm/jay/meta"
)

// mapObjopsStatus translates an objops.* sentinel into the proto StatusFoo
// byte + error-code string used by EncodeError. Returns (0, "", "") when the
// error is not a known objops sentinel — caller should treat as StatusInternal.
func mapObjopsStatus(err error) (status byte, msg, code string, handled bool) {
	switch {
	case errors.Is(err, objops.ErrBucketNotFound):
		return StatusNotFound, "bucket not found", "NoSuchBucket", true
	case errors.Is(err, objops.ErrObjectNotFound):
		return StatusNotFound, "object not found", "NoSuchKey", true
	case errors.Is(err, objops.ErrPolicyDenied), errors.Is(err, objops.ErrAccessDenied):
		return StatusForbidden, "access denied", "AccessDenied", true
	}
	return 0, "", "", false
}

// handlePutObject delegates to objops.Service. On auth/bucket errors the
// frame data MUST be drained (up to MaxDrainSize) so the connection stays
// in a readable state for the next request.
func (h *connHandler) handlePutObject(req *request) error {
	bucket, key, contentType, metadata, err := DecodePutObjectRequest(req.meta)
	if err != nil {
		if derr := drainData(req); derr != nil {
			return derr
		}
		return h.writeError(StatusBadRequest, req.streamID, "invalid request", "InvalidArgument")
	}

	// objops authorizes internally; on auth failure the body may still be
	// fully consumed because PutObject streams it into the store before
	// returning. Authorization happens BEFORE streaming though (authorize
	// runs immediately after bucket resolution), so an auth rejection aborts
	// early and we drain the remainder of the frame.
	//
	// However, the current objops.PutObject does the authorize BEFORE writing
	// bytes but does NOT drain req.data if authorize fails — so we handle
	// that here. We call HeadObject-style auth first? No — simpler: let
	// PutObject run; if it returns an auth error before reading, we drain.
	obj, err := h.objops.PutObject(
		nil, h.token,
		bucket, key, contentType,
		req.data,
		objops.PutOptions{UserMetadata: metadata},
		h.identity(meta.ActionObjectPut),
	)
	if err != nil {
		// Drain any unread body bytes so the frame boundary is respected.
		if derr := drainData(req); derr != nil {
			// Data was larger than MaxDrainSize — the only safe response is
			// to report the error and let the server loop close the conn.
			return derr
		}
		if status, m, code, ok := mapObjopsStatus(err); ok {
			return h.writeError(status, req.streamID, m, code)
		}
		h.log.Error("put object", "err", err, "bucket", bucket, "key", key)
		return h.writeError(StatusInternal, req.streamID, "failed to store object", "InternalError")
	}

	return h.writeResponseCombined(StatusOK, req.streamID, EncodePutResponse(obj.ETag, obj.ChecksumSHA256))
}

// handleGetObject streams the object body to the connection via WriteFrame,
// which uses io.CopyN on a *bufio.Writer. The buffer is small (64KB) and is
// backed by the net.Conn; we do NOT wrap or re-hash — sendfile only fires on
// raw *net.TCPConn writes, not through a bufio.Writer, but the streaming is
// still zero-allocation per chunk once the data_len is known. The scrubber
// owns read-time integrity verification.
func (h *connHandler) handleGetObject(req *request) error {
	bucket, key, err := DecodeBucketKey(req.meta)
	if err != nil {
		return h.writeError(StatusBadRequest, req.streamID, "invalid request", "InvalidArgument")
	}

	obj, err := h.objops.HeadObject(nil, h.token, bucket, key, h.identity(meta.ActionObjectGet))
	if err != nil {
		if status, m, code, ok := mapObjopsStatus(err); ok {
			return h.writeError(status, req.streamID, m, code)
		}
		return h.writeError(StatusInternal, req.streamID, "internal error", "InternalError")
	}

	f, err := h.objops.OpenObjectFile(obj)
	if err != nil {
		h.log.Error("read object", "err", err, "location", obj.LocationRef)
		return h.writeError(StatusInternal, req.streamID, "failed to read object", "InternalError")
	}
	defer func() { _ = f.Close() }()

	resp := EncodeObjectInfo(
		obj.ContentType, obj.SizeBytes,
		obj.ETag, obj.ChecksumSHA256,
		obj.UpdatedAt.Format(time.RFC3339),
		obj.MetadataHeaders,
	)
	// WriteFrame copies exactly SizeBytes from f into the bufio writer; the
	// subsequent Flush in handleOneRequest drains to the TCP conn. An io.Copy
	// directly to the net.Conn would be marginally better for sendfile, but
	// changing the framing contract here is out of scope — frames are the
	// protocol.
	return h.writeResponse(StatusOK, req.streamID, resp, f, obj.SizeBytes)
}

// handleHeadObject returns object metadata only. No body frame.
func (h *connHandler) handleHeadObject(req *request) error {
	bucket, key, err := DecodeBucketKey(req.meta)
	if err != nil {
		return h.writeError(StatusBadRequest, req.streamID, "invalid request", "InvalidArgument")
	}

	obj, err := h.objops.HeadObject(nil, h.token, bucket, key, h.identity(meta.ActionObjectGet))
	if err != nil {
		if status, m, code, ok := mapObjopsStatus(err); ok {
			return h.writeError(status, req.streamID, m, code)
		}
		return h.writeError(StatusInternal, req.streamID, "internal error", "InternalError")
	}

	resp := EncodeObjectInfo(
		obj.ContentType, obj.SizeBytes,
		obj.ETag, obj.ChecksumSHA256,
		obj.UpdatedAt.Format(time.RFC3339),
		obj.MetadataHeaders,
	)
	return h.writeResponseCombined(StatusOK, req.streamID, resp)
}

// handleDeleteObject returns StatusOK for both existing-then-deleted and
// already-absent objects (S3 semantics). objops.DeleteObject collapses the
// not-found case into nil, so we only have to distinguish the policy /
// bucket-not-found / internal branches.
func (h *connHandler) handleDeleteObject(req *request) error {
	bucket, key, err := DecodeBucketKey(req.meta)
	if err != nil {
		return h.writeError(StatusBadRequest, req.streamID, "invalid request", "InvalidArgument")
	}

	if err := h.objops.DeleteObject(nil, h.token, bucket, key, h.identity(meta.ActionObjectDelete)); err != nil {
		if status, m, code, ok := mapObjopsStatus(err); ok {
			return h.writeError(status, req.streamID, m, code)
		}
		h.log.Error("delete object", "err", err, "bucket", bucket, "key", key)
		return h.writeError(StatusInternal, req.streamID, "internal error", "InternalError")
	}
	return h.writeResponse(StatusOK, req.streamID, nil, nil, 0)
}

// errDataTooLarge is returned by drainData when the remaining data exceeds
// MaxDrainSize, indicating the connection must be closed.
var errDataTooLarge = fmt.Errorf("data too large to drain, closing connection")

func drainData(req *request) error {
	if req.data == nil || req.dataLen == 0 {
		return nil
	}
	if req.dataLen > MaxDrainSize {
		return errDataTooLarge
	}
	_, err := io.CopyN(io.Discard, req.data, req.dataLen)
	return err
}

// emptyReader is used by multipart upload handling when a part carries no
// body bytes. Kept here (not moved to objops) because the proto multipart
// handlers still pass a raw reader to store.WritePart directly — they do not
// route through objops yet.
type emptyReader struct{}

func (e *emptyReader) Read(p []byte) (int, error) { return 0, io.EOF }
