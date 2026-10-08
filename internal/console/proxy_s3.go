package console

import (
	"errors"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/ivangsm/jay/meta"
)

// requestHeaders is what the S3 proxy forwards from the browser (canonical
// form). Everything else is dropped, in particular Cookie, Authorization,
// X-Forwarded-* and the SigV4 payload headers: the request is re-authorized
// from scratch by SignS3, and nothing the browser sent may pose as a
// credential or as proxy metadata.
var requestHeaders = map[string]bool{
	"Content-Type":             true,
	"Content-Md5":              true,
	"Content-Disposition":      true,
	"Cache-Control":            true,
	"Expires":                  true,
	"Range":                    true,
	"If-Match":                 true,
	"If-None-Match":            true,
	"If-Modified-Since":        true,
	"If-Unmodified-Since":      true,
	"X-Amz-Copy-Source":        true,
	"X-Amz-Metadata-Directive": true,
	"X-Amz-Checksum-Sha256":    true,
}

const metaPrefix = "x-amz-meta-"

// responseHeaders is what the browser sees from the S3 handler.
var responseHeaders = map[string]bool{
	"Content-Type":          true,
	"Content-Length":        true,
	"Content-Range":         true,
	"Accept-Ranges":         true,
	"Etag":                  true,
	"Last-Modified":         true,
	"Retry-After":           true,
	"X-Amz-Checksum-Sha256": true,
}

func s3ResponseHeader(canonical string) bool {
	return responseHeaders[canonical] || strings.HasPrefix(strings.ToLower(canonical), metaPrefix)
}

// s3RequestIDHeader carries the S3 handler's request id; the plain
// x-amz-request-id of the response stays the console listener's own.
const s3RequestIDHeader = "X-Jay-S3-Request-Id"

// serveS3Proxy forwards /console/api/s3/<bucket>[/<key>] to the S3 handler,
// authorized as the token named by as_token ("browse as"). The console decides
// nothing about the data: the S3 handler re-validates the token, its account,
// its scope and the bucket policy exactly as it would for any client.
func (h *Handler) serveS3Proxy(w http.ResponseWriter, r *http.Request) {
	// Object bytes are served from the console's origin: they are never
	// rendered there.
	hd := w.Header()
	hd.Set("Content-Security-Policy", cspObject)
	hd.Set("X-Content-Type-Options", "nosniff")
	hd.Set("Cache-Control", "no-store")

	if _, ok := h.requireSessionCSRF(w, r); !ok {
		return
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodPut, http.MethodPost, http.MethodDelete:
	default:
		methodNotAllowed(w, "GET, HEAD, PUT, POST, DELETE")
		return
	}

	query := r.URL.Query()
	asTokens := query["as_token"]
	if len(asTokens) != 1 || asTokens[0] == "" {
		writeJSONError(w, http.StatusBadRequest, "as_token is required")
		return
	}
	tokenID := asTokens[0]
	query.Del("as_token")
	for name := range query {
		lower := strings.ToLower(name)
		if strings.HasPrefix(lower, "x-jay-") || strings.HasPrefix(lower, "x-amz-") {
			writeJSONError(w, http.StatusBadRequest, "presigned parameters are not accepted here")
			return
		}
	}
	if !h.ready() {
		writeJSONError(w, http.StatusServiceUnavailable,
			"startup recovery is still running; object operations are refused until it finishes")
		return
	}
	if status, msg := h.checkBrowseAs(tokenID); status != 0 {
		writeJSONError(w, status, msg)
		return
	}
	if strings.Contains(strings.ToLower(r.Header.Get("Content-Encoding")), "aws-chunked") {
		writeJSONError(w, http.StatusBadRequest, "aws-chunked uploads are not supported through the console")
		return
	}

	s3Path := strings.TrimPrefix(r.URL.Path, pathS3)
	bucket, key := splitBucketKey(s3Path)

	out := r.Clone(r.Context())
	out.URL = &url.URL{Path: s3Path, RawQuery: query.Encode()}
	out.RequestURI = out.URL.RequestURI()
	out.Header = make(http.Header)
	for name, vals := range r.Header {
		canonical := http.CanonicalHeaderKey(name)
		if requestHeaders[canonical] || strings.HasPrefix(strings.ToLower(canonical), metaPrefix) {
			out.Header[canonical] = slices.Clone(vals)
		}
	}
	out.Body = r.Body
	out.ContentLength = r.ContentLength
	out.TransferEncoding = r.TransferEncoding
	out.Trailer = nil

	if err := h.signS3(out, tokenID); err != nil {
		h.log.Error("console s3 presign", "error", err, "as_token", tokenID)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}

	download := safeMethod(r.Method) && key != "" && !query.Has("uploadId")
	fw := newFilterWriter(w, filterOptions{
		allow:           s3ResponseHeader,
		requestIDHeader: s3RequestIDHeader,
		finalize: func(status int, dst http.Header) {
			if download && (status == http.StatusOK || status == http.StatusPartialContent) {
				dst.Set("Content-Disposition", attachment(key))
			}
		},
	})
	h.s3.ServeHTTP(fw, out)
	fw.finish()

	if !safeMethod(r.Method) && fw.status/100 == 2 {
		keys := slices.Sorted(maps.Keys(query))
		if keys == nil {
			keys = []string{}
		}
		h.audit(r, "console.s3",
			slog.String("method", r.Method),
			slog.String("bucket", bucket),
			slog.String("key", key),
			slog.Any("query_keys", keys),
			slog.String("as_token", tokenID),
			slog.Int("status", fw.status),
			slog.String("s3_request_id", fw.innerRequestID),
		)
	}
}

// checkBrowseAs explains, before the S3 handler would, why a token cannot be
// browsed as. It is only for the message: the handler re-validates everything,
// so a divergence here costs a less precise error, never a hole. status 0
// means the token is usable.
func (h *Handler) checkBrowseAs(tokenID string) (status int, msg string) {
	tok, err := h.tokens.GetToken(tokenID)
	if err != nil {
		if errors.Is(err, meta.ErrTokenNotFound) {
			return http.StatusNotFound, "token not found"
		}
		h.log.Error("console read token", "error", err, "as_token", tokenID)
		return http.StatusInternalServerError, "internal error"
	}
	if tok.Status != "active" {
		return http.StatusConflict, "token is revoked"
	}
	if tok.ExpiresAt != nil && !h.now().Before(*tok.ExpiresAt) {
		return http.StatusConflict, "token expired at " + tok.ExpiresAt.UTC().Format(time.RFC3339)
	}
	acct, err := h.tokens.GetAccount(tok.AccountID)
	if err != nil {
		if errors.Is(err, meta.ErrAccountNotFound) {
			return http.StatusConflict, "token's account not found"
		}
		h.log.Error("console read account", "error", err, "account_id", tok.AccountID)
		return http.StatusInternalServerError, "internal error"
	}
	if acct.Status != "active" {
		return http.StatusConflict, "token's account is " + acct.Status
	}
	return 0, ""
}

// splitBucketKey splits "/bucket/some/key" into bucket and key.
func splitBucketKey(p string) (bucket, key string) {
	p = strings.TrimPrefix(p, "/")
	bucket, key, _ = strings.Cut(p, "/")
	return bucket, key
}

// attachment is the Content-Disposition of a downloaded object: always an
// attachment, named after the last segment of the key in RFC 5987 form.
func attachment(key string) string {
	base := key[strings.LastIndex(key, "/")+1:]
	if base == "" {
		return "attachment"
	}
	return "attachment; filename*=UTF-8''" + encodeRFC5987(base)
}

// encodeRFC5987 percent-encodes everything outside attr-char.
func encodeRFC5987(s string) string {
	const hexDigits = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			strings.IndexByte("!#$&+-.^_`|~", c) >= 0:
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(hexDigits[c>>4])
			b.WriteByte(hexDigits[c&0x0f])
		}
	}
	return b.String()
}

// filterOptions configures a filterWriter.
type filterOptions struct {
	// allow decides, per canonical header name, what reaches the browser.
	allow func(canonical string) bool
	// requestIDHeader, when set, receives the inner x-amz-request-id.
	requestIDHeader string
	// finalize may add headers once the status is known.
	finalize func(status int, dst http.Header)
}

// filterWriter lets a handler we do not control write a response while only an
// allowlist of its headers reaches the browser. It also records the status and
// the inner request id for the audit line.
type filterWriter struct {
	dst  http.ResponseWriter
	hdr  http.Header
	opts filterOptions

	wrote          bool
	status         int
	innerRequestID string
}

func newFilterWriter(dst http.ResponseWriter, opts filterOptions) *filterWriter {
	return &filterWriter{dst: dst, hdr: make(http.Header), opts: opts}
}

// finish commits the implicit 200 of a handler that returned without writing,
// so the status the audit line reads is the one the client got.
func (f *filterWriter) finish() {
	if !f.wrote {
		f.WriteHeader(http.StatusOK)
	}
}

func (f *filterWriter) Header() http.Header { return f.hdr }

func (f *filterWriter) WriteHeader(code int) {
	if f.wrote {
		return
	}
	f.wrote = true
	f.status = code
	out := f.dst.Header()
	for name, vals := range f.hdr {
		canonical := http.CanonicalHeaderKey(name)
		if canonical == "X-Amz-Request-Id" {
			if len(vals) > 0 {
				f.innerRequestID = vals[0]
			}
			if f.opts.requestIDHeader != "" && len(vals) > 0 {
				out.Set(f.opts.requestIDHeader, vals[0])
			}
			continue
		}
		if f.opts.allow(canonical) {
			out[canonical] = slices.Clone(vals)
		}
	}
	if f.opts.finalize != nil {
		f.opts.finalize(code, out)
	}
	f.dst.WriteHeader(code)
}

func (f *filterWriter) Write(b []byte) (int, error) {
	if !f.wrote {
		f.WriteHeader(http.StatusOK)
	}
	return f.dst.Write(b)
}

// ReadFrom keeps zero-copy reachable for handlers that copy a file into the
// response.
func (f *filterWriter) ReadFrom(r io.Reader) (int64, error) {
	if !f.wrote {
		f.WriteHeader(http.StatusOK)
	}
	if rf, ok := f.dst.(io.ReaderFrom); ok {
		return rf.ReadFrom(r)
	}
	return io.Copy(struct{ io.Writer }{f.dst}, r)
}

// Flush sends the filtered headers first: flushing the raw writer would
// commit the response without them.
func (f *filterWriter) Flush() {
	if !f.wrote {
		f.WriteHeader(http.StatusOK)
	}
	if fl, ok := f.dst.(http.Flusher); ok {
		fl.Flush()
	}
}

// Unwrap lets http.ResponseController reach the connection (deadlines). It
// exposes no header map, so it cannot bypass the filter.
func (f *filterWriter) Unwrap() http.ResponseWriter { return f.dst }

var (
	_ http.ResponseWriter = (*filterWriter)(nil)
	_ http.Flusher        = (*filterWriter)(nil)
	_ io.ReaderFrom       = (*filterWriter)(nil)
)
