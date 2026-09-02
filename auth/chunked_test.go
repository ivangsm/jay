package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestChunkedBodyIndicator(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		want    string
	}{
		{
			name: "plain signed payload is not framed",
			headers: map[string]string{
				"x-amz-content-sha256": sha256Hex("hello"),
			},
			want: "",
		},
		{
			name: "unsigned payload is not framed",
			headers: map[string]string{
				"x-amz-content-sha256": "UNSIGNED-PAYLOAD",
			},
			want: "",
		},
		{
			name:    "no headers at all",
			headers: nil,
			want:    "",
		},
		{
			// What minio-go (mc, warp) sends by default.
			name: "streaming signed payload",
			headers: map[string]string{
				"x-amz-content-sha256": "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
			},
			want: "x-amz-content-sha256",
		},
		{
			name: "streaming with trailer",
			headers: map[string]string{
				"x-amz-content-sha256": "STREAMING-UNSIGNED-PAYLOAD-TRAILER",
			},
			want: "x-amz-content-sha256",
		},
		{
			name: "declared literal is matched case-insensitively",
			headers: map[string]string{
				"x-amz-content-sha256": "streaming-aws4-hmac-sha256-payload",
			},
			want: "x-amz-content-sha256",
		},
		{
			// The case the declared hash alone would miss: framing sent
			// without announcing the STREAMING-* literal.
			name: "decoded content length without the literal",
			headers: map[string]string{
				"x-amz-content-sha256":         "UNSIGNED-PAYLOAD",
				"x-amz-decoded-content-length": "15",
			},
			want: "x-amz-decoded-content-length",
		},
		{
			name: "content-encoding alone",
			headers: map[string]string{
				"Content-Encoding": "aws-chunked",
			},
			want: "content-encoding",
		},
		{
			name: "content-encoding combined with another coding",
			headers: map[string]string{
				"Content-Encoding": "aws-chunked,gzip",
			},
			want: "content-encoding",
		},
		{
			name: "an ordinary content-encoding is not framing",
			headers: map[string]string{
				"Content-Encoding": "gzip",
			},
			want: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPut, "/bucket/key", strings.NewReader("body"))
			for k, v := range tc.headers {
				r.Header.Set(k, v)
			}
			if got := ChunkedBodyIndicator(r); got != tc.want {
				t.Errorf("ChunkedBodyIndicator = %q, want %q", got, tc.want)
			}
		})
	}
}
