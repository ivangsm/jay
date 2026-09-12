package client

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/ivangsm/jay/auth"
)

// PresignURL returns a SigV4 query-string presigned URL for one S3 operation
// on the object — the form `aws s3 presign`, boto3 and minio-go produce — that
// any HTTP client can use against jay's S3 listener until it expires.
//
// It is computed locally: the signature is an HMAC over the token secret this
// client already holds, exactly as the AWS SDKs do it, so there is no round
// trip and no opcode. What it needs from Dial is WithS3Endpoint, because the
// signature covers the host and the native address is not it.
//
// expires must be positive and at most 7 days (auth.MaxPresignExpiry). method
// is the HTTP method the URL is for: GET to download, PUT to upload, HEAD or
// DELETE. The token's scope still applies when the URL is used.
//
// It takes no context because nothing here can block: it is the one method
// of this client that never touches the network.
func (c *Client) PresignURL(method, bucket, key string, expires time.Duration) (string, error) {
	if c.s3Endpoint == "" {
		return "", errors.New("jay client: PresignURL requires WithS3Endpoint: the SigV4 signature covers the host, and the native address is not the one the URL will be fetched from")
	}
	base, err := url.Parse(c.s3Endpoint)
	if err != nil || base.Scheme == "" || base.Host == "" {
		return "", fmt.Errorf("jay client: S3 endpoint %q must be a scheme and host, like https://s3.example.com", c.s3Endpoint)
	}
	if bucket == "" || key == "" {
		return "", errors.New("jay client: PresignURL requires a bucket and a key")
	}

	path := "/" + bucket + "/" + key
	query, err := auth.PresignQuery(auth.PresignInput{
		AccessKeyID: c.tokenID,
		SecretKey:   c.secret,
		Region:      presignRegion,
		Method:      strings.ToUpper(method),
		Host:        base.Host,
		Path:        path,
		Expires:     expires,
	})
	if err != nil {
		return "", fmt.Errorf("jay client: %w", err)
	}

	u := url.URL{
		Scheme:   base.Scheme,
		Host:     base.Host,
		Path:     path,
		RawQuery: query,
	}
	return u.String(), nil
}
