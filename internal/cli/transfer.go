package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ivangsm/jay/proto/client"
)

// multipartThreshold is the object size above which an upload is split. Below
// it a single PutObject is one round trip; above it, a failure in the middle of
// a long stream would mean restarting from zero.
//
// It is a var so tests can exercise the part-splitting path without moving
// 64 MiB through a temp directory. Nothing else reassigns it.
var multipartThreshold int64 = 64 << 20 // 64 MiB

// multipartChunkSize is the size of each uploaded part. 16 MiB keeps the part
// count far under the 10,000 limit for any object that fits in the server's
// default 5 GiB cap, while staying small enough that one retry is cheap.
const multipartChunkSize = 16 << 20

// upload sends a local file to a bucket, choosing single-shot or multipart by
// size. It returns the checksum the server computed.
func upload(ctx context.Context, c *client.Client, path string, dst Location, progress io.Writer) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if info.IsDir() {
		return "", fmt.Errorf("%s is a directory: use -r or sync", path)
	}

	if info.Size() > multipartThreshold {
		return uploadMultipart(ctx, c, path, info.Size(), dst, progress)
	}

	f, err := os.Open(path) //nolint:gosec // the path is the argument the user typed
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	body := newProgressReader(f, info.Size(), filepath.Base(path), progress)
	res, err := c.PutObject(ctx, dst.Bucket, dst.Key, body, info.Size(), nil)
	if err != nil {
		return "", err
	}
	return res.ChecksumSHA256, nil
}

// uploadMultipart splits a large file into parts. Any failure aborts the
// upload server-side: leaving it open would hold the parts on disk until the
// GC reclaims them 24h later, and would look to the caller like a finished
// object that simply is not there.
func uploadMultipart(ctx context.Context, c *client.Client, path string, size int64, dst Location, progress io.Writer) (string, error) {
	f, err := os.Open(path) //nolint:gosec // the path is the argument the user typed
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	uploadID, err := c.CreateMultipartUpload(ctx, dst.Bucket, dst.Key, nil)
	if err != nil {
		return "", err
	}

	body := newProgressReader(f, size, filepath.Base(path), progress)

	parts, err := uploadParts(ctx, c, body, size, dst, uploadID)
	if err != nil {
		if abortErr := c.AbortMultipartUpload(ctx, dst.Bucket, dst.Key, uploadID); abortErr != nil {
			return "", fmt.Errorf("%w (and aborting the upload failed: %w)", err, abortErr)
		}
		return "", err
	}

	res, err := c.CompleteMultipartUpload(ctx, dst.Bucket, dst.Key, uploadID, parts)
	if err != nil {
		if abortErr := c.AbortMultipartUpload(ctx, dst.Bucket, dst.Key, uploadID); abortErr != nil {
			return "", fmt.Errorf("%w (and aborting the upload failed: %w)", err, abortErr)
		}
		return "", err
	}
	return res.ChecksumSHA256, nil
}

// uploadParts streams the reader into fixed-size parts. Parts go up in order
// because the source is a single sequential reader; the progress bar wraps it
// once, so it measures the whole object rather than each part.
func uploadParts(ctx context.Context, c *client.Client, body io.Reader, size int64, dst Location, uploadID string) ([]client.CompletePart, error) {
	var parts []client.CompletePart
	remaining := size

	for partNumber := 1; remaining > 0; partNumber++ {
		chunk := int64(multipartChunkSize)
		if remaining < chunk {
			chunk = remaining
		}

		etag, err := c.UploadPart(ctx, dst.Bucket, dst.Key, uploadID, partNumber, io.LimitReader(body, chunk), chunk)
		if err != nil {
			return nil, fmt.Errorf("part %d: %w", partNumber, err)
		}

		parts = append(parts, client.CompletePart{PartNumber: partNumber, ETag: etag})
		remaining -= chunk
	}
	return parts, nil
}

// download writes an object to a local path, creating parent directories, and
// returns how many bytes landed. The file is written to a temporary name and
// renamed, so an interrupted transfer never leaves a truncated file where a
// complete one is expected.
func download(ctx context.Context, c *client.Client, src Location, path string, progress io.Writer) (int64, error) {
	obj, err := c.GetObject(ctx, src.Bucket, src.Key)
	if err != nil {
		return 0, err
	}
	defer func() { _ = obj.Body.Close() }()

	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return 0, err
		}
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".jay-download-*")
	if err != nil {
		return 0, err
	}
	tmpName := tmp.Name()
	defer func() {
		_ = tmp.Close()
		// Removing a file that was already renamed fails harmlessly.
		_ = os.Remove(tmpName)
	}()

	body := newProgressReader(obj.Body, obj.Size, filepath.Base(src.Key), progress)
	written, err := io.Copy(tmp, body)
	if err != nil {
		return 0, err
	}
	if err := tmp.Sync(); err != nil {
		return 0, err
	}
	if err := tmp.Close(); err != nil {
		return 0, err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return 0, err
	}
	return written, nil
}

// remoteCopy copies an object from one location to another without touching
// the local disk. The server does it in place when it can; a jay that predates
// CopyObject answers UnknownOp, and then the bytes go through this process —
// the progress bar is what tells the user which one happened.
func remoteCopy(ctx context.Context, c *client.Client, src, dst Location, progress io.Writer) error {
	_, err := c.CopyObject(ctx, src.Bucket, src.Key, dst.Bucket, dst.Key)
	if err == nil {
		return nil
	}
	if !client.IsUnknownOp(err) {
		return err
	}

	obj, err := c.GetObject(ctx, src.Bucket, src.Key)
	if err != nil {
		return err
	}
	defer func() { _ = obj.Body.Close() }()

	body := newProgressReader(obj.Body, obj.Size, baseName(src.Key), progress)
	opts := &client.PutOptions{ContentType: obj.ContentType, Metadata: obj.Metadata}
	if _, err := c.PutObject(ctx, dst.Bucket, dst.Key, body, obj.Size, opts); err != nil {
		return err
	}
	return nil
}

// baseName returns the last segment of a key, for display.
func baseName(key string) string {
	return filepath.Base(key)
}

// localTarget joins rel under root and refuses a result that lands outside it.
//
// Object keys are opaque bytes: "../../.ssh/authorized_keys" is a legal key in
// S3 and in jay, so joining one straight onto a download destination turns
// `jay sync` into a write anywhere the caller can write. The destination
// itself is the user's choice and stays allowed.
func localTarget(root, rel string) (string, error) {
	target := filepath.Join(root, filepath.FromSlash(rel))
	cleanRoot := filepath.Clean(root)
	if target != cleanRoot && !strings.HasPrefix(target, cleanRoot+string(filepath.Separator)) {
		return "", fmt.Errorf("key %q escapes the destination directory %s", rel, root)
	}
	return target, nil
}

// isDir reports whether path is an existing directory. A path that cannot be
// stat'ed is treated as a plain file name the caller is about to create.
func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
