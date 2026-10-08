package main

// Bucket subcommands (list, create, delete, policy, visibility), over the
// /_jay/buckets endpoints.

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
)

func (c *client) listBuckets(args []string) error {
	endpoint := c.addr + "/_jay/buckets"
	if owner := parseFlag(args, "-owner"); owner != "" {
		endpoint += "?owner_account_id=" + url.QueryEscape(owner)
	}
	data, status, err := doRequest(http.MethodGet, endpoint, c.token, nil)
	if err != nil {
		return err
	}
	if status >= 400 {
		return fmt.Errorf("server error (%d): %s", status, data)
	}
	prettyJSON(c.stdout, data)
	return nil
}

func (c *client) createBucket(args []string) error {
	name := parseFlag(args, "-name")
	owner := parseFlag(args, "-owner")
	if name == "" || owner == "" {
		return errors.New("usage: create-bucket -name <name> -owner <account-id>")
	}

	body := map[string]string{"name": name, "owner_account_id": owner}
	data, status, err := doRequest(http.MethodPost, c.addr+"/_jay/buckets", c.token, body)
	if err != nil {
		return err
	}
	if status >= 400 {
		return fmt.Errorf("server error (%d): %s", status, data)
	}
	prettyJSON(c.stdout, data)
	return nil
}

// deleteBucket removes an empty bucket. The success line is printed only after
// the server answered 2xx: a non-empty bucket is a 409 that says so.
func (c *client) deleteBucket(args []string) error {
	name := parseFlag(args, "-name")
	if name == "" {
		return errors.New("usage: delete-bucket -name <name>")
	}

	data, status, err := doRequest(http.MethodDelete, c.addr+"/_jay/buckets/"+url.PathEscape(name), c.token, nil)
	if err != nil {
		return err
	}
	if status >= 400 {
		return fmt.Errorf("server error (%d): %s", status, data)
	}
	_, _ = fmt.Fprintf(c.stdout, "Bucket %s deleted.\n", name)
	return nil
}

func (c *client) getBucket(args []string) error {
	bucket := parseFlag(args, "-bucket")
	if bucket == "" {
		return errors.New("usage: get-bucket -bucket <name>")
	}

	data, status, err := doRequest(http.MethodGet, c.addr+"/_jay/buckets/"+bucket, c.token, nil)
	if err != nil {
		return err
	}
	if status >= 400 {
		return fmt.Errorf("server error (%d): %s", status, data)
	}
	prettyJSON(c.stdout, data)
	return nil
}

func (c *client) setBucketPolicy(args []string) error {
	bucket := parseFlag(args, "-bucket")
	file := parseFlag(args, "-file")
	if bucket == "" || file == "" {
		return errors.New("usage: set-bucket-policy -bucket <name> -file <path|->")
	}

	raw, err := readPolicyDocument(c.stdin, file)
	if err != nil {
		return err
	}
	// Sent with doRawRequest so the server sees the bytes of the file, not a
	// re-encoding of them.
	data, status, err := doRawRequest(http.MethodPut, c.addr+"/_jay/buckets/"+bucket+"/policy", c.token, raw)
	if err != nil {
		return err
	}
	if status >= 400 {
		return fmt.Errorf("server error (%d): %s", status, data)
	}
	prettyJSON(c.stdout, data)
	return nil
}

func (c *client) deleteBucketPolicy(args []string) error {
	bucket := parseFlag(args, "-bucket")
	if bucket == "" {
		return errors.New("usage: delete-bucket-policy -bucket <name>")
	}

	data, status, err := doRequest(http.MethodDelete, c.addr+"/_jay/buckets/"+bucket+"/policy", c.token, nil)
	if err != nil {
		return err
	}
	if status >= 400 {
		return fmt.Errorf("server error (%d): %s", status, data)
	}
	_, _ = fmt.Fprintln(c.stdout, "Bucket policy removed. The bucket is now reachable only by its "+
		"owner account and by tokens scoped to it.")
	return nil
}

func (c *client) setBucketVisibility(args []string) error {
	bucket := parseFlag(args, "-bucket")
	visibility := parseFlag(args, "-visibility")
	if bucket == "" || visibility == "" {
		return errors.New("usage: set-bucket-visibility -bucket <name> -visibility private|public-read")
	}

	body := map[string]string{"visibility": visibility}
	data, status, err := doRequest(http.MethodPut, c.addr+"/_jay/buckets/"+bucket+"/visibility", c.token, body)
	if err != nil {
		return err
	}
	if status >= 400 {
		return fmt.Errorf("server error (%d): %s", status, data)
	}
	prettyJSON(c.stdout, data)
	return nil
}

// readPolicyDocument loads the policy from a file, or from stdin when path is
// "-". An empty document is refused here rather than sent: the server would
// answer 400 anyway, and the reason is clearer next to the file that is empty.
func readPolicyDocument(stdin io.Reader, path string) ([]byte, error) {
	var (
		raw []byte
		err error
	)
	if path == "-" {
		raw, err = io.ReadAll(stdin)
	} else {
		raw, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, fmt.Errorf("read policy document: %w", err)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, errors.New("the policy document is empty; use delete-bucket-policy to remove a policy")
	}
	return raw, nil
}
