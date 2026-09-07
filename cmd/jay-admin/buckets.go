package main

// Bucket policy and visibility, the operator side of PND-0187.
//
// The endpoints alone would already be a way in, but jay-admin is what the docs
// tell an operator to use and what ships in the release archives and the image.
// A feature reachable only by hand-writing curl is a feature half of its users
// will not find.

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
)

func getBucket(addr, token string, args []string) error {
	bucket := parseFlag(args, "-bucket")
	if bucket == "" {
		return errors.New("usage: get-bucket -bucket <name>")
	}

	data, status, err := doRequest(http.MethodGet, addr+"/_jay/buckets/"+bucket, token, nil)
	if err != nil {
		return err
	}
	if status >= 400 {
		return fmt.Errorf("server error (%d): %s", status, data)
	}
	prettyJSON(data)
	return nil
}

func setBucketPolicy(addr, token string, args []string) error {
	bucket := parseFlag(args, "-bucket")
	file := parseFlag(args, "-file")
	if bucket == "" || file == "" {
		return errors.New("usage: set-bucket-policy -bucket <name> -file <path|->")
	}

	raw, err := readPolicyDocument(file)
	if err != nil {
		return err
	}
	// Sent with doRawRequest so the server sees the bytes of the file, not a
	// re-encoding of them.
	data, status, err := doRawRequest(http.MethodPut, addr+"/_jay/buckets/"+bucket+"/policy", token, raw)
	if err != nil {
		return err
	}
	if status >= 400 {
		return fmt.Errorf("server error (%d): %s", status, data)
	}
	prettyJSON(data)
	return nil
}

func deleteBucketPolicy(addr, token string, args []string) error {
	bucket := parseFlag(args, "-bucket")
	if bucket == "" {
		return errors.New("usage: delete-bucket-policy -bucket <name>")
	}

	data, status, err := doRequest(http.MethodDelete, addr+"/_jay/buckets/"+bucket+"/policy", token, nil)
	if err != nil {
		return err
	}
	if status >= 400 {
		return fmt.Errorf("server error (%d): %s", status, data)
	}
	fmt.Println("Bucket policy removed. The bucket is now reachable only by its " +
		"owner account and by tokens scoped to it.")
	return nil
}

func setBucketVisibility(addr, token string, args []string) error {
	bucket := parseFlag(args, "-bucket")
	visibility := parseFlag(args, "-visibility")
	if bucket == "" || visibility == "" {
		return errors.New("usage: set-bucket-visibility -bucket <name> -visibility private|public-read")
	}

	body := map[string]string{"visibility": visibility}
	data, status, err := doRequest(http.MethodPut, addr+"/_jay/buckets/"+bucket+"/visibility", token, body)
	if err != nil {
		return err
	}
	if status >= 400 {
		return fmt.Errorf("server error (%d): %s", status, data)
	}
	prettyJSON(data)
	return nil
}

// readPolicyDocument loads the policy from a file, or from stdin when path is
// "-". An empty document is refused here rather than sent: the server would
// answer 400 anyway, and the reason is clearer next to the file that is empty.
func readPolicyDocument(path string) ([]byte, error) {
	var (
		raw []byte
		err error
	)
	if path == "-" {
		raw, err = io.ReadAll(os.Stdin)
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
