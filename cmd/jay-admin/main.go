// Command jay-admin is a CLI for jay's admin API: creating accounts and tokens,
// issuing presigned URLs, reading metrics and inspecting quarantine.
//
// It authenticates with JAY_ADMIN_TOKEN, the same credential the admin listener
// requires.
package main

import (
	"bytes"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/ivangsm/jay/internal/jsonx"
	"github.com/ivangsm/jay/meta"
)

func main() {
	os.Exit(run(os.Args[1:], os.Getenv, os.Stdin, os.Stdout, os.Stderr))
}

// client carries what every subcommand needs: where the admin API is, the
// bearer token, and the streams it reads from and prints to.
type client struct {
	addr   string
	token  string
	stdin  io.Reader
	stdout io.Writer
}

// run is main with its environment passed in, so the argument handling and
// every subcommand can be driven from a test. It returns the exit code.
func run(args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
	addr := envOr(getenv, "JAY_ADMIN_ADDR", "http://localhost:9001")
	token := getenv("JAY_ADMIN_TOKEN")

	// Parse global flags
	for len(args) >= 2 {
		switch args[0] {
		case "-addr":
			addr = args[1]
			args = args[2:]
		case "-token":
			token = args[1]
			args = args[2:]
		default:
			goto done
		}
	}
done:

	if len(args) == 0 {
		usage(stderr)
		return 1
	}

	if token == "" {
		_, _ = fmt.Fprintln(stderr, "Error: admin token required. Set JAY_ADMIN_TOKEN or use -token flag.")
		return 1
	}

	// Ensure addr has scheme
	if !strings.HasPrefix(addr, "http://") && !strings.HasPrefix(addr, "https://") {
		addr = "http://" + addr
	}

	c := &client{addr: addr, token: token, stdin: stdin, stdout: stdout}
	cmd := args[0]
	cmdArgs := args[1:]

	var err error
	switch cmd {
	case "create-account":
		err = c.createAccount(cmdArgs)
	case "create-token":
		err = c.createToken(cmdArgs)
	case "list-tokens":
		err = c.listTokens()
	case "revoke-token":
		err = c.revokeToken(cmdArgs)
	case "metrics":
		err = c.metrics()
	case "presign":
		err = c.presign(cmdArgs)
	case "quarantine-list":
		err = c.quarantineList()
	case "quarantine-revalidate":
		err = c.quarantineRevalidate(cmdArgs)
	case "quarantine-purge":
		err = c.quarantinePurge(cmdArgs)
	case "get-bucket":
		err = c.getBucket(cmdArgs)
	case "set-bucket-policy":
		err = c.setBucketPolicy(cmdArgs)
	case "delete-bucket-policy":
		err = c.deleteBucketPolicy(cmdArgs)
	case "set-bucket-visibility":
		err = c.setBucketVisibility(cmdArgs)
	default:
		_, _ = fmt.Fprintf(stderr, "Unknown command: %s\n\n", cmd)
		usage(stderr)
		return 1
	}

	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	return 0
}

func usage(w io.Writer) {
	_, _ = fmt.Fprintln(w, `jay-admin — CLI tool for Jay object storage administration

Usage: jay-admin [-addr URL] [-token TOKEN] <command> [args]

Global flags:
  -addr    Admin API URL (default: $JAY_ADMIN_ADDR or http://localhost:9001)
  -token   Admin bearer token (default: $JAY_ADMIN_TOKEN)

Commands:
  create-account  -name <name>                         Create a new account
  create-token    -account <id> -actions <a,b,...>      Create a new token
                  [-name <name>] [-bucket-scope b1,b2]
                  [-prefix-scope p1,p2]
                  [-expires-at 2030-01-02T15:04:05Z]
                  -actions is required: a comma-separated list of
                  bucket:list, bucket:read-meta, bucket:write-meta,
                  object:get, object:put, object:delete, object:list,
                  multipart:create, multipart:upload-part,
                  multipart:complete, multipart:abort — or '*'
  list-tokens                                           List all tokens
  revoke-token    -id <token-id>                        Revoke a token
  metrics                                               Show server metrics
  presign         -bucket <b> -key <k> -token-id <id>   Generate presigned URL
                  [-method GET] [-expires 3600]
                  [-style jay|aws] [-host s3.example.com]
                  [-region us-east-1]
                  style "aws" emits a SigV4 URL any S3 client
                  understands; it needs -host unless
                  JAY_LISTEN_ADDR carries a hostname
  quarantine-list                                       List quarantined objects
  quarantine-revalidate -bucket-id <id> -key <key>      Revalidate object
  quarantine-purge [-bucket-id <id> -key <key>]         Purge one quarantined object,
                                                        or all of them
  get-bucket      -bucket <name>                        Show visibility and policy
  set-bucket-policy -bucket <name> -file <path|->       Install a bucket policy
                  reads the policy document from a file,
                  or from stdin with "-"
  delete-bucket-policy -bucket <name>                   Remove the bucket policy
  set-bucket-visibility -bucket <name> \
                  -visibility private|public-read       Open or close anonymous reads`)
}

func envOr(getenv func(string) string, key, fallback string) string {
	if v := getenv(key); v != "" {
		return v
	}
	return fallback
}

func doRequest(method, url, token string, body any) ([]byte, int, error) {
	var bodyReader io.Reader
	if body != nil {
		// The marshal error cannot be swallowed: sending an empty body would
		// make the admin API answer 400, and the user would see an error with
		// nothing to do with the real cause.
		data, err := jsonv2.Marshal(body, jsonx.Wire)
		if err != nil {
			return nil, 0, fmt.Errorf("codificar request body: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(resp.Body)
	return data, resp.StatusCode, err
}

// doRawRequest sends body as-is instead of marshalling a Go value into it.
//
// It exists for the bucket policy, whose body IS the document the operator
// wrote. Passing it through the JSON encoder would re-emit it — reordered keys,
// re-escaped strings — so the bytes the server validates would not be the bytes
// in the file, and a reported error would point at a line number that is not
// there.
func doRawRequest(method, url, token string, body []byte) ([]byte, int, error) {
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(resp.Body)
	return data, resp.StatusCode, err
}

func prettyJSON(w io.Writer, data []byte) {
	// PreserveRawStrings leaves literals exactly as they arrived, which is what
	// v1's json.Indent did: this is a pretty-print, not a re-encode.
	pretty, err := jsontext.AppendFormat(nil, data,
		jsontext.WithIndent("  "), jsontext.PreserveRawStrings(true))
	if err != nil {
		_, _ = fmt.Fprintln(w, string(data))
		return
	}
	_, _ = fmt.Fprintln(w, string(pretty))
}

func parseFlag(args []string, name string) string {
	for i, a := range args {
		if a == name && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func (c *client) createAccount(args []string) error {
	name := parseFlag(args, "-name")
	if name == "" {
		return errors.New("usage: create-account -name <name>")
	}

	data, status, err := doRequest("POST", c.addr+"/_jay/accounts", c.token, map[string]string{"name": name})
	if err != nil {
		return err
	}
	if status >= 400 {
		return fmt.Errorf("server error (%d): %s", status, data)
	}
	prettyJSON(c.stdout, data)
	return nil
}

const createTokenUsage = "usage: create-token -account <id> -actions <a,b,...|'*'> [-name <name>] " +
	"[-bucket-scope <b1,b2>] [-prefix-scope <p1,p2>] [-expires-at <RFC 3339 time>]"

func (c *client) createToken(args []string) error {
	accountID := parseFlag(args, "-account")
	actions := splitList(parseFlag(args, "-actions"))
	if accountID == "" || len(actions) == 0 {
		return errors.New(createTokenUsage)
	}
	// The server refuses these too; checking here fails a typo before anything
	// is sent, with the list of the actions that exist.
	for _, action := range actions {
		if !meta.ValidAction(action) {
			return fmt.Errorf("unknown action %q: use '*' or any of %s",
				action, strings.Join(meta.AllActions, ", "))
		}
	}

	body := map[string]any{
		"account_id":      accountID,
		"name":            parseFlag(args, "-name"),
		"allowed_actions": actions,
	}
	// Only send the optional fields that were given: the server's defaults
	// (no scope, no expiry) are the ones it documents.
	if scope := splitList(parseFlag(args, "-bucket-scope")); len(scope) > 0 {
		body["bucket_scope"] = scope
	}
	if scope := splitList(parseFlag(args, "-prefix-scope")); len(scope) > 0 {
		body["prefix_scope"] = scope
	}
	if expiresAt := parseFlag(args, "-expires-at"); expiresAt != "" {
		body["expires_at"] = expiresAt
	}

	data, status, err := doRequest("POST", c.addr+"/_jay/tokens", c.token, body)
	if err != nil {
		return err
	}
	if status >= 400 {
		return fmt.Errorf("server error (%d): %s", status, data)
	}
	prettyJSON(c.stdout, data)
	return nil
}

// splitList parses a comma-separated flag value, trimming the spaces around
// each entry and dropping empty ones.
func splitList(value string) []string {
	var out []string
	for item := range strings.SplitSeq(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

func (c *client) listTokens() error {
	data, status, err := doRequest("GET", c.addr+"/_jay/tokens", c.token, nil)
	if err != nil {
		return err
	}
	if status >= 400 {
		return fmt.Errorf("server error (%d): %s", status, data)
	}
	prettyJSON(c.stdout, data)
	return nil
}

func (c *client) revokeToken(args []string) error {
	id := parseFlag(args, "-id")
	if id == "" {
		return errors.New("usage: revoke-token -id <token-id>")
	}

	data, status, err := doRequest("DELETE", c.addr+"/_jay/tokens/"+id, c.token, nil)
	if err != nil {
		return err
	}
	if status >= 400 {
		return fmt.Errorf("server error (%d): %s", status, data)
	}
	_, _ = fmt.Fprintln(c.stdout, "Token revoked.")
	return nil
}

func (c *client) metrics() error {
	data, status, err := doRequest("GET", c.addr+"/_jay/metrics", c.token, nil)
	if err != nil {
		return err
	}
	if status >= 400 {
		return fmt.Errorf("server error (%d): %s", status, data)
	}
	prettyJSON(c.stdout, data)
	return nil
}

const presignUsage = "usage: presign -bucket <b> -key <k> -token-id <id> " +
	"[-method GET] [-expires 3600] [-style jay|aws] [-host s3.example.com] [-region us-east-1]"

func (c *client) presign(args []string) error {
	bucket := parseFlag(args, "-bucket")
	key := parseFlag(args, "-key")
	method := parseFlag(args, "-method")
	expires := parseFlag(args, "-expires")

	if bucket == "" {
		return errors.New(presignUsage)
	}
	if method == "" {
		method = "GET"
	}
	if expires == "" {
		expires = "3600"
	}
	// expires_seconds is a number on the wire: the admin API's strict decoder
	// answers 400 to a string where it expects an int.
	expiresSeconds, err := strconv.Atoi(expires)
	if err != nil || expiresSeconds <= 0 {
		return fmt.Errorf("-expires must be a positive number of seconds, got %q", expires)
	}

	// We also need a token_id for presigning — use the first token from list or require it
	tokenID := parseFlag(args, "-token-id")
	if tokenID == "" {
		return errors.New(presignUsage)
	}

	body := map[string]any{
		"token_id":        tokenID,
		"method":          method,
		"bucket":          bucket,
		"key":             key,
		"expires_seconds": expiresSeconds,
	}
	// Only send the optional fields that were actually given: the server picks
	// the defaults, and it is the one place they are documented.
	for flag, field := range map[string]string{"-style": "style", "-host": "host", "-region": "region"} {
		if v := parseFlag(args, flag); v != "" {
			body[field] = v
		}
	}

	data, status, err := doRequest("POST", c.addr+"/_jay/presign", c.token, body)
	if err != nil {
		return err
	}
	if status >= 400 {
		return fmt.Errorf("server error (%d): %s", status, data)
	}
	prettyJSON(c.stdout, data)
	return nil
}

func (c *client) quarantineList() error {
	data, status, err := doRequest("GET", c.addr+"/_jay/quarantine", c.token, nil)
	if err != nil {
		return err
	}
	if status >= 400 {
		return fmt.Errorf("server error (%d): %s", status, data)
	}
	prettyJSON(c.stdout, data)
	return nil
}

func (c *client) quarantineRevalidate(args []string) error {
	bucketID := parseFlag(args, "-bucket-id")
	key := parseFlag(args, "-key")
	if bucketID == "" || key == "" {
		return errors.New("usage: quarantine-revalidate -bucket-id <id> -key <key>")
	}

	body := map[string]string{
		"bucket_id": bucketID,
		"key":       key,
	}

	data, status, err := doRequest("POST", c.addr+"/_jay/quarantine/revalidate", c.token, body)
	if err != nil {
		return err
	}
	if status >= 400 {
		return fmt.Errorf("server error (%d): %s", status, data)
	}
	prettyJSON(c.stdout, data)
	return nil
}

const quarantinePurgeUsage = "usage: quarantine-purge [-bucket-id <id> -key <key>]"

// quarantinePurge purges one quarantined object when -bucket-id and -key are
// given, and the whole quarantine otherwise. The line it prints comes from the
// server's answer: a partial purge is a server error that names what failed,
// never "purged".
func (c *client) quarantinePurge(args []string) error {
	bucketID := parseFlag(args, "-bucket-id")
	key := parseFlag(args, "-key")
	if (bucketID == "") != (key == "") {
		return errors.New(quarantinePurgeUsage)
	}

	body := map[string]string{"mode": "all"}
	if bucketID != "" {
		body = map[string]string{"bucket_id": bucketID, "key": key}
	}
	data, status, err := doRequest("DELETE", c.addr+"/_jay/quarantine", c.token, body)
	if err != nil {
		return err
	}
	if status >= 400 {
		return fmt.Errorf("server error (%d): %s", status, data)
	}

	if bucketID != "" {
		_, _ = fmt.Fprintf(c.stdout, "Purged %s from bucket %s.\n", key, bucketID)
		return nil
	}
	var resp struct {
		Purged *int `json:"purged"`
	}
	if err := jsonv2.Unmarshal(data, &resp); err != nil || resp.Purged == nil {
		return fmt.Errorf("unexpected answer from the server (%d): %s", status, data)
	}
	_, _ = fmt.Fprintf(c.stdout, "Purged %d quarantined object(s).\n", *resp.Purged)
	return nil
}
