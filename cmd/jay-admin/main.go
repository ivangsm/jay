package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

func main() {
	addr := envOr("JAY_ADMIN_ADDR", "http://localhost:9001")
	token := os.Getenv("JAY_ADMIN_TOKEN")

	args := os.Args[1:]

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
		usage()
		os.Exit(1)
	}

	if token == "" {
		fmt.Fprintln(os.Stderr, "Error: admin token required. Set JAY_ADMIN_TOKEN or use -token flag.")
		os.Exit(1)
	}

	// Ensure addr has scheme
	if !strings.HasPrefix(addr, "http://") && !strings.HasPrefix(addr, "https://") {
		addr = "http://" + addr
	}

	cmd := args[0]
	cmdArgs := args[1:]

	var err error
	switch cmd {
	case "create-account":
		err = createAccount(addr, token, cmdArgs)
	case "create-token":
		err = createToken(addr, token, cmdArgs)
	case "list-tokens":
		err = listTokens(addr, token)
	case "revoke-token":
		err = revokeToken(addr, token, cmdArgs)
	case "metrics":
		err = metrics(addr, token)
	case "presign":
		err = presign(addr, token, cmdArgs)
	case "quarantine-list":
		err = quarantineList(addr, token)
	case "quarantine-revalidate":
		err = quarantineRevalidate(addr, token, cmdArgs)
	case "quarantine-purge":
		err = quarantinePurge(addr, token)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", cmd)
		usage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `jay-admin — CLI tool for Jay object storage administration

Usage: jay-admin [-addr URL] [-token TOKEN] <command> [args]

Global flags:
  -addr    Admin API URL (default: $JAY_ADMIN_ADDR or http://localhost:9001)
  -token   Admin bearer token (default: $JAY_ADMIN_TOKEN)

Commands:
  create-account  -name <name>                         Create a new account
  create-token    -account <id> -name <name>            Create a new token
  list-tokens                                           List all tokens
  revoke-token    -id <token-id>                        Revoke a token
  metrics                                               Show server metrics
  presign         -bucket <b> -key <k> [-method GET]    Generate presigned URL
                  [-expires 3600]
  quarantine-list                                       List quarantined objects
  quarantine-revalidate -bucket-id <id> -key <key>      Revalidate object
  quarantine-purge                                      Purge all quarantined`)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func doRequest(method, url, token string, body interface{}) ([]byte, int, error) {
	var bodyReader io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
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
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	return data, resp.StatusCode, err
}

func prettyJSON(data []byte) {
	var buf bytes.Buffer
	if err := json.Indent(&buf, data, "", "  "); err != nil {
		fmt.Println(string(data))
		return
	}
	fmt.Println(buf.String())
}

func parseFlag(args []string, name string) string {
	for i, a := range args {
		if a == name && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func createAccount(addr, token string, args []string) error {
	name := parseFlag(args, "-name")
	if name == "" {
		return fmt.Errorf("usage: create-account -name <name>")
	}

	data, status, err := doRequest("POST", addr+"/_jay/accounts", token, map[string]string{"name": name})
	if err != nil {
		return err
	}
	if status >= 400 {
		return fmt.Errorf("server error (%d): %s", status, data)
	}
	prettyJSON(data)
	return nil
}

func createToken(addr, token string, args []string) error {
	accountID := parseFlag(args, "-account")
	name := parseFlag(args, "-name")
	if accountID == "" {
		return fmt.Errorf("usage: create-token -account <id> -name <name>")
	}

	body := map[string]string{
		"account_id": accountID,
		"name":       name,
	}

	data, status, err := doRequest("POST", addr+"/_jay/tokens", token, body)
	if err != nil {
		return err
	}
	if status >= 400 {
		return fmt.Errorf("server error (%d): %s", status, data)
	}
	prettyJSON(data)
	return nil
}

func listTokens(addr, token string) error {
	data, status, err := doRequest("GET", addr+"/_jay/tokens", token, nil)
	if err != nil {
		return err
	}
	if status >= 400 {
		return fmt.Errorf("server error (%d): %s", status, data)
	}
	prettyJSON(data)
	return nil
}

func revokeToken(addr, token string, args []string) error {
	id := parseFlag(args, "-id")
	if id == "" {
		return fmt.Errorf("usage: revoke-token -id <token-id>")
	}

	_, status, err := doRequest("DELETE", addr+"/_jay/tokens/"+id, token, nil)
	if err != nil {
		return err
	}
	if status >= 400 {
		return fmt.Errorf("server error (%d)", status)
	}
	fmt.Println("Token revoked.")
	return nil
}

func metrics(addr, token string) error {
	data, status, err := doRequest("GET", addr+"/_jay/metrics", token, nil)
	if err != nil {
		return err
	}
	if status >= 400 {
		return fmt.Errorf("server error (%d): %s", status, data)
	}
	prettyJSON(data)
	return nil
}

func presign(addr, token string, args []string) error {
	bucket := parseFlag(args, "-bucket")
	key := parseFlag(args, "-key")
	method := parseFlag(args, "-method")
	expires := parseFlag(args, "-expires")

	if bucket == "" {
		return fmt.Errorf("usage: presign -bucket <b> -key <k> [-method GET] [-expires 3600]")
	}
	if method == "" {
		method = "GET"
	}
	if expires == "" {
		expires = "3600"
	}

	// We also need a token_id for presigning — use the first token from list or require it
	tokenID := parseFlag(args, "-token-id")
	if tokenID == "" {
		return fmt.Errorf("usage: presign -bucket <b> -key <k> -token-id <id> [-method GET] [-expires 3600]")
	}

	body := map[string]interface{}{
		"token_id":        tokenID,
		"method":          method,
		"bucket":          bucket,
		"key":             key,
		"expires_seconds": expires,
	}

	data, status, err := doRequest("POST", addr+"/_jay/presign", token, body)
	if err != nil {
		return err
	}
	if status >= 400 {
		return fmt.Errorf("server error (%d): %s", status, data)
	}
	prettyJSON(data)
	return nil
}

func quarantineList(addr, token string) error {
	data, status, err := doRequest("GET", addr+"/_jay/quarantine", token, nil)
	if err != nil {
		return err
	}
	if status >= 400 {
		return fmt.Errorf("server error (%d): %s", status, data)
	}
	prettyJSON(data)
	return nil
}

func quarantineRevalidate(addr, token string, args []string) error {
	bucketID := parseFlag(args, "-bucket-id")
	key := parseFlag(args, "-key")
	if bucketID == "" || key == "" {
		return fmt.Errorf("usage: quarantine-revalidate -bucket-id <id> -key <key>")
	}

	body := map[string]string{
		"bucket_id": bucketID,
		"key":       key,
	}

	data, status, err := doRequest("POST", addr+"/_jay/quarantine/revalidate", token, body)
	if err != nil {
		return err
	}
	if status >= 400 {
		return fmt.Errorf("server error (%d): %s", status, data)
	}
	prettyJSON(data)
	return nil
}

func quarantinePurge(addr, token string) error {
	_, status, err := doRequest("DELETE", addr+"/_jay/quarantine", token, nil)
	if err != nil {
		return err
	}
	if status >= 400 {
		return fmt.Errorf("server error (%d)", status)
	}
	fmt.Println("All quarantined objects purged.")
	return nil
}
