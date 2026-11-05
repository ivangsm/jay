package main

// Account listing, over GET /_jay/accounts.

import (
	"fmt"
	"net/http"
)

func (c *client) listAccounts() error {
	data, status, err := doRequest(http.MethodGet, c.addr+"/_jay/accounts", c.token, nil)
	if err != nil {
		return err
	}
	if status >= 400 {
		return fmt.Errorf("server error (%d): %s", status, data)
	}
	prettyJSON(c.stdout, data)
	return nil
}
