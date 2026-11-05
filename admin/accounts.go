package admin

import (
	jsonv2 "encoding/json/v2"
	"net/http"
	"slices"
	"strings"

	"github.com/ivangsm/jay/meta"
)

// handleListAccounts answers GET /_jay/accounts, oldest first. Until now an
// account was only reachable by remembering the id from the 201 that created it.
//
// The order is decided here, not by bbolt: its key order is the account id, a
// random uuid. Ties on created_at break on the id so two calls agree.
func (h *Handler) handleListAccounts(w http.ResponseWriter, _ *http.Request) {
	accounts, err := h.db.ListAccounts()
	if err != nil {
		h.log.Error("list accounts", "err", err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}
	slices.SortFunc(accounts, func(a, b meta.Account) int {
		if c := a.CreatedAt.Compare(b.CreatedAt); c != 0 {
			return c
		}
		return strings.Compare(a.AccountID, b.AccountID)
	})
	if accounts == nil {
		accounts = []meta.Account{} // "[]", never "null"
	}

	w.Header().Set("Content-Type", "application/json")
	if err := jsonv2.MarshalWrite(w, accounts); err != nil {
		h.log.Error("encode list-accounts response", "err", err)
	}
}
