package admin

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/ivangsm/jay/auth"
	"github.com/ivangsm/jay/maintenance"
	"github.com/ivangsm/jay/meta"
)

// Handler serves the admin API for managing accounts and tokens.
type Handler struct {
	db         *meta.DB
	adminToken string
	log        *slog.Logger
	metrics    *maintenance.Metrics
}

// NewHandler creates a new admin API handler.
func NewHandler(db *meta.DB, adminToken string, log *slog.Logger, metrics *maintenance.Metrics) *Handler {
	return &Handler{db: db, adminToken: adminToken, log: log, metrics: metrics}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Authenticate admin
	if !h.authenticateAdmin(r) {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/_jay")

	switch {
	case path == "/accounts" && r.Method == http.MethodPost:
		h.handleCreateAccount(w, r)
	case path == "/tokens" && r.Method == http.MethodPost:
		h.handleCreateToken(w, r)
	case path == "/tokens" && r.Method == http.MethodGet:
		h.handleListTokens(w, r)
	case strings.HasPrefix(path, "/tokens/") && r.Method == http.MethodDelete:
		tokenID := strings.TrimPrefix(path, "/tokens/")
		h.handleRevokeToken(w, r, tokenID)
	case path == "/metrics" && r.Method == http.MethodGet:
		h.handleMetrics(w, r)
	default:
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
	}
}

func (h *Handler) authenticateAdmin(r *http.Request) bool {
	if h.adminToken == "" {
		return false
	}
	authHeader := r.Header.Get("Authorization")
	return authHeader == "Bearer "+h.adminToken
}

type createAccountRequest struct {
	Name string `json:"name"`
}

func (h *Handler) handleCreateAccount(w http.ResponseWriter, r *http.Request) {
	var req createAccountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	account := &meta.Account{
		AccountID: uuid.New().String(),
		Name:      req.Name,
		Status:    "active",
	}

	if err := h.db.CreateAccount(account); err != nil {
		h.log.Error("create account", "err", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(account)
}

type createTokenRequest struct {
	AccountID      string   `json:"account_id"`
	Name           string   `json:"name"`
	AllowedActions []string `json:"allowed_actions"`
	BucketScope    []string `json:"bucket_scope,omitempty"`
	PrefixScope    []string `json:"prefix_scope,omitempty"`
	ExpiresAt      string   `json:"expires_at,omitempty"`
}

type createTokenResponse struct {
	TokenID string `json:"token_id"`
	Secret  string `json:"secret"`
}

func (h *Handler) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	var req createTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	if req.AccountID == "" {
		http.Error(w, `{"error":"account_id required"}`, http.StatusBadRequest)
		return
	}

	// Verify account exists
	if _, err := h.db.GetAccount(req.AccountID); err != nil {
		http.Error(w, `{"error":"account not found"}`, http.StatusBadRequest)
		return
	}

	// Generate secret
	secretBytes := make([]byte, 32)
	if _, err := rand.Read(secretBytes); err != nil {
		h.log.Error("generate secret", "err", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	secret := hex.EncodeToString(secretBytes)

	// Hash secret for storage
	hash, err := auth.HashSecret(secret)
	if err != nil {
		h.log.Error("hash secret", "err", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	actions := req.AllowedActions
	if len(actions) == 0 {
		actions = meta.AllActions
	}

	token := &meta.Token{
		TokenID:        uuid.New().String(),
		AccountID:      req.AccountID,
		Name:           req.Name,
		SecretHash:     hash,
		AllowedActions: actions,
		BucketScope:    req.BucketScope,
		PrefixScope:    req.PrefixScope,
		Status:         "active",
	}

	if err := h.db.CreateToken(token); err != nil {
		h.log.Error("create token", "err", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(createTokenResponse{
		TokenID: token.TokenID,
		Secret:  secret,
	})
}

func (h *Handler) handleListTokens(w http.ResponseWriter, r *http.Request) {
	accountID := r.URL.Query().Get("account_id")
	tokens, err := h.db.ListTokens(accountID)
	if err != nil {
		h.log.Error("list tokens", "err", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokens)
}

func (h *Handler) handleRevokeToken(w http.ResponseWriter, _ *http.Request, tokenID string) {
	if err := h.db.RevokeToken(tokenID); err != nil {
		h.log.Error("revoke token", "err", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	if h.metrics == nil {
		http.Error(w, `{"error":"metrics not available"}`, http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(h.metrics.Snapshot())
}
