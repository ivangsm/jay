package admin

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/ivangsm/jay/auth"
	"github.com/ivangsm/jay/maintenance"
	"github.com/ivangsm/jay/meta"
	"github.com/ivangsm/jay/store"
)

// authFailure tracks failed authentication attempts from an IP.
type authFailure struct {
	count    int
	lastFail time.Time
}

// Handler serves the admin API for managing accounts and tokens.
type Handler struct {
	db            *meta.DB
	store         *store.Store
	adminToken    string
	log           *slog.Logger
	metrics       *maintenance.Metrics
	signingSecret string
	listenAddr    string
	tlsEnabled    bool

	authFailures sync.Map // map[string]*authFailure keyed by remote IP
}

const (
	maxAuthFailures     = 5
	authFailureWindow   = 15 * time.Minute
)

// NewHandler creates a new admin API handler.
func NewHandler(db *meta.DB, adminToken string, log *slog.Logger, metrics *maintenance.Metrics, st *store.Store, signingSecret, listenAddr string, tlsEnabled bool) *Handler {
	return &Handler{db: db, store: st, adminToken: adminToken, log: log, metrics: metrics, signingSecret: signingSecret, listenAddr: listenAddr, tlsEnabled: tlsEnabled}
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
	case path == "/presign" && r.Method == http.MethodPost:
		h.handlePresign(w, r)
	case path == "/quarantine" && r.Method == http.MethodGet:
		h.handleListQuarantined(w, r)
	case path == "/quarantine/revalidate" && r.Method == http.MethodPost:
		h.handleRevalidate(w, r)
	case path == "/quarantine" && r.Method == http.MethodDelete:
		h.handlePurge(w, r)
	default:
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
	}
}

func (h *Handler) authenticateAdmin(r *http.Request) bool {
	if h.adminToken == "" {
		return false
	}

	clientIP := r.RemoteAddr
	if idx := strings.LastIndex(clientIP, ":"); idx != -1 {
		clientIP = clientIP[:idx]
	}

	// Check rate limit for this IP
	if val, ok := h.authFailures.Load(clientIP); ok {
		af := val.(*authFailure)
		if af.count >= maxAuthFailures && time.Since(af.lastFail) < authFailureWindow {
			h.log.Warn("admin auth rate limited", "ip", clientIP, "failures", af.count)
			return false
		}
		// Reset if window has expired
		if time.Since(af.lastFail) >= authFailureWindow {
			h.authFailures.Delete(clientIP)
		}
	}

	authHeader := r.Header.Get("Authorization")
	expected := "Bearer " + h.adminToken
	// Constant-time comparison to prevent timing attacks
	ok := subtle.ConstantTimeCompare([]byte(authHeader), []byte(expected)) == 1

	if !ok {
		h.log.Warn("admin auth failure", "ip", clientIP)
		val, _ := h.authFailures.LoadOrStore(clientIP, &authFailure{})
		af := val.(*authFailure)
		af.count++
		af.lastFail = time.Now()
		return false
	}

	// Successful auth clears failure counter
	h.authFailures.Delete(clientIP)
	return true
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
		SecretKey:      secret,
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

type presignRequest struct {
	TokenID        string `json:"token_id"`
	Method         string `json:"method"`
	Bucket         string `json:"bucket"`
	Key            string `json:"key"`
	ExpiresSeconds int    `json:"expires_seconds"`
}

type presignResponse struct {
	URL string `json:"url"`
}

func (h *Handler) handlePresign(w http.ResponseWriter, r *http.Request) {
	if h.signingSecret == "" {
		http.Error(w, `{"error":"signing secret not configured"}`, http.StatusBadRequest)
		return
	}

	var req presignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	if req.TokenID == "" || req.Bucket == "" || req.Method == "" {
		http.Error(w, `{"error":"token_id, method, and bucket are required"}`, http.StatusBadRequest)
		return
	}

	if req.ExpiresSeconds <= 0 {
		req.ExpiresSeconds = 3600
	}

	// Verify token exists
	if _, err := h.db.GetToken(req.TokenID); err != nil {
		http.Error(w, `{"error":"token not found"}`, http.StatusBadRequest)
		return
	}

	path := "/" + req.Bucket
	if req.Key != "" {
		path += "/" + req.Key
	}

	presignedURL, err := generateAdminPresignedURL(h.signingSecret, h.listenAddr, req.TokenID, req.Method, path, time.Duration(req.ExpiresSeconds)*time.Second, h.tlsEnabled)
	if err != nil {
		h.log.Error("generate presigned URL", "err", err)
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(presignResponse{URL: presignedURL})
}

// Quarantine handlers

func (h *Handler) handleListQuarantined(w http.ResponseWriter, _ *http.Request) {
	qm := maintenance.NewQuarantineManager(h.db, h.store, h.log)
	objects, err := qm.ListQuarantined()
	if err != nil {
		h.log.Error("list quarantined", "err", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(objects)
}

type quarantineRequest struct {
	BucketID string `json:"bucket_id"`
	Key      string `json:"key"`
}

func (h *Handler) handleRevalidate(w http.ResponseWriter, r *http.Request) {
	var req quarantineRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	qm := maintenance.NewQuarantineManager(h.db, h.store, h.log)
	restored, err := qm.Revalidate(req.BucketID, req.Key)
	if err != nil {
		h.log.Error("revalidate", "err", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"restored": restored})
}

func (h *Handler) handlePurge(w http.ResponseWriter, r *http.Request) {
	qm := maintenance.NewQuarantineManager(h.db, h.store, h.log)

	body, _ := io.ReadAll(r.Body)
	if len(body) == 0 || string(body) == "{}" {
		count, err := qm.PurgeAll()
		if err != nil {
			h.log.Error("purge all", "err", err)
			http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]int{"purged": count})
		return
	}

	var req quarantineRequest
	if err := json.Unmarshal(body, &req); err != nil || req.BucketID == "" || req.Key == "" {
		count, err := qm.PurgeAll()
		if err != nil {
			h.log.Error("purge all", "err", err)
			http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]int{"purged": count})
		return
	}

	if err := qm.Purge(req.BucketID, req.Key); err != nil {
		h.log.Error("purge", "err", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
