// Package admin implements jay's management plane: accounts, tokens, presigned
// URLs, metrics and quarantine inspection.
//
// It is served on its own listener (JAY_ADMIN_ADDR) and gated by
// JAY_ADMIN_TOKEN. Nothing here should ever be reachable from the internet.
package admin

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	jsonv2 "encoding/json/v2"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
	"uuid"

	"github.com/ivangsm/jay/auth"
	"github.com/ivangsm/jay/internal/jsonx"
	"github.com/ivangsm/jay/maintenance"
	"github.com/ivangsm/jay/meta"
	"github.com/ivangsm/jay/store"
)

// authFailure tracks failed authentication attempts from an IP.
type authFailure struct {
	mu       sync.Mutex
	count    int
	lastFail time.Time
}

// Handler serves the admin API for managing accounts and tokens.
type Handler struct {
	db            *meta.DB
	store         *store.Store
	auth          *auth.Auth
	adminToken    string
	log           *slog.Logger
	metrics       *maintenance.Metrics
	signingSecret string
	listenAddr    string
	tlsEnabled    bool

	authFailures sync.Map // map[string]*authFailure keyed by remote IP

	stopCh   chan struct{}
	stopOnce sync.Once
}

const (
	maxAuthFailures     = 5
	authFailureWindow   = 15 * time.Minute
	authFailureCap      = 10000
	authFailureEvictN   = 100
	authFailureSweepInt = 5 * time.Minute
)

// AdminConfig holds the configuration for the admin API handler.
type AdminConfig struct {
	DB            *meta.DB
	Store         *store.Store
	Auth          *auth.Auth
	AdminToken    string
	Log           *slog.Logger
	Metrics       *maintenance.Metrics
	SigningSecret string
	ListenAddr    string
	TLSEnabled    bool
}

// NewHandler creates a new admin API handler.
func NewHandler(cfg AdminConfig) *Handler {
	// Without a logger, the first unauthorised request nil-dereferenced inside
	// authenticateAdmin — the handler blew up on exactly the path nobody
	// exercises before production.
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	h := &Handler{
		db:            cfg.DB,
		store:         cfg.Store,
		auth:          cfg.Auth,
		adminToken:    cfg.AdminToken,
		log:           cfg.Log,
		metrics:       cfg.Metrics,
		signingSecret: cfg.SigningSecret,
		listenAddr:    cfg.ListenAddr,
		tlsEnabled:    cfg.TLSEnabled,
		stopCh:        make(chan struct{}),
	}
	go h.sweepAuthFailures()
	return h
}

// Close signals the auth-failure sweeper to stop. Safe to call multiple times.
func (h *Handler) Close() error {
	h.stopOnce.Do(func() {
		if h.stopCh != nil {
			close(h.stopCh)
		}
	})
	return nil
}

// sweepAuthFailures periodically purges auth-failure entries whose last-fail
// timestamp is older than authFailureWindow. Bounds memory usage under
// source-IP rotation attacks.
func (h *Handler) sweepAuthFailures() {
	t := time.NewTicker(authFailureSweepInt)
	defer t.Stop()
	for {
		select {
		case <-h.stopCh:
			return
		case <-t.C:
			cutoff := time.Now().Add(-authFailureWindow)
			h.authFailures.Range(func(key, val any) bool {
				af, ok := val.(*authFailure)
				if !ok {
					h.authFailures.Delete(key)
					return true
				}
				af.mu.Lock()
				stale := af.lastFail.Before(cutoff)
				af.mu.Unlock()
				if stale {
					h.authFailures.Delete(key)
				}
				return true
			})
		}
	}
}

// evictOldestAuthFailures removes the N entries with the oldest lastFail
// timestamps from the failure map. Called when the map exceeds the cap.
func (h *Handler) evictOldestAuthFailures(n int) {
	type kv struct {
		key      any
		lastFail time.Time
	}
	var entries []kv
	h.authFailures.Range(func(key, val any) bool {
		af, ok := val.(*authFailure)
		if !ok {
			h.authFailures.Delete(key)
			return true
		}
		af.mu.Lock()
		ts := af.lastFail
		af.mu.Unlock()
		entries = append(entries, kv{key: key, lastFail: ts})
		return true
	})
	if len(entries) <= n {
		for _, e := range entries {
			h.authFailures.Delete(e.key)
		}
		return
	}
	// Partial sort: find n oldest. Simple full sort is fine for N=100.
	// Selection-sort-ish: pick smallest n times.
	for i := range n {
		minIdx := i
		for j := i + 1; j < len(entries); j++ {
			if entries[j].lastFail.Before(entries[minIdx].lastFail) {
				minIdx = j
			}
		}
		entries[i], entries[minIdx] = entries[minIdx], entries[i]
		h.authFailures.Delete(entries[i].key)
	}
}

// authFailureMapLen returns the current number of tracked source IPs.
func (h *Handler) authFailureMapLen() int {
	n := 0
	h.authFailures.Range(func(_, _ any) bool {
		n++
		return true
	})
	return n
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
	case strings.HasPrefix(path, "/buckets/"):
		h.routeBucket(w, r, path)
	default:
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
	}
}

// routeBucket dispatches the bucket-configuration surface: the policy and the
// visibility, which are the two things that decide who can reach a bucket and
// which had no endpoint at all until PND-0187. See admin/buckets.go for why
// they live here rather than on the S3 port.
func (h *Handler) routeBucket(w http.ResponseWriter, r *http.Request, path string) {
	name, sub, ok := bucketRoute(path)
	if !ok {
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	switch {
	case sub == "" && r.Method == http.MethodGet:
		h.handleGetBucket(w, r, name)
	case sub == "policy" && r.Method == http.MethodPut:
		h.handlePutBucketPolicy(w, r, name)
	case sub == "policy" && r.Method == http.MethodDelete:
		h.handleDeleteBucketPolicy(w, r, name)
	case sub == "visibility" && r.Method == http.MethodPut:
		h.handlePutBucketVisibility(w, r, name)
	default:
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
	}
}

func (h *Handler) authenticateAdmin(r *http.Request) bool {
	if h.adminToken == "" {
		return false
	}

	clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		clientIP = r.RemoteAddr
	}

	// Check rate limit for this IP
	if val, ok := h.authFailures.Load(clientIP); ok {
		af := val.(*authFailure)
		af.mu.Lock()
		count := af.count
		lastFail := af.lastFail
		af.mu.Unlock()
		if count >= maxAuthFailures && time.Since(lastFail) < authFailureWindow {
			h.log.Warn("admin auth rate limited", "ip", clientIP, "failures", count)
			return false
		}
		// Reset if window has expired
		if time.Since(lastFail) >= authFailureWindow {
			h.authFailures.Delete(clientIP)
		}
	}

	authHeader := r.Header.Get("Authorization")
	expected := "Bearer " + h.adminToken
	// Constant-time comparison to prevent timing attacks
	ok := subtle.ConstantTimeCompare([]byte(authHeader), []byte(expected)) == 1

	if !ok {
		h.log.Warn("admin auth failure", "ip", clientIP)
		val, loaded := h.authFailures.LoadOrStore(clientIP, &authFailure{})
		// If this is a fresh insert and we're now over the cap, evict oldest.
		if !loaded && h.authFailureMapLen() > authFailureCap {
			h.evictOldestAuthFailures(authFailureEvictN)
		}
		af := val.(*authFailure)
		af.mu.Lock()
		af.count++
		af.lastFail = time.Now()
		af.mu.Unlock()
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
	if err := jsonv2.UnmarshalRead(r.Body, &req, jsonx.Strict); err != nil {
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
	if err := jsonv2.MarshalWrite(w, account); err != nil {
		h.log.Error("encode create-account response", "err", err)
	}
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
	if err := jsonv2.UnmarshalRead(r.Body, &req, jsonx.Strict); err != nil {
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
		http.Error(w, `{"error":"allowed_actions is required"}`, http.StatusBadRequest)
		return
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
	if err := jsonv2.MarshalWrite(w, createTokenResponse{
		TokenID: token.TokenID,
		Secret:  secret,
	}); err != nil {
		h.log.Error("encode create-token response", "err", err)
	}
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
	if err := jsonv2.MarshalWrite(w, tokens); err != nil {
		h.log.Error("encode list-tokens response", "err", err)
	}
}

func (h *Handler) handleRevokeToken(w http.ResponseWriter, _ *http.Request, tokenID string) {
	if err := h.db.RevokeToken(tokenID); err != nil {
		h.log.Error("revoke token", "err", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	if h.auth != nil {
		h.auth.InvalidateToken(tokenID)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	if h.metrics == nil {
		http.Error(w, `{"error":"metrics not available"}`, http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := jsonv2.MarshalWrite(w, h.metrics.Snapshot()); err != nil {
		h.log.Error("encode metrics response", "err", err)
	}
}

type presignRequest struct {
	TokenID        string `json:"token_id"`
	Method         string `json:"method"`
	Bucket         string `json:"bucket"`
	Key            string `json:"key"`
	ExpiresSeconds int    `json:"expires_seconds"`
	// Style selects the signature form: "jay" (default) or "aws".
	Style string `json:"style"`
	// Host overrides the host baked into the URL. Required for the aws style
	// whenever JAY_LISTEN_ADDR carries no hostname, because the SigV4
	// signature covers it.
	Host string `json:"host"`
	// Region is the SigV4 credential-scope region; aws style only.
	Region string `json:"region"`
}

type presignResponse struct {
	URL string `json:"url"`
	// Style echoes which form was emitted, so a caller can tell without
	// parsing the URL — and so the day the default changes is visible.
	Style string `json:"style"`
}

// handlePresign mints a presigned URL in one of two forms.
//
// The default is "jay", not "aws": `jay-admin presign` and falco already
// consume the X-Jay-* form, and flipping the default would change what they get
// without them asking. AWS-style presigning is opt-in until it has run in
// production long enough to be the safe default, which is exactly what
// PND-0161 deferred with "default aws cuando se estabilice".
func (h *Handler) handlePresign(w http.ResponseWriter, r *http.Request) {
	var req presignRequest
	if err := jsonv2.UnmarshalRead(r.Body, &req, jsonx.Strict); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	if req.TokenID == "" || req.Bucket == "" || req.Method == "" {
		http.Error(w, `{"error":"token_id, method, and bucket are required"}`, http.StatusBadRequest)
		return
	}

	style := strings.ToLower(strings.TrimSpace(req.Style))
	if style == "" {
		style = presignStyleJay
	}
	if style != presignStyleJay && style != presignStyleAWS {
		http.Error(w, `{"error":"style must be \"jay\" or \"aws\""}`, http.StatusBadRequest)
		return
	}

	// The jay form is HMAC'd with the server signing secret; the aws form is
	// HMAC'd with the token's own secret and needs no server secret at all.
	if style == presignStyleJay && h.signingSecret == "" {
		http.Error(w, `{"error":"signing secret not configured"}`, http.StatusBadRequest)
		return
	}

	if req.ExpiresSeconds <= 0 {
		req.ExpiresSeconds = 3600
	}
	expires := time.Duration(req.ExpiresSeconds) * time.Second

	token, err := h.db.GetToken(req.TokenID)
	if err != nil {
		http.Error(w, `{"error":"token not found"}`, http.StatusBadRequest)
		return
	}
	// A URL signed by a revoked or expired token is rejected the moment anyone
	// uses it, so handing one out with a 200 would be a confirmation with
	// nothing behind it.
	if token.Status != "active" {
		writeJSONError(w, http.StatusBadRequest, "token is not active")
		return
	}
	if token.ExpiresAt != nil && time.Now().After(*token.ExpiresAt) {
		writeJSONError(w, http.StatusBadRequest, "token has expired")
		return
	}

	host := resolvePresignHost(req.Host, h.listenAddr)

	path := "/" + req.Bucket
	if req.Key != "" {
		path += "/" + req.Key
	}

	scheme := "http"
	if h.tlsEnabled {
		scheme = "https"
	}

	var presignedURL string
	switch style {
	case presignStyleAWS:
		// Only the aws form needs a real hostname: its signature covers the
		// host. The jay form keeps taking the listen address as-is, so an
		// existing deployment does not start failing on a call that answered
		// yesterday.
		if err := requirePresignHostname(host); err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		region := strings.TrimSpace(req.Region)
		if region == "" {
			region = defaultPresignRegion
		}
		presignedURL, err = generateAWSPresignedURL(token.SecretKey, scheme, host, req.TokenID, region, req.Method, path, expires)
	default:
		presignedURL, err = generateAdminPresignedURL(h.signingSecret, scheme, host, req.TokenID, req.Method, path, expires)
	}
	if err != nil {
		h.log.Error("generate presigned URL", "err", err, "style", style)
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := jsonv2.MarshalWrite(w, presignResponse{URL: presignedURL, Style: style}); err != nil {
		h.log.Error("encode presign response", "err", err)
	}
}

// writeJSONError answers with a JSON error body whose message is safely quoted.
// fmt.Sprintf into a JSON literal broke the response as soon as the message
// contained a quote — which the presign errors do, since they quote the host.
func writeJSONError(w http.ResponseWriter, status int, message string) {
	body, err := jsonv2.Marshal(map[string]string{"error": message})
	if err != nil {
		body = []byte(`{"error":"internal error"}`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
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
	if err := jsonv2.MarshalWrite(w, objects); err != nil {
		h.log.Error("encode quarantined list", "err", err)
	}
}

type quarantineRequest struct {
	BucketID string `json:"bucket_id"`
	Key      string `json:"key"`
}

func (h *Handler) handleRevalidate(w http.ResponseWriter, r *http.Request) {
	var req quarantineRequest
	if err := jsonv2.UnmarshalRead(r.Body, &req, jsonx.Strict); err != nil {
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
	if err := jsonv2.MarshalWrite(w, map[string]bool{"restored": restored}); err != nil {
		h.log.Error("encode revalidate response", "err", err)
	}
}

func (h *Handler) handlePurge(w http.ResponseWriter, r *http.Request) {
	qm := maintenance.NewQuarantineManager(h.db, h.store, h.log)

	var body struct {
		Mode     string `json:"mode"`
		BucketID string `json:"bucket_id"`
		Key      string `json:"key"`
	}
	if err := jsonv2.UnmarshalRead(r.Body, &body, jsonx.Strict); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	if body.BucketID != "" && body.Key != "" {
		if err := qm.Purge(body.BucketID, body.Key); err != nil {
			h.log.Error("purge", "err", err)
			http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if body.Mode == "all" {
		count, err := qm.PurgeAll()
		if err != nil {
			h.log.Error("purge all", "err", err)
			http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := jsonv2.MarshalWrite(w, map[string]int{"purged": count}); err != nil {
			h.log.Error("encode purge response", "err", err)
		}
		return
	}

	http.Error(w, `{"error":"specify bucket_id+key for single purge, or mode=all for purge all"}`, http.StatusBadRequest)
}

// RequireAdmin wraps a handler in the same authentication the admin API uses:
// Bearer JAY_ADMIN_TOKEN, with the same per-IP backoff on failure.
//
// It exists so net/http/pprof can be mounted on the admin listener without
// exposing it: pprof profiles leak function names, stack arguments and the
// process's memory layout, and /debug/pprof/profile burns CPU on demand. Never
// put them behind anything looser than this.
func (h *Handler) RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !h.authenticateAdmin(r) {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
