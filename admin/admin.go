// Package admin implements jay's management plane: accounts, tokens, presigned
// URLs, metrics and quarantine inspection.
//
// It is served on its own listener (JAY_ADMIN_ADDR) and gated by
// JAY_ADMIN_TOKEN. Nothing here should ever be reachable from the internet.
// The one route a second credential can open is GET /metrics, which also takes
// the read-only JAY_METRICS_TOKEN (see PrometheusHandler).
package admin

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"uuid"

	"github.com/ivangsm/jay/auth"
	"github.com/ivangsm/jay/internal/accesslog"
	"github.com/ivangsm/jay/internal/jsonx"
	"github.com/ivangsm/jay/internal/objops"
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
	objops        *objops.Service
	auth          *auth.Auth
	adminToken    string
	metricsToken  string
	metricsPublic bool
	extraMetrics  func() []maintenance.MetricFamily
	log           *slog.Logger
	metrics       *maintenance.Metrics
	signingSecret string
	listenAddr    string
	tlsEnabled    bool

	authFailures sync.Map // map[string]*authFailure keyed by remote IP
	// authFailureCount is the number of entries in authFailures, kept in step
	// with every insert and delete so the cap check is O(1). Counting the map
	// on each new failing address made every failure cost a walk of up to
	// authFailureCap entries — under source-address rotation, which is
	// exactly when the cap matters.
	authFailureCount atomic.Int64

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
	DB         *meta.DB
	Store      *store.Store
	Auth       *auth.Auth
	AdminToken string
	// MetricsToken is an optional second bearer that opens GET /metrics and
	// nothing else, so a Prometheus server never has to hold the credential
	// that mints tokens. Empty means there is no such token.
	MetricsToken string
	// MetricsPublic serves GET /metrics with no authentication at all. It is
	// an explicit opt-in; without it and without MetricsToken, /metrics takes
	// the admin token like every other route.
	MetricsPublic bool
	// ExtraMetrics, when set, is called on every /metrics scrape and its
	// families are appended to the counters. The server uses it for the
	// readings that live outside Metrics: free disk, the bbolt ping.
	ExtraMetrics  func() []maintenance.MetricFamily
	Log           *slog.Logger
	Metrics       *maintenance.Metrics
	SigningSecret string
	ListenAddr    string
	TLSEnabled    bool
}

// NewHandler creates a new admin API handler.
func NewHandler(cfg AdminConfig) *Handler {
	// authorize logs every unauthorised request, so a nil logger
	// would panic on exactly the path nobody exercises before production.
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	h := &Handler{
		db:            cfg.DB,
		store:         cfg.Store,
		objops:        objops.New(cfg.DB, cfg.Store, cfg.Log),
		auth:          cfg.Auth,
		adminToken:    cfg.AdminToken,
		metricsToken:  cfg.MetricsToken,
		metricsPublic: cfg.MetricsPublic,
		extraMetrics:  cfg.ExtraMetrics,
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
					h.forgetAuthFailures(key)
					return true
				}
				af.mu.Lock()
				stale := af.lastFail.Before(cutoff)
				af.mu.Unlock()
				if stale {
					h.forgetAuthFailures(key)
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
			h.forgetAuthFailures(key)
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
			h.forgetAuthFailures(e.key)
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
		h.forgetAuthFailures(entries[i].key)
	}
}

// authFailureMapLen returns the current number of tracked source IPs.
func (h *Handler) authFailureMapLen() int {
	return int(h.authFailureCount.Load())
}

// recordAuthFailure counts one failed attempt from clientIP at now.
//
// The new entry carries its timestamp from the start: with a zero lastFail it
// would be the "oldest" in the map, and the eviction its insert may trigger
// would drop it first — the address that just failed would start over from
// zero failures.
func (h *Handler) recordAuthFailure(clientIP string, now time.Time) {
	val, loaded := h.authFailures.LoadOrStore(clientIP, &authFailure{lastFail: now})
	if !loaded && h.authFailureCount.Add(1) > authFailureCap {
		h.evictOldestAuthFailures(authFailureEvictN)
	}
	af := val.(*authFailure)
	af.mu.Lock()
	af.count++
	af.lastFail = now
	af.mu.Unlock()
}

// forgetAuthFailures drops the entry for key. Only the call that actually
// removed it decrements authFailureCount, so concurrent deletes of the same
// address cannot drive the count below the map's real size.
func (h *Handler) forgetAuthFailures(key any) {
	if _, ok := h.authFailures.LoadAndDelete(key); ok {
		h.authFailureCount.Add(-1)
	}
}

// route is one endpoint of the admin API.
type route struct {
	method string
	// pattern is the path under /_jay. "{name}" matches exactly one non-empty
	// segment; "{id...}", only as the last segment, matches the non-empty rest
	// of the path, slashes included.
	pattern string
	serve   func(h *Handler, w http.ResponseWriter, r *http.Request, param string)
}

// routes is every endpoint the admin API serves: the one list the dispatcher,
// the Allow header of a 405 and the tests all read. An endpoint cannot exist
// without the test that checks it requires the admin token knowing about it.
var routes = []route{
	{http.MethodPost, "/accounts", noParam((*Handler).handleCreateAccount)},
	{http.MethodGet, "/accounts", noParam((*Handler).handleListAccounts)},
	{http.MethodPost, "/tokens", noParam((*Handler).handleCreateToken)},
	{http.MethodGet, "/tokens", noParam((*Handler).handleListTokens)},
	{http.MethodDelete, "/tokens/{id...}", (*Handler).handleRevokeToken},
	{http.MethodGet, "/metrics", noParam((*Handler).handleMetrics)},
	{http.MethodPost, "/presign", noParam((*Handler).handlePresign)},
	{http.MethodGet, "/quarantine", noParam((*Handler).handleListQuarantined)},
	{http.MethodDelete, "/quarantine", noParam((*Handler).handlePurge)},
	{http.MethodPost, "/quarantine/revalidate", noParam((*Handler).handleRevalidate)},
	// The bucket-configuration surface: the policy and the visibility, the two
	// things that decide who can reach a bucket. See admin/buckets.go for why
	// they live here rather than on the S3 port. Bucket names cannot contain a
	// slash (meta.ValidBucketName), so {name} is one segment.
	{http.MethodGet, "/buckets", noParam((*Handler).handleListBuckets)},
	{http.MethodPost, "/buckets", noParam((*Handler).handleCreateBucket)},
	{http.MethodDelete, "/buckets/{name}", (*Handler).handleDeleteBucket},
	{http.MethodGet, "/buckets/{name}", (*Handler).handleGetBucket},
	{http.MethodPut, "/buckets/{name}/policy", (*Handler).handlePutBucketPolicy},
	{http.MethodDelete, "/buckets/{name}/policy", (*Handler).handleDeleteBucketPolicy},
	{http.MethodPut, "/buckets/{name}/visibility", (*Handler).handlePutBucketVisibility},
}

func noParam(f func(*Handler, http.ResponseWriter, *http.Request)) func(*Handler, http.ResponseWriter, *http.Request, string) {
	return func(h *Handler, w http.ResponseWriter, r *http.Request, _ string) { f(h, w, r) }
}

// matchPattern reports whether path matches a route pattern, and the value of
// its wildcard segment if it has one.
func matchPattern(pattern, path string) (string, bool) {
	want := strings.Split(strings.TrimPrefix(pattern, "/"), "/")
	got := strings.Split(strings.TrimPrefix(path, "/"), "/")
	param := ""
	for i, seg := range want {
		if i >= len(got) {
			return "", false
		}
		switch {
		case strings.HasSuffix(seg, "...}"):
			rest := strings.Join(got[i:], "/")
			return rest, rest != ""
		case strings.HasPrefix(seg, "{"):
			if got[i] == "" {
				return "", false
			}
			param = got[i]
		case got[i] != seg:
			return "", false
		}
	}
	if len(got) != len(want) {
		return "", false
	}
	return param, true
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Authentication comes before routing, so an unauthenticated caller
	// learns nothing about which paths exist.
	if !h.authorize(r, scopeAdmin) {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/_jay")
	var allowed []string
	for i := range routes {
		param, ok := matchPattern(routes[i].pattern, path)
		if !ok {
			continue
		}
		if routes[i].method == r.Method {
			routes[i].serve(h, w, r, param)
			return
		}
		allowed = append(allowed, routes[i].method)
	}

	// A path that exists under other methods is a 405 that says which ones,
	// not a 404 that makes the caller doubt the path.
	if len(allowed) > 0 {
		slices.Sort(allowed)
		w.Header().Set("Allow", strings.Join(allowed, ", "))
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSONError(w, http.StatusNotFound, "not found")
}

// scope is what a route accepts as a credential.
type scope int

const (
	// scopeAdmin accepts JAY_ADMIN_TOKEN and nothing else: every /_jay route
	// and pprof.
	scopeAdmin scope = iota
	// scopeMetrics also accepts JAY_METRICS_TOKEN. Only GET /metrics asks for
	// it.
	scopeMetrics
)

// credential is what an Authorization header proved.
type credential int

const (
	credentialNone credential = iota
	credentialMetrics
	credentialAdmin
)

// credentialOf compares the header with each configured bearer in constant
// time. A token that is not configured never matches — not even an empty
// bearer, which is what comparing against "Bearer " would let through.
func (h *Handler) credentialOf(header string) credential {
	isAdmin := h.adminToken != "" &&
		subtle.ConstantTimeCompare([]byte(header), []byte("Bearer "+h.adminToken)) == 1
	isMetrics := h.metricsToken != "" &&
		subtle.ConstantTimeCompare([]byte(header), []byte("Bearer "+h.metricsToken)) == 1
	switch {
	case isAdmin:
		return credentialAdmin
	case isMetrics:
		return credentialMetrics
	}
	return credentialNone
}

// authorize is the bearer gate of the admin listener. It reports whether the
// request may proceed; every refusal is logged, counted in the source
// address's backoff and in the admin auth failure metric.
//
// The per-address backoff is shared by both scopes: guessing on /metrics costs
// the same as guessing on /_jay. And only the ADMIN token clears it. A metrics
// token that could clear the count would let whoever holds it interleave one
// valid scrape between every few guesses at the admin token and never be
// locked out.
func (h *Handler) authorize(r *http.Request, need scope) bool {
	ok, _ := h.authorizeHeader(r, r.Header.Get("Authorization"), need)
	return ok
}

// authorizeHeader is authorize for an Authorization header value that did not
// necessarily arrive in r's headers. lockedOut reports that the refusal was the
// address's backoff rather than the credential, which the web console's login
// needs in order to answer 429 instead of 401.
func (h *Handler) authorizeHeader(r *http.Request, header string, need scope) (ok, lockedOut bool) {
	ip := accesslog.PeerIP(r)
	requestID := accesslog.RequestID(r.Context())

	if failures, locked := h.lockedOut(ip); locked {
		h.log.Warn("admin auth rate limited", "ip", ip, "failures", failures, "request_id", requestID)
		h.metrics.RecordAdminAuthFailure()
		return false, true
	}

	var reason string
	switch cred := h.credentialOf(header); {
	case cred == credentialAdmin:
		h.forgetAuthFailures(ip)
		return true, false
	case cred == credentialMetrics && need == scopeMetrics:
		return true, false
	case cred == credentialMetrics:
		// A valid credential in the wrong place. It is refused like a wrong
		// one — the metrics token must not be an admin credential in
		// disguise — and said plainly, because the likely cause is a scraper
		// pointed at the wrong path.
		reason = "the metrics token only opens GET /metrics"
	default:
		reason = "missing or wrong bearer token"
	}

	h.log.Warn("admin auth failure", "ip", ip, "reason", reason, "request_id", requestID)
	h.recordAuthFailure(ip, time.Now())
	h.metrics.RecordAdminAuthFailure()
	return false, false
}

// CredentialResult is the outcome of AuthenticateAdminToken.
type CredentialResult int

const (
	// CredentialAccepted is the admin token. It clears the address's failures.
	CredentialAccepted CredentialResult = iota
	// CredentialRejected is a wrong token, the metrics token included. It is counted.
	CredentialRejected
	// CredentialLockedOut means the address used up its failures inside the window.
	CredentialLockedOut
)

// AuthenticateAdminToken checks candidate as if it had arrived as
// "Authorization: Bearer <candidate>" on r: same constant-time comparison,
// same per-address backoff, same log line and failure metric. The web
// console's login goes through here so it is not a second door with its own
// counter.
func (h *Handler) AuthenticateAdminToken(r *http.Request, candidate string) CredentialResult {
	ok, locked := h.authorizeHeader(r, "Bearer "+candidate, scopeAdmin)
	switch {
	case ok:
		return CredentialAccepted
	case locked:
		return CredentialLockedOut
	}
	return CredentialRejected
}

// lockedOut reports whether ip has used up its failures inside the window,
// and how many it has. An entry whose window has passed is forgotten here.
func (h *Handler) lockedOut(ip string) (int, bool) {
	val, ok := h.authFailures.Load(ip)
	if !ok {
		return 0, false
	}
	af := val.(*authFailure)
	af.mu.Lock()
	count := af.count
	lastFail := af.lastFail
	af.mu.Unlock()

	if time.Since(lastFail) >= authFailureWindow {
		h.forgetAuthFailures(ip)
		return 0, false
	}
	return count, count >= maxAuthFailures
}

type createAccountRequest struct {
	Name string `json:"name"`
}

func (h *Handler) handleCreateAccount(w http.ResponseWriter, r *http.Request) {
	var req createAccountRequest
	if err := jsonv2.UnmarshalRead(r.Body, &req, jsonx.Strict); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	// The name is the only handle an operator has on an account — there is no
	// endpoint that lists them — so an account without one is refused, not
	// created anonymous.
	if strings.TrimSpace(req.Name) == "" {
		writeJSONError(w, http.StatusBadRequest, "name is required")
		return
	}

	account := &meta.Account{
		AccountID: uuid.New().String(),
		Name:      req.Name,
		Status:    "active",
	}

	if err := h.db.CreateAccount(account); err != nil {
		h.log.Error("create account", "err", err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}
	h.audit(r, "account.create",
		slog.String("account_id", account.AccountID),
		slog.String("name", account.Name))

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
	// ExpiresAt echoes the expiry that was installed, so a caller can see it
	// was honoured rather than assume it.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

func (h *Handler) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	var req createTokenRequest
	if err := jsonv2.UnmarshalRead(r.Body, &req, jsonx.Strict); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.AccountID == "" {
		writeJSONError(w, http.StatusBadRequest, "account_id required")
		return
	}

	// Verify account exists. Only a missing account is the caller's mistake;
	// a read that fails is reported as what it is.
	if _, err := h.db.GetAccount(req.AccountID); err != nil {
		if errors.Is(err, meta.ErrAccountNotFound) {
			writeJSONError(w, http.StatusBadRequest, "account not found")
			return
		}
		h.log.Error("get account", "err", err, "account_id", req.AccountID)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Everything the caller sent is validated before the secret is generated:
	// hashing it is bcrypt, and a request that is going to be refused should
	// not pay for it.
	actions := req.AllowedActions
	if len(actions) == 0 {
		writeJSONError(w, http.StatusBadRequest, "allowed_actions is required")
		return
	}
	// An action that is not one jay knows matches nothing: the token would be
	// created, answer 201, and fail every request that needed it. Same rule as
	// the bucket policy: refused where it enters.
	for _, action := range actions {
		if !meta.ValidAction(action) {
			writeJSONError(w, http.StatusBadRequest, fmt.Sprintf(
				"unknown action %q in allowed_actions: use \"*\" or any of %s",
				action, strings.Join(meta.AllActions, ", ")))
			return
		}
	}
	expiresAt, err := parseTokenExpiry(req.ExpiresAt, time.Now())
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Generate secret
	secretBytes := make([]byte, 32)
	if _, err := rand.Read(secretBytes); err != nil {
		h.log.Error("generate secret", "err", err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}
	secret := hex.EncodeToString(secretBytes)

	// Hash secret for storage
	hash, err := auth.HashSecret(secret)
	if err != nil {
		h.log.Error("hash secret", "err", err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
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
		ExpiresAt:      expiresAt,
		Status:         "active",
	}

	if err := h.db.CreateToken(token); err != nil {
		h.log.Error("create token", "err", err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}
	// Everything that decides what the new credential can reach, and nothing
	// that would let someone use it: the secret exists in the response body
	// and nowhere else.
	h.audit(r, "token.create",
		slog.String("token_id", token.TokenID),
		slog.String("account_id", token.AccountID),
		slog.String("name", token.Name),
		slog.Any("allowed_actions", token.AllowedActions),
		slog.Any("bucket_scope", token.BucketScope),
		slog.Any("prefix_scope", token.PrefixScope),
		expiryAttr(token.ExpiresAt))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := jsonv2.MarshalWrite(w, createTokenResponse{
		TokenID:   token.TokenID,
		Secret:    secret,
		ExpiresAt: token.ExpiresAt,
	}); err != nil {
		h.log.Error("encode create-token response", "err", err)
	}
}

// parseTokenExpiry turns the optional expires_at of a create-token request
// into the token's expiry. Empty means the token does not expire.
//
// The field used to be decoded and then dropped, so a caller that asked for a
// token that dies on Friday got a 201 and one that never dies. An expiry that
// is accepted has to be installed, and one that cannot be installed — not a
// timestamp, or already past — is refused rather than ignored.
func parseTokenExpiry(raw string, now time.Time) (*time.Time, error) {
	if raw == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return nil, errors.New("expires_at must be an RFC 3339 timestamp, e.g. 2030-01-02T15:04:05Z")
	}
	if !t.After(now) {
		return nil, errors.New("expires_at is not in the future: the token would be dead on arrival")
	}
	t = t.UTC()
	return &t, nil
}

func (h *Handler) handleListTokens(w http.ResponseWriter, r *http.Request) {
	accountID := r.URL.Query().Get("account_id")
	tokens, err := h.db.ListTokens(accountID)
	if err != nil {
		h.log.Error("list tokens", "err", err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := jsonv2.MarshalWrite(w, tokens); err != nil {
		h.log.Error("encode list-tokens response", "err", err)
	}
}

func (h *Handler) handleRevokeToken(w http.ResponseWriter, r *http.Request, tokenID string) {
	if err := h.db.RevokeToken(tokenID); err != nil {
		// An id that names no token is the caller's mistake, not jay breaking.
		if errors.Is(err, meta.ErrTokenNotFound) {
			writeJSONError(w, http.StatusNotFound, "token not found")
			return
		}
		h.log.Error("revoke token", "err", err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if h.auth != nil {
		h.auth.InvalidateToken(tokenID)
	}
	h.audit(r, "token.revoke", slog.String("token_id", tokenID))
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	if h.metrics == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "metrics not available")
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

// handlePresign mints a presigned URL in one of two forms. The default is
// "jay", not "aws": `jay-admin presign` and falco consume the X-Jay-* form,
// and flipping the default would change what they get without them asking.
// TODO(revisar): make "aws" the default once it has run in production.
func (h *Handler) handlePresign(w http.ResponseWriter, r *http.Request) {
	var req presignRequest
	if err := jsonv2.UnmarshalRead(r.Body, &req, jsonx.Strict); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.TokenID == "" || req.Bucket == "" || req.Method == "" {
		writeJSONError(w, http.StatusBadRequest, "token_id, method, and bucket are required")
		return
	}

	style := strings.ToLower(strings.TrimSpace(req.Style))
	if style == "" {
		style = presignStyleJay
	}
	if style != presignStyleJay && style != presignStyleAWS {
		writeJSONError(w, http.StatusBadRequest, `style must be "jay" or "aws"`)
		return
	}

	// The jay form is HMAC'd with the server signing secret; the aws form is
	// HMAC'd with the token's own secret and needs no server secret at all.
	if style == presignStyleJay && h.signingSecret == "" {
		writeJSONError(w, http.StatusBadRequest, "signing secret not configured")
		return
	}

	if req.ExpiresSeconds <= 0 {
		req.ExpiresSeconds = 3600
	}
	expires := time.Duration(req.ExpiresSeconds) * time.Second

	token, err := h.db.GetToken(req.TokenID)
	if err != nil {
		if errors.Is(err, meta.ErrTokenNotFound) {
			writeJSONError(w, http.StatusBadRequest, "token not found")
			return
		}
		// Not the caller's mistake: a token that exists but cannot be read —
		// typically a JAY_SIGNING_SECRET that does not match the one the
		// token was encrypted with. "token not found" would send the operator
		// looking for the wrong problem.
		h.log.Error("get token", "err", err, "token_id", req.TokenID)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
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
	// What was granted, to whom and until when — never the URL: its query
	// string carries the signature, and a log line holding it is a working
	// credential for anyone who can read the log.
	h.audit(r, "presign.issue",
		slog.String("token_id", req.TokenID),
		slog.String("method", req.Method),
		slog.String("bucket", req.Bucket),
		slog.String("key", req.Key),
		slog.String("style", style),
		slog.Int("expires_seconds", req.ExpiresSeconds),
		slog.String("expires_at", time.Now().Add(expires).UTC().Format(time.RFC3339)))

	w.Header().Set("Content-Type", "application/json")
	if err := jsonv2.MarshalWrite(w, presignResponse{URL: presignedURL, Style: style}); err != nil {
		h.log.Error("encode presign response", "err", err)
	}
}

// writeJSONError answers with a JSON error body whose message is safely quoted.
// Never fmt.Sprintf into a JSON literal: the presign errors quote the host,
// and an unescaped quote breaks the document.
//
// Every error the admin API answers goes through here. http.Error was used for
// most of them before and labelled a JSON body text/plain.
func writeJSONError(w http.ResponseWriter, status int, message string) {
	body, err := jsonv2.Marshal(map[string]string{"error": message})
	if err != nil {
		body = []byte(`{"error":"internal error"}`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// Quarantine handlers

func (h *Handler) handleListQuarantined(w http.ResponseWriter, r *http.Request) {
	qm := maintenance.NewQuarantineManager(h.db, h.store, h.requestLog(r))
	objects, err := qm.ListQuarantined()
	if err != nil {
		h.log.Error("list quarantined", "err", err)
		writeJSONError(w, http.StatusInternalServerError, "internal error")
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
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.BucketID == "" || req.Key == "" {
		writeJSONError(w, http.StatusBadRequest, "bucket_id and key are required")
		return
	}
	qm := maintenance.NewQuarantineManager(h.db, h.store, h.requestLog(r))
	restored, err := qm.Revalidate(req.BucketID, req.Key)
	if err != nil {
		h.writeQuarantineError(w, "revalidate", req.BucketID, req.Key, err)
		return
	}
	h.audit(r, "quarantine.revalidate",
		slog.String("bucket_id", req.BucketID),
		slog.String("key", req.Key),
		slog.Bool("restored", restored))
	w.Header().Set("Content-Type", "application/json")
	if err := jsonv2.MarshalWrite(w, map[string]bool{"restored": restored}); err != nil {
		h.log.Error("encode revalidate response", "err", err)
	}
}

// purgeAllResponse answers DELETE /_jay/quarantine with mode "all". failed is
// always present, so a caller can tell a clean purge from a partial one
// without relying on the status alone.
type purgeAllResponse struct {
	Error  string                     `json:"error,omitempty"`
	Purged int                        `json:"purged"`
	Failed []maintenance.PurgeFailure `json:"failed"`
}

func (h *Handler) handlePurge(w http.ResponseWriter, r *http.Request) {
	qm := maintenance.NewQuarantineManager(h.db, h.store, h.requestLog(r))

	var body struct {
		Mode     string `json:"mode"`
		BucketID string `json:"bucket_id"`
		Key      string `json:"key"`
	}
	if err := jsonv2.UnmarshalRead(r.Body, &body, jsonx.Strict); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	single := body.BucketID != "" || body.Key != ""
	switch {
	case single && body.Mode != "":
		writeJSONError(w, http.StatusBadRequest, "give either mode=all or bucket_id+key, not both")
	case single && (body.BucketID == "" || body.Key == ""):
		writeJSONError(w, http.StatusBadRequest, "a single purge needs both bucket_id and key")
	case single:
		if err := qm.Purge(body.BucketID, body.Key); err != nil {
			h.writeQuarantineError(w, "purge", body.BucketID, body.Key, err)
			return
		}
		h.audit(r, "quarantine.purge",
			slog.String("bucket_id", body.BucketID),
			slog.String("key", body.Key))
		w.WriteHeader(http.StatusNoContent)
	case body.Mode == "all":
		h.purgeAll(w, r, qm)
	default:
		writeJSONError(w, http.StatusBadRequest, "specify bucket_id+key for single purge, or mode=all for purge all")
	}
}

// purgeAll answers a mode=all purge. A partial purge is a 500 that says what
// was purged and what was not — never a 200 with a count that leaves out the
// failures.
func (h *Handler) purgeAll(w http.ResponseWriter, r *http.Request, qm *maintenance.QuarantineManager) {
	count, err := qm.PurgeAll()
	resp := purgeAllResponse{Purged: count, Failed: []maintenance.PurgeFailure{}}
	status := http.StatusOK
	level := slog.LevelInfo

	var partial *maintenance.PurgeAllError
	switch {
	case errors.As(err, &partial):
		resp.Error = partial.Error()
		resp.Failed = partial.Failed
		status = http.StatusInternalServerError
		level = slog.LevelWarn
	case err != nil:
		h.log.Error("purge all", "err", err)
		writeJSONError(w, http.StatusInternalServerError, "purge failed: "+err.Error())
		return
	}

	// A partial purge still gets its line, at WARN and with both counts: the
	// objects it did remove are gone for good, and the trail has to say so
	// even though the request as a whole failed.
	h.auditAt(r, level, "quarantine.purge_all",
		slog.Int("purged", resp.Purged),
		slog.Int("failed", len(resp.Failed)))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := jsonv2.MarshalWrite(w, resp); err != nil {
		h.log.Error("encode purge response", "err", err)
	}
}

// writeQuarantineError maps what QuarantineManager returns. The quarantine
// surface only acts on quarantined objects, and that check lives in the same
// bbolt transaction as the write (meta.DeleteQuarantinedObject,
// meta.RestoreQuarantinedObject); here it only becomes a status.
func (h *Handler) writeQuarantineError(w http.ResponseWriter, action, bucketID, key string, err error) {
	switch {
	case errors.Is(err, meta.ErrObjectNotFound), errors.Is(err, meta.ErrBucketNotFound):
		writeJSONError(w, http.StatusNotFound, "object not found")
	case errors.Is(err, meta.ErrObjectNotQuarantined):
		writeJSONError(w, http.StatusConflict, "object is not quarantined")
	default:
		h.log.Error("quarantine "+action, "err", err, "bucket_id", bucketID, "key", key)
		writeJSONError(w, http.StatusInternalServerError, action+" failed: "+err.Error())
	}
}

// RequireAdmin wraps a handler in the same authentication the admin API uses:
// Bearer JAY_ADMIN_TOKEN, with the same per-IP backoff on failure. The metrics
// token does not open it.
//
// It exists so net/http/pprof can be mounted on the admin listener without
// exposing it: pprof profiles leak function names, stack arguments and the
// process's memory layout, and /debug/pprof/profile burns CPU on demand. Never
// put them behind anything looser than this.
func (h *Handler) RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !h.authorize(r, scopeAdmin) {
			writeJSONError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next.ServeHTTP(w, r)
	})
}
