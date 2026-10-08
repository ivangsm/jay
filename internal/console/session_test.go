package console

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestSessionRequiredWithoutCookie(t *testing.T) {
	hn := newHarness(t)
	rec := hn.serve(jsonReq(http.MethodGet, "/console/api/session", ""))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", rec.Code)
	}
	if got := decodeBody[map[string]string](t, rec)["reason"]; got != "missing" {
		t.Fatalf("reason = %q", got)
	}
}

func TestSessionUnknownCookieIsCleared(t *testing.T) {
	hn := newHarness(t)
	r := jsonReq(http.MethodGet, "/console/api/session", "")
	r.AddCookie(&http.Cookie{Name: hn.h.cookieName, Value: "forged"})
	rec := hn.serve(r)
	if rec.Code != http.StatusUnauthorized || decodeBody[map[string]string](t, rec)["reason"] != "unknown" {
		t.Fatalf("status %d body %s", rec.Code, rec.Body)
	}
	cleared := false
	for _, c := range rec.Result().Cookies() {
		if c.Name == hn.h.cookieName && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("a rejected cookie was not cleared")
	}
}

func TestSessionIdleExpiry(t *testing.T) {
	hn := newHarness(t)
	c := hn.login()
	hn.clock.advance(31 * time.Minute)
	rec := c.do(http.MethodGet, "/console/api/session", "")
	if rec.Code != http.StatusUnauthorized || decodeBody[map[string]string](t, rec)["reason"] != "expired_idle" {
		t.Fatalf("status %d body %s", rec.Code, rec.Body)
	}
	if hn.h.sessions.len() != 0 {
		t.Fatalf("expired session still in the store (%d)", hn.h.sessions.len())
	}
	// Going back in time must not revive it.
	hn.clock.advance(-31 * time.Minute)
	if rec := c.do(http.MethodGet, "/console/api/session", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("expired session revived: status %d", rec.Code)
	}
}

func TestSessionActivitySlidesUntilAbsolute(t *testing.T) {
	hn := newHarness(t)
	c := hn.login()
	// Active every 20 minutes: far past the 30-minute idle window.
	for elapsed := 20 * time.Minute; elapsed < 8*time.Hour; elapsed += 20 * time.Minute {
		hn.clock.advance(20 * time.Minute)
		if rec := c.do(http.MethodGet, "/console/api/session", ""); rec.Code != http.StatusOK {
			t.Fatalf("at %v: status %d body %s", elapsed, rec.Code, rec.Body)
		}
	}
	// The next touch is at exactly 8 h: the absolute limit wins over activity.
	hn.clock.advance(20 * time.Minute)
	rec := c.do(http.MethodGet, "/console/api/session", "")
	if rec.Code != http.StatusUnauthorized || decodeBody[map[string]string](t, rec)["reason"] != "expired_absolute" {
		t.Fatalf("status %d body %s", rec.Code, rec.Body)
	}
	if hn.h.sessions.len() != 0 {
		t.Fatal("absolutely-expired session still in the store")
	}
}

func TestStaticAssetsDoNotSlideTheSession(t *testing.T) {
	hn := newHarness(t)
	c := hn.login()
	hn.clock.advance(20 * time.Minute)
	hn.serve(httptestGet(hn.h.assets.hash))
	hn.clock.advance(20 * time.Minute)
	if rec := c.do(http.MethodGet, "/console/api/session", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("an asset request kept the session alive: status %d", rec.Code)
	}
}

func httptestGet(hash string) *http.Request {
	r, _ := http.NewRequest(http.MethodGet, "/console/static/"+hash+"/console.css", nil)
	r.RemoteAddr = testPeer
	return r
}

func TestLogoutRevokesTheSession(t *testing.T) {
	hn := newHarness(t)
	c := hn.login()
	rec := c.do(http.MethodDelete, "/console/api/session", "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status %d", rec.Code)
	}
	cleared := false
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == hn.h.cookieName && ck.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("logout did not clear the cookie")
	}
	if hn.h.sessions.len() != 0 {
		t.Fatalf("logout left %d sessions in the store", hn.h.sessions.len())
	}
	// A copy of the old cookie is worthless.
	if rec := c.do(http.MethodGet, "/console/api/session", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("reused cookie: status %d", rec.Code)
	}
	if len(hn.logs.auditLines("console.logout")) != 1 {
		t.Fatal("logout wrote no audit line")
	}
}

func TestLogoutNeedsCSRF(t *testing.T) {
	hn := newHarness(t)
	c := hn.login()
	r := jsonReq(http.MethodDelete, "/console/api/session", "")
	r.AddCookie(c.cookie)
	if rec := hn.serve(r); rec.Code != http.StatusForbidden {
		t.Fatalf("status %d", rec.Code)
	}
	if hn.h.sessions.len() != 1 {
		t.Fatal("a logout without the CSRF token ended the session")
	}
}

func TestSessionCapEvictsTheOldest(t *testing.T) {
	hn := newHarness(t)
	first := hn.login()
	for i := 1; i < maxSessions; i++ {
		hn.clock.advance(time.Second)
		hn.login()
	}
	if hn.h.sessions.len() != maxSessions {
		t.Fatalf("store holds %d, want %d", hn.h.sessions.len(), maxSessions)
	}
	// The 33rd login pushes the first (idle the longest) out.
	hn.clock.advance(time.Second)
	hn.login()
	if hn.h.sessions.len() != maxSessions {
		t.Fatalf("store holds %d after eviction, want %d", hn.h.sessions.len(), maxSessions)
	}
	if rec := first.do(http.MethodGet, "/console/api/session", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("evicted session still authenticates: status %d", rec.Code)
	}
	if !strings.Contains(hn.logs.String(), "console session evicted") {
		t.Fatal("eviction was not logged")
	}
}

func TestExpiredSessionsAreSweptOnLogin(t *testing.T) {
	hn := newHarness(t)
	for range 5 {
		hn.login()
	}
	hn.clock.advance(9 * time.Hour)
	hn.login()
	if hn.h.sessions.len() != 1 {
		t.Fatalf("store holds %d, want only the new session", hn.h.sessions.len())
	}
}

func TestSessionStoreKeepsNoUsableID(t *testing.T) {
	s := newSessionStore()
	id, _, _ := s.create(time.Now())
	for k := range s.m {
		if k == id || strings.Contains(k, id) {
			t.Fatal("the store is keyed by the raw session id")
		}
	}
	if len(id) != 43 {
		t.Fatalf("session id length = %d, want 43", len(id))
	}
}
