package api

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daimoniac/suppline/internal/statestore"
)

type fakeDirectory struct {
	mu     sync.Mutex
	leader statestore.Leader
	ok     bool
	calls  atomic.Int32
}

func (d *fakeDirectory) CurrentLeader(context.Context) (statestore.Leader, bool, error) {
	d.calls.Add(1)
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.leader, d.ok, nil
}

func (d *fakeDirectory) set(address string, ok bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.leader = statestore.Leader{Holder: "leader-pod", Address: address}
	d.ok = ok
}

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// standby builds a standby's front handler in front of a local handler that
// must never be reached.
func standby(t *testing.T, dir LeaderDirectory, isLeader func() bool) *leaderProxy {
	t.Helper()
	local := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isLeader() {
			t.Errorf("standby served %s itself", r.URL.Path)
		}
		w.Header().Set("X-Local", "yes")
		_, _ = io.WriteString(w, "local")
	})
	p := newLeaderProxy(local, isLeader, "standby-pod", dir, quietLogger())
	p.waitFor = 300 * time.Millisecond
	p.pollEvery = 20 * time.Millisecond
	return p
}

func TestStandbyForwardsToLeader(t *testing.T) {
	var seen http.Header
	var seenPath string
	leaderSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, seenPath = r.Header.Clone(), r.URL.RequestURI()
		w.Header().Set(HeaderServedBy, "leader-pod")
		_, _ = io.WriteString(w, "from leader")
	}))
	defer leaderSrv.Close()

	dir := &fakeDirectory{}
	dir.set(leaderSrv.URL, true)
	front := httptest.NewServer(standby(t, dir, func() bool { return false }))
	defer front.Close()

	req, _ := http.NewRequest(http.MethodGet, front.URL+"/suppline/api/v1/scans?limit=5", nil)
	req.Header.Set("Authorization", "Bearer k")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK || string(body) != "from leader" {
		t.Fatalf("got %d %q, want the leader's answer", resp.StatusCode, body)
	}
	if got := resp.Header.Get(HeaderServedBy); got != "leader-pod" {
		t.Fatalf("%s = %q, want leader-pod", HeaderServedBy, got)
	}
	if seenPath != "/suppline/api/v1/scans?limit=5" {
		t.Fatalf("leader saw %q, want the original path and query", seenPath)
	}
	if seen.Get("Authorization") != "Bearer k" || seen.Get(headerProxied) != "standby-pod" || seen.Get("X-Forwarded-For") == "" {
		t.Fatalf("leader saw headers %v", seen)
	}

	// A second request within the cache window does not query the database again.
	before := dir.calls.Load()
	resp, err = http.Get(front.URL + "/api/v1/scans")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if dir.calls.Load() != before {
		t.Fatal("leader looked up again inside the cache window")
	}
}

func TestLeaderServesLocally(t *testing.T) {
	dir := &fakeDirectory{}
	p := standby(t, dir, func() bool { return true })
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/scans", nil))
	if rec.Body.String() != "local" || rec.Header().Get(HeaderServedBy) != "standby-pod" {
		t.Fatalf("leader answered %q with served-by %q", rec.Body.String(), rec.Header().Get(HeaderServedBy))
	}
	if dir.calls.Load() != 0 {
		t.Fatal("leader looked up the leader")
	}
}

func TestStandbyRefusesForwardedRequest(t *testing.T) {
	dir := &fakeDirectory{}
	dir.set("http://127.0.0.1:1", true)
	p := standby(t, dir, func() bool { return false })
	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans", nil)
	req.Header.Set(headerProxied, "other-standby")
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503 for a forwarded request", rec.Code)
	}
}

func TestStandbyWithoutLeaderAnswers503(t *testing.T) {
	p := standby(t, &fakeDirectory{}, func() bool { return false })
	rec := httptest.NewRecorder()
	start := time.Now()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/scans", nil))
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("status %d Retry-After %q, want 503 with Retry-After", rec.Code, rec.Header().Get("Retry-After"))
	}
	if time.Since(start) < p.waitFor {
		t.Fatal("gave up before waiting for a leader")
	}
}

func TestStandbyWaitsForNewLeader(t *testing.T) {
	leaderSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "new leader")
	}))
	defer leaderSrv.Close()

	dir := &fakeDirectory{}
	p := standby(t, dir, func() bool { return false })
	p.waitFor = 2 * time.Second
	time.AfterFunc(100*time.Millisecond, func() { dir.set(leaderSrv.URL, true) })

	front := httptest.NewServer(p)
	defer front.Close()
	resp, err := http.Get(front.URL + "/api/v1/scans")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "new leader" {
		t.Fatalf("got %d %q, want the new leader's answer", resp.StatusCode, body)
	}
}

func TestStandbyServesLocallyWhenElectedWhileWaiting(t *testing.T) {
	var elected atomic.Bool
	p := standby(t, &fakeDirectory{}, elected.Load)
	p.waitFor = 2 * time.Second
	time.AfterFunc(50*time.Millisecond, func() { elected.Store(true) })
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/scans", nil))
	if rec.Body.String() != "local" {
		t.Fatalf("got %d %q, want a local answer after election", rec.Code, rec.Body.String())
	}
}

func deadAddress(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := "http://" + ln.Addr().String()
	ln.Close()
	return addr
}

// A killed leader still holds its lock until PostgreSQL notices, so the
// directory names it for a moment. The request never reached it, so the
// standby retries on whoever leads next, body and all.
func TestRefusedLeaderIsRetriedOnTheNextLeader(t *testing.T) {
	var gotBody string
	next := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		_, _ = io.WriteString(w, "next leader")
	}))
	defer next.Close()

	dir := &fakeDirectory{}
	dir.set(deadAddress(t), true)
	p := standby(t, dir, func() bool { return false })
	p.waitFor = 2 * time.Second
	time.AfterFunc(100*time.Millisecond, func() { dir.set(next.URL, true) })

	front := httptest.NewServer(p)
	defer front.Close()
	resp, err := http.Post(front.URL+"/api/v1/scan-requests", "application/json", strings.NewReader(`{"image":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "next leader" {
		t.Fatalf("got %d %q, want the next leader's answer", resp.StatusCode, body)
	}
	if gotBody != `{"image":"x"}` {
		t.Fatalf("next leader got body %q, want the original", gotBody)
	}
}

func TestLeaderThatStaysUnreachableAnswers503(t *testing.T) {
	dir := &fakeDirectory{}
	dir.set(deadAddress(t), true)
	p := standby(t, dir, func() bool { return false })
	rec := httptest.NewRecorder()
	start := time.Now()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/scans", nil))
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("status %d Retry-After %q, want 503 with Retry-After", rec.Code, rec.Header().Get("Retry-After"))
	}
	if time.Since(start) < p.waitFor {
		t.Fatal("gave up before waiting for another leader")
	}
	if dir.calls.Load() < 2 {
		t.Fatalf("looked the leader up %d times; an unreachable leader must not stay cached", dir.calls.Load())
	}
}

// Once the leader has the request, the standby cannot know whether it acted
// on it, so it must not send it again.
func TestLeaderFailingMidRequestAnswers502(t *testing.T) {
	var hits atomic.Int32
	leaderSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		conn, _, err := http.NewResponseController(w).Hijack()
		if err == nil {
			conn.Close()
		}
	}))
	defer leaderSrv.Close()

	dir := &fakeDirectory{}
	dir.set(leaderSrv.URL, true)
	p := standby(t, dir, func() bool { return false })
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/scan-requests", strings.NewReader("{}")))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status %d, want 502", rec.Code)
	}
	if hits.Load() != 1 {
		t.Fatalf("leader got the request %d times, want once", hits.Load())
	}
}

// The API server's 15 s write timeout must not cut a proxied long-poll.
func TestProxiedResponseOutlivesWriteTimeout(t *testing.T) {
	leaderSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(400 * time.Millisecond)
		_, _ = io.WriteString(w, "verdict")
	}))
	defer leaderSrv.Close()

	dir := &fakeDirectory{}
	dir.set(leaderSrv.URL, true)
	front := httptest.NewUnstartedServer(standby(t, dir, func() bool { return false }))
	front.Config.WriteTimeout = 100 * time.Millisecond
	front.Start()
	defer front.Close()

	resp, err := http.Get(front.URL + "/api/v1/scan-requests/sha256:x")
	if err != nil {
		t.Fatalf("proxied long request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "verdict" {
		t.Fatalf("got %q, want the full answer", body)
	}
}
