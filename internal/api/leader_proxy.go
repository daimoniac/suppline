package api

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daimoniac/suppline/internal/statestore"
)

// Headers of the standby proxy (ADR 0004).
const (
	// HeaderServedBy names the instance that handled the request.
	HeaderServedBy = "X-Suppline-Served-By"
	// headerProxied marks a request a standby forwarded. A standby answers
	// 503 to such a request instead of forwarding it again, so a stale view
	// of the leader can never loop.
	headerProxied = "X-Suppline-Proxied"
)

// LeaderDirectory finds the current leader. statestore.Store implements it.
type LeaderDirectory interface {
	CurrentLeader(ctx context.Context) (statestore.Leader, bool, error)
}

// leaderProxy serves requests itself on the leader and forwards them to the
// leader on a standby. Nearly every endpoint reads state that lives only in
// the leader's memory, so a standby serves nothing itself.
type leaderProxy struct {
	local    http.Handler
	isLeader func() bool
	self     string
	dir      LeaderDirectory
	logger   *slog.Logger

	cacheFor  time.Duration
	waitFor   time.Duration
	pollEvery time.Duration

	mu        sync.Mutex
	leader    statestore.Leader
	found     bool
	checkedAt time.Time
	proxies   map[string]*httputil.ReverseProxy
}

func newLeaderProxy(local http.Handler, isLeader func() bool, self string, dir LeaderDirectory, logger *slog.Logger) *leaderProxy {
	return &leaderProxy{
		local:     local,
		isLeader:  isLeader,
		self:      self,
		dir:       dir,
		logger:    logger,
		cacheFor:  2 * time.Second,
		waitFor:   10 * time.Second,
		pollEvery: 500 * time.Millisecond,
		proxies:   map[string]*httputil.ReverseProxy{},
	}
}

func (p *leaderProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if p.isLeader() {
		w.Header().Set(HeaderServedBy, p.self)
		p.local.ServeHTTP(w, r)
		return
	}
	if r.Header.Get(headerProxied) != "" {
		// Another standby believes this instance leads. Its view is stale.
		w.Header().Set("Retry-After", "2")
		http.Error(w, "standby received a forwarded request; leadership is changing", http.StatusServiceUnavailable)
		return
	}

	// A request that fails to connect never reached the leader, so it goes
	// to the next leader instead. The body must still be unread for that.
	attempt := &forwardAttempt{}
	r = r.WithContext(context.WithValue(r.Context(), forwardAttemptKey{}, attempt))
	if r.Body != nil && r.Body != http.NoBody {
		attempt.body = &trackedBody{ReadCloser: r.Body}
		r.Body = attempt.body
	}

	deadline := time.Now().Add(p.waitFor)
	for {
		leader, ok := p.awaitLeader(r.Context(), deadline)
		if p.isLeader() {
			// Elected while waiting.
			w.Header().Set(HeaderServedBy, p.self)
			p.local.ServeHTTP(w, r)
			return
		}
		if !ok {
			w.Header().Set("Retry-After", "5")
			http.Error(w, "no suppline leader is available", http.StatusServiceUnavailable)
			return
		}

		// Proxied responses can take as long as the leader's handler: scan
		// requests wait up to 10 minutes. The leader enforces its own deadlines.
		_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})
		attempt.connectFailed = false
		p.proxyFor(leader.Address).ServeHTTP(w, r)
		if !attempt.connectFailed {
			return
		}
		if time.Now().After(deadline) {
			w.Header().Set("Retry-After", "5")
			http.Error(w, "the suppline leader is unreachable and no other leader took over", http.StatusServiceUnavailable)
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-time.After(p.pollEvery):
		}
	}
}

type forwardAttemptKey struct{}

// forwardAttempt carries what the proxy's error handler learned back to
// ServeHTTP.
type forwardAttempt struct {
	body          *trackedBody
	connectFailed bool
}

// retryable reports whether err left the request unsent: the connection
// was never made and no body byte was read.
func (a *forwardAttempt) retryable(err error) bool {
	var opErr *net.OpError
	if !errors.As(err, &opErr) || opErr.Op != "dial" {
		return false
	}
	return a.body == nil || !a.body.read.Load()
}

// trackedBody records whether the request body was read and ignores Close,
// which the transport calls even when it could not connect. The server
// closes the real body when the handler returns.
type trackedBody struct {
	io.ReadCloser
	read atomic.Bool
}

func (b *trackedBody) Read(p []byte) (int, error) {
	b.read.Store(true)
	return b.ReadCloser.Read(p)
}

func (b *trackedBody) Close() error { return nil }

// awaitLeader returns the current leader, polling until deadline while
// there is none, so a request that arrives during a failover waits instead
// of failing.
func (p *leaderProxy) awaitLeader(ctx context.Context, deadline time.Time) (statestore.Leader, bool) {
	for {
		if leader, ok := p.lookup(ctx); ok {
			return leader, true
		}
		if p.isLeader() || time.Now().After(deadline) {
			return statestore.Leader{}, false
		}
		select {
		case <-ctx.Done():
			return statestore.Leader{}, false
		case <-time.After(p.pollEvery):
		}
	}
}

func (p *leaderProxy) lookup(ctx context.Context) (statestore.Leader, bool) {
	p.mu.Lock()
	if p.found && time.Since(p.checkedAt) < p.cacheFor {
		leader := p.leader
		p.mu.Unlock()
		return leader, true
	}
	p.mu.Unlock()

	leader, ok, err := p.dir.CurrentLeader(ctx)
	if err != nil {
		p.logger.Warn("cannot look up the suppline leader", "error", err)
		ok = false
	}
	p.mu.Lock()
	p.leader, p.found, p.checkedAt = leader, ok, time.Now()
	p.mu.Unlock()
	return leader, ok
}

// forget drops the cached leader so the next request looks it up again.
func (p *leaderProxy) forget() {
	p.mu.Lock()
	p.found = false
	p.mu.Unlock()
}

func (p *leaderProxy) proxyFor(address string) *httputil.ReverseProxy {
	p.mu.Lock()
	defer p.mu.Unlock()
	if proxy, ok := p.proxies[address]; ok {
		return proxy
	}
	target, err := url.Parse(address)
	if err != nil {
		// CurrentLeader returns what a leader advertised after validating it.
		target = &url.URL{Scheme: "http", Host: address}
	}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			// Keep the original path: the leader serves the same basePath.
			pr.Out.URL.Path = pr.In.URL.Path
			pr.Out.URL.RawPath = pr.In.URL.RawPath
			pr.Out.Host = pr.In.Host
			pr.SetXForwarded()
			pr.Out.Header.Set(headerProxied, p.self)
		},
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			p.forget()
			if attempt, ok := r.Context().Value(forwardAttemptKey{}).(*forwardAttempt); ok && attempt.retryable(err) {
				// ServeHTTP tries again on whoever leads by then.
				attempt.connectFailed = true
				p.logger.Warn("cannot connect to the suppline leader; waiting for the next one", "leader", address, "path", r.URL.Path, "error", err)
				return
			}
			p.logger.Warn("forwarding to the suppline leader failed", "leader", address, "path", r.URL.Path, "error", err)
			w.Header().Set("Retry-After", "2")
			http.Error(w, "the suppline leader is unreachable", http.StatusBadGateway)
		},
	}
	p.proxies[address] = proxy
	return proxy
}

// SetLeaderProxy makes a standby forward every API and UI request to the
// leader. isLeader reports whether this instance leads; self names it in
// X-Suppline-Served-By.
func (s *APIServer) SetLeaderProxy(isLeader func() bool, self string, dir LeaderDirectory) {
	if s == nil || s.server == nil {
		return
	}
	s.server.Handler = newLeaderProxy(s.server.Handler, isLeader, self, dir, s.logger.With("module", "leader-proxy"))
}
