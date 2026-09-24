// Package api is the HTTPS API that services and operators talk to.
//
// Every request goes through the same pipeline, in this order:
//
//	identity (mTLS certificate) → rate limit → seal check → revocation →
//	policy → audit(request) → handler → audit(response, secret values HMAC'd) → reply
//
// If either audit write fails the caller gets 500 and no data (fail closed).
// Policy is checked before existence, so callers without access get the same
// 403 whether or not a path exists.
package api

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/hamad-tariq/SecretsManager/internal/audit"
	"github.com/hamad-tariq/SecretsManager/internal/barrier"
	"github.com/hamad-tariq/SecretsManager/internal/kv"
	"github.com/hamad-tariq/SecretsManager/internal/lease"
	"github.com/hamad-tariq/SecretsManager/internal/metrics"
	"github.com/hamad-tariq/SecretsManager/internal/pki"
	"github.com/hamad-tariq/SecretsManager/internal/policy"
	"github.com/hamad-tariq/SecretsManager/internal/rotation"
	"github.com/hamad-tariq/SecretsManager/internal/secret"
)

// Cluster is what the API needs from the Raft node (cluster.Node).
type Cluster interface {
	IsLeader() bool
	Leader() string
	Voters() ([]string, error)
	Members() map[string]string
	Remove(id string) error
	StepDown() error
	Dump() (map[string][]byte, error)
	Restore(map[string][]byte) error
}

type Config struct {
	Seal    *barrier.Seal
	Audit   *audit.Logger
	Cluster Cluster           // nil in single-process tests: always leader, no cluster routes
	Metrics *metrics.Registry // default: a new one
	Roots   *x509.CertPool    // root CA; uploaded intermediates must chain to it
	// MaxLineage bounds how long a service certificate can keep renewing
	// itself before its identity must log in again (default 30 days).
	MaxLineage time.Duration
	// Per-identity (or per-IP for unauthenticated calls) request rate.
	Rate  rate.Limit // default 50/s
	Burst int        // default 100
	Log   *slog.Logger
}

type Server struct {
	maxLineage time.Duration
	cluster    Cluster
	metrics    *metrics.Registry
	seal       *barrier.Seal
	kv         *kv.Store
	leases     *lease.Manager
	roots      *x509.CertPool
	audit      *audit.Logger
	lim        *limiters
	log        *slog.Logger
}

func New(cfg Config) *Server {
	if cfg.Rate == 0 {
		cfg.Rate = 50
	}
	if cfg.Burst == 0 {
		cfg.Burst = 100
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.Metrics == nil {
		cfg.Metrics = metrics.New()
	}
	if cfg.MaxLineage <= 0 {
		cfg.MaxLineage = 30 * 24 * time.Hour
	}
	s := &Server{maxLineage: cfg.MaxLineage, cluster: cfg.Cluster, metrics: cfg.Metrics, seal: cfg.Seal, kv: kv.New(cfg.Seal.Barrier), roots: cfg.Roots, audit: cfg.Audit,
		leases: lease.New(lease.Config{Backend: cfg.Seal.Barrier, Log: cfg.Log}),
		lim:    &limiters{m: map[string]*rate.Limiter{}, r: cfg.Rate, b: cfg.Burst}, log: cfg.Log}
	s.metrics.Gauge("sm_sealed", "1 if this node is sealed.", func() []metrics.Sample {
		return metrics.One(metrics.Bool(s.seal.Sealed()))
	})
	s.metrics.Gauge("sm_leader", "1 if this node is the Raft leader.", func() []metrics.Sample {
		return metrics.One(metrics.Bool(s.isLeader()))
	})
	s.metrics.Gauge("sm_cert_expiry_seconds", "Seconds until the cluster's intermediate CA expires (service certificates stop being issued).", func() []metrics.Sample {
		if s.seal.Sealed() {
			return nil
		}
		ca, err := s.issuer()
		if err != nil {
			return nil
		}
		return []metrics.Sample{{Labels: []string{"cert", "intermediate"}, Value: time.Until(ca.Cert.NotAfter).Seconds()}}
	})
	return s
}

func (s *Server) isLeader() bool { return s.cluster == nil || s.cluster.IsLeader() }

// TLSConfig is the server side: TLS 1.3, client certificates verified when
// presented. Routes that need an identity reject requests without one; only
// health and unseal work without a certificate.
func TLSConfig(cert tls.Certificate, roots *x509.CertPool) *tls.Config {
	c := pki.ServerTLS(cert, roots)
	c.ClientAuth = tls.VerifyClientCertIfGiven
	return c
}

type authMode int

const (
	authNone   authMode = iota // no certificate needed
	authCert                   // any valid certificate, no policy (handler checks the kind)
	authAdmin                  // any admin certificate, no policy (init only)
	authPolicy                 // certificate + policy check
)

// call is the per-request context the pipeline builds up.
type call struct {
	reqID, id, serial, ip string
	kind                  pki.Kind
	login                 time.Time // the certificate's lineage (see revoke.go)
	start                 time.Time
}

// text is a response body sent as-is (text/plain), e.g. metrics.
type text []byte

// response is what handlers return; the pipeline audits it before sending.
type response struct {
	status    int
	body      any
	sensitive map[string]secret.Secret
}

type route struct {
	op       string // audit operation name
	auth     authMode
	sealedOK bool
	noAudit  bool // health checks only
	// perm returns the policy path and capability; an error means a bad request.
	perm   func(r *http.Request) (string, policy.Capability, error)
	handle func(r *http.Request, c *call) response
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	for pattern, rt := range s.routes() {
		mux.HandleFunc(pattern, s.wrap(rt))
	}
	return mux
}

func (s *Server) wrap(rt route) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := &call{reqID: newID(), ip: clientIP(r), start: time.Now()}
		if id, err := pki.PeerIdentity(r.TLS); err == nil {
			c.id, c.kind = id.String(), id.Kind
			c.serial = r.TLS.VerifiedChains[0][0].SerialNumber.Text(16)
			c.login = pki.LoginTime(r.TLS.VerifiedChains[0][0])
		}

		path := r.URL.Path
		if rt.auth != authNone && c.id == "" {
			s.finish(w, c, rt, path, errResp(http.StatusUnauthorized, "client certificate required"))
			return
		}
		key := c.id
		if key == "" {
			key = "ip:" + c.ip
		}
		if !s.lim.allow(key) {
			s.finish(w, c, rt, path, errResp(http.StatusTooManyRequests, "rate limit exceeded"))
			return
		}
		if !rt.sealedOK && s.seal.Sealed() {
			s.finish(w, c, rt, path, errResp(http.StatusServiceUnavailable, "sealed"))
			return
		}
		// Revoked certificates and identities stop here, before any policy
		// (and before root-admin rights). While sealed there's nothing to
		// check against, and the only certificate routes then are init and
		// restore, which only work on an empty cluster.
		if rt.auth != authNone && !s.seal.Sealed() {
			revoked, err := s.isRevoked(c.serial, c.id, c.login)
			if err != nil {
				s.log.Error("reading revocations", "err", err)
				s.finish(w, c, rt, path, errResp(http.StatusServiceUnavailable, "revocation list unavailable"))
				return
			}
			if revoked {
				s.finish(w, c, rt, path, errResp(http.StatusUnauthorized, "certificate revoked"))
				return
			}
		}
		if rt.perm != nil {
			p, capability, err := rt.perm(r)
			if err != nil {
				s.finish(w, c, rt, path, errResp(http.StatusBadRequest, err.Error()))
				return
			}
			path = p
			if rt.auth == authPolicy && !s.allowed(c.id, p, capability) {
				s.finish(w, c, rt, path, errResp(http.StatusForbidden, "permission denied"))
				return
			}
		}
		if rt.auth == authAdmin && c.kind != pki.Admin {
			s.finish(w, c, rt, path, errResp(http.StatusForbidden, "an admin certificate is required"))
			return
		}

		if !rt.noAudit {
			if err := s.audit.Log(audit.Entry{RequestID: c.reqID, Identity: c.id, Operation: rt.op, Path: path,
				Result: "request", SourceIP: c.ip, CertSerial: c.serial}); err != nil {
				s.log.Error("audit write failed", "err", err)
				writeJSON(w, http.StatusInternalServerError, errBody("audit log unavailable"))
				return
			}
		}
		s.finish(w, c, rt, path, rt.handle(r, c))
	}
}

// finish audits the outcome and only then sends it.
func (s *Server) finish(w http.ResponseWriter, c *call, rt route, path string, resp response) {
	defer func() {
		s.metrics.Add("sm_requests_total", "API requests by operation and status.", 1, "op", rt.op, "code", strconv.Itoa(resp.status))
		s.metrics.Add("sm_request_duration_seconds_sum", "Total time spent serving API requests, by operation.", time.Since(c.start).Seconds(), "op", rt.op)
		s.metrics.Add("sm_request_duration_seconds_count", "API requests timed, by operation.", 1, "op", rt.op)
	}()
	if !rt.noAudit {
		err := s.audit.Log(audit.Entry{RequestID: c.reqID, Identity: c.id, Operation: rt.op, Path: path,
			Result: result(resp.status), SourceIP: c.ip, CertSerial: c.serial, Sensitive: resp.sensitive})
		if err != nil {
			s.log.Error("audit write failed", "err", err)
			resp = errResp(http.StatusInternalServerError, "audit log unavailable")
			writeJSON(w, resp.status, resp.body)
			return
		}
	}
	if t, ok := resp.body.(text); ok {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		w.WriteHeader(resp.status)
		_, _ = w.Write(t)
		return
	}
	writeJSON(w, resp.status, resp.body)
}

func result(status int) string {
	switch {
	case status < 300:
		return "ok"
	case status == http.StatusUnauthorized, status == http.StatusForbidden, status == http.StatusTooManyRequests:
		return "denied:" + strconv.Itoa(status)
	default:
		return "error:" + strconv.Itoa(status)
	}
}

// allowed evaluates the caller's policies. The root admin named at init has
// unrestricted access.
func (s *Server) allowed(identity, path string, c policy.Capability) bool {
	root, err := s.rootAdmin()
	if err != nil {
		s.log.Error("loading root admin", "err", err)
		return false
	}
	if identity != "" && identity == root {
		return true
	}
	pols, err := s.policiesFor(identity)
	if err != nil {
		s.log.Error("loading policies", "identity", identity, "err", err)
		return false
	}
	return policy.Allowed(pols, path, c)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if body != nil {
		_ = json.NewEncoder(w).Encode(body)
	}
}

type errorBody struct {
	Error string `json:"error"`
}

func errBody(msg string) errorBody { return errorBody{Error: msg} }

func errResp(status int, msg string) response {
	return response{status: status, body: errBody(msg)}
}

func ok(body any) response { return response{status: http.StatusOK, body: body} }

// fail maps known errors to status codes; anything else is logged and hidden.
func (s *Server) fail(err error) response {
	switch {
	case errors.Is(err, kv.ErrNotFound), errors.Is(err, rotation.ErrNotFound), errors.Is(err, lease.ErrNotFound):
		return errResp(http.StatusNotFound, "not found")
	case errors.Is(err, kv.ErrCASMismatch), errors.Is(err, kv.ErrNotDeleted):
		return errResp(http.StatusConflict, err.Error())
	case errors.Is(err, kv.ErrBusy), errors.Is(err, rotation.ErrBusy):
		return errResp(http.StatusServiceUnavailable, err.Error())
	case errors.Is(err, lease.ErrNotOwner):
		return errResp(http.StatusForbidden, "permission denied")
	case errors.Is(err, lease.ErrExpired):
		return errResp(http.StatusConflict, err.Error())
	case errors.Is(err, lease.ErrDatabase):
		return errResp(http.StatusBadGateway, err.Error()) // details go to the server log only
	case errors.Is(err, barrier.ErrSealed):
		return errResp(http.StatusServiceUnavailable, "sealed")
	}
	s.log.Error("request failed", "err", err)
	return errResp(http.StatusInternalServerError, "internal error")
}

const maxBody = 1 << 20

func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return errors.New("invalid JSON body")
	}
	return nil
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// limiters is a token bucket per identity (or IP).
//
// ponytail: the map is reset wholesale past 10k keys to bound memory under an
// IP flood; that briefly forgives everyone. Use an LRU if it ever matters.
type limiters struct {
	mu sync.Mutex
	m  map[string]*rate.Limiter
	r  rate.Limit
	b  int
}

func (l *limiters) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	lim, ok := l.m[key]
	if !ok {
		if len(l.m) >= 10000 {
			l.m = map[string]*rate.Limiter{}
		}
		lim = rate.NewLimiter(l.r, l.b)
		l.m[key] = lim
	}
	return lim.Allow()
}
