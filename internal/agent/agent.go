// Package agent gets a service certificate and delivers secrets as files.
//
// It runs next to an application (Kubernetes init container or sidecar, or
// a systemd service on a VM):
//
//  1. Login: a fresh key + CSR, exchanged for a service certificate using a
//     single-use enrollment token or a Kubernetes service-account token.
//  2. Sync: fetch each configured secret and write it to OutDir, atomically,
//     only when its version changed.
//  3. Renew: at 2/3 of the certificate's lifetime, get a fresh one with the
//     current certificate (falling back to Kubernetes login if it expired).
//  4. Database credentials (DBCreds): get a per-pod database user for each
//     configured role and write it as JSON; renew its lease at 2/3 of its
//     lifetime, and get new credentials once the lease can't be extended
//     (max TTL). The old user keeps working until its own expiry, so the
//     application has time to reconnect with the new file.
//
// OutDir also receives tls.crt, tls.key and ca.crt so the application (or
// the Python SDK's Client.from_agent_dir) can call the API with the same
// identity. Put OutDir on tmpfs (Kubernetes emptyDir medium: Memory).
package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/hamad-tariq/SecretsManager/internal/pki"
)

type Config struct {
	Addrs     []string          // node API addresses
	CAPEM     []byte            // root CA
	OutDir    string            // where files are written
	Auth      string            // "token" or "kubernetes"
	TokenFile string            // enrollment token (auth=token)
	JWTFile   string            // projected service-account token (auth=kubernetes)
	Secrets   map[string]string // kv path → file name in OutDir
	DBCreds   map[string]string // database role → file name in OutDir
	Refresh   time.Duration     // how often to re-fetch secrets; default 5m
	Log       *slog.Logger
}

type Agent struct {
	cfg    Config
	client *http.Client
	now    func() time.Time

	mu      sync.Mutex
	key     *ecdsa.PrivateKey
	cert    *x509.Certificate
	chain   [][]byte // DER: leaf, intermediate
	version map[string]int
	leases  map[string]*dbLease // by role
}

type dbLease struct {
	ID         string    `json:"lease_id"`
	Expires    time.Time `json:"expires"`
	MaxExpires time.Time `json:"max_expires"`
	renewed    time.Time // when it was issued or last renewed
}

func New(cfg Config) (*Agent, error) {
	if len(cfg.Addrs) == 0 || cfg.OutDir == "" {
		return nil, errors.New("agent: addresses and an output directory are required")
	}
	if cfg.Auth != "token" && cfg.Auth != "kubernetes" {
		return nil, fmt.Errorf("agent: auth must be token or kubernetes, not %q", cfg.Auth)
	}
	files := map[string]bool{}
	for _, m := range []map[string]string{cfg.Secrets, cfg.DBCreds} {
		for _, f := range m {
			if files[f] {
				return nil, fmt.Errorf("agent: file %q used twice", f)
			}
			files[f] = true
		}
	}
	for f := range files {
		if f == "" || f != filepath.Base(f) || strings.HasPrefix(f, ".") || isReserved(f) {
			return nil, fmt.Errorf("agent: invalid secret file name %q", f)
		}
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(cfg.CAPEM) {
		return nil, errors.New("agent: CA PEM has no certificates")
	}
	if cfg.Refresh <= 0 {
		cfg.Refresh = 5 * time.Minute
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	a := &Agent{cfg: cfg, now: time.Now, version: map[string]int{}, leases: map[string]*dbLease{}}
	a.client = &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    roots,
		// Always present the current certificate (none before login).
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			a.mu.Lock()
			defer a.mu.Unlock()
			if a.cert == nil {
				return &tls.Certificate{}, nil
			}
			return &tls.Certificate{Certificate: a.chain, PrivateKey: a.key, Leaf: a.cert}, nil
		},
	}}}
	return a, os.MkdirAll(cfg.OutDir, 0o700)
}

func isReserved(f string) bool { return f == "tls.crt" || f == "tls.key" || f == "ca.crt" }

// Login obtains a certificate with the configured method.
func (a *Agent) Login(ctx context.Context) error {
	body := map[string]string{}
	path := "/v1/auth/enroll"
	switch a.cfg.Auth {
	case "token":
		tok, err := os.ReadFile(a.cfg.TokenFile)
		if err != nil {
			return fmt.Errorf("agent: reading enrollment token: %w", err)
		}
		body["token"] = strings.TrimSpace(string(tok))
	case "kubernetes":
		jwt, err := os.ReadFile(a.cfg.JWTFile) // re-read every time: kubelet rotates it
		if err != nil {
			return fmt.Errorf("agent: reading service-account token: %w", err)
		}
		body["jwt"] = strings.TrimSpace(string(jwt))
		path = "/v1/auth/kubernetes"
	}
	return a.obtain(ctx, path, body)
}

// Renew replaces the certificate if 2/3 of its lifetime has passed. If it has
// already expired and auth is kubernetes, it logs in again.
func (a *Agent) Renew(ctx context.Context) error {
	a.mu.Lock()
	cert := a.cert
	a.mu.Unlock()
	if cert == nil {
		return a.Login(ctx)
	}
	now := a.now()
	if now.Before(renewAt(cert)) {
		return nil
	}
	if now.After(cert.NotAfter) {
		if a.cfg.Auth == "kubernetes" {
			return a.Login(ctx)
		}
		return errors.New("agent: certificate expired and enrollment tokens are single-use; issue a new token")
	}
	err := a.obtain(ctx, "/v1/auth/renew", map[string]string{})
	if err != nil && a.cfg.Auth == "kubernetes" {
		// Renewal refused (e.g. the last full login is too old): prove the
		// pod's identity again with its service-account token.
		a.cfg.Log.Warn("renewal refused; logging in again", "err", err)
		return a.Login(ctx)
	}
	return err
}

func renewAt(c *x509.Certificate) time.Time {
	return c.NotBefore.Add(c.NotAfter.Sub(c.NotBefore) * 2 / 3)
}

// obtain sends a fresh CSR to path and installs the returned certificate.
func (a *Agent) obtain(ctx context.Context, path string, body map[string]string) error {
	key, err := pki.NewKey()
	if err != nil {
		return err
	}
	csr, err := pki.NewCSR(key)
	if err != nil {
		return err
	}
	body["csr"] = base64.StdEncoding.EncodeToString(csr)
	var out struct {
		Certificate string `json:"certificate"`
	}
	if err := a.call(ctx, "POST", path, body, &out); err != nil {
		return fmt.Errorf("agent: %s: %w", path, err)
	}
	certs, err := pki.ParseCerts([]byte(out.Certificate))
	if err != nil {
		return err
	}
	keyPEM, err := pki.EncodeKey(key)
	if err != nil {
		return err
	}
	var chain [][]byte
	for _, c := range certs {
		chain = append(chain, c.Raw)
	}
	// Key before certificate: the SDK reloads when tls.crt changes, and by
	// then the matching key is already in place.
	if err := a.write("tls.key", keyPEM); err != nil {
		return err
	}
	if err := a.write("tls.crt", []byte(out.Certificate)); err != nil {
		return err
	}
	if err := a.write("ca.crt", a.cfg.CAPEM); err != nil {
		return err
	}
	a.mu.Lock()
	a.key, a.cert, a.chain = key, certs[0], chain
	a.mu.Unlock()
	// Pooled connections were handshaken with the old (or no) certificate;
	// drop them so the next request presents the new one.
	a.client.CloseIdleConnections()
	a.cfg.Log.Info("certificate installed", "path", path, "not_after", certs[0].NotAfter)
	return nil
}

// Sync fetches every configured secret and rewrites files whose version changed.
func (a *Agent) Sync(ctx context.Context) error {
	var errs []error
	for path, file := range a.cfg.Secrets {
		var out struct {
			Value   string `json:"value"`
			Version int    `json:"version"`
		}
		if err := a.call(ctx, "GET", "/v1/kv/"+path, nil, &out); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", path, err))
			continue
		}
		a.mu.Lock()
		unchanged := a.version[path] == out.Version
		a.mu.Unlock()
		if unchanged {
			continue
		}
		if err := a.write(file, []byte(out.Value)); err != nil {
			errs = append(errs, err)
			continue
		}
		a.mu.Lock()
		a.version[path] = out.Version
		a.mu.Unlock()
		a.cfg.Log.Info("secret updated", "path", path, "file", file, "version", out.Version)
	}
	return errors.Join(errs...)
}

// DBCreds gets, renews or replaces each configured database credential as due.
func (a *Agent) DBCreds(ctx context.Context) error {
	var errs []error
	for role, file := range a.cfg.DBCreds {
		a.mu.Lock()
		l := a.leases[role]
		a.mu.Unlock()
		now := a.now()
		switch {
		case l == nil || !now.Before(l.Expires):
		case now.Before(l.renewed.Add(l.Expires.Sub(l.renewed) * 2 / 3)):
			continue // not due
		case l.Expires.Before(l.MaxExpires):
			var out dbLease
			err := a.call(ctx, "POST", "/v1/leases/renew", map[string]string{"lease_id": l.ID}, &out)
			if err == nil {
				a.mu.Lock()
				l.Expires, l.renewed = out.Expires, now
				a.mu.Unlock()
				continue
			}
			a.cfg.Log.Warn("lease renewal failed; requesting new credentials", "role", role, "err", err)
		}
		// New credentials: none yet, expired, at max TTL, or renewal refused.
		var out struct {
			dbLease
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := a.call(ctx, "POST", "/v1/db/creds/"+role, nil, &out); err != nil {
			errs = append(errs, fmt.Errorf("db %s: %w", role, err))
			continue
		}
		data, _ := json.Marshal(map[string]any{"username": out.Username, "password": out.Password,
			"lease_id": out.ID, "expires": out.Expires, "max_expires": out.MaxExpires})
		if err := a.write(file, data); err != nil {
			errs = append(errs, err)
			continue
		}
		out.renewed = now
		a.mu.Lock()
		a.leases[role] = &out.dbLease
		a.mu.Unlock()
		a.cfg.Log.Info("database credentials issued", "role", role, "file", file, "lease", out.ID, "expires", out.Expires)
	}
	return errors.Join(errs...)
}

// Run logs in, syncs, and then keeps secrets, database credentials and the
// certificate fresh until ctx ends. Transient errors are logged and retried
// on the next tick.
//
// ponytail: checks at most once a minute, so leases need TTLs of a few
// minutes or more (the default is 1 h).
func (a *Agent) Run(ctx context.Context) error {
	if err := a.Login(ctx); err != nil {
		return err
	}
	if err := a.Sync(ctx); err != nil {
		a.cfg.Log.Error("sync failed", "err", err)
	}
	if err := a.DBCreds(ctx); err != nil {
		a.cfg.Log.Error("database credentials failed", "err", err)
	}
	t := time.NewTicker(min(a.cfg.Refresh, time.Minute))
	defer t.Stop()
	lastSync := a.now()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
		if err := a.Renew(ctx); err != nil {
			a.cfg.Log.Error("renewal failed", "err", err)
		}
		if err := a.DBCreds(ctx); err != nil {
			a.cfg.Log.Error("database credentials failed", "err", err)
		}
		if a.now().Sub(lastSync) >= a.cfg.Refresh {
			if err := a.Sync(ctx); err != nil {
				a.cfg.Log.Error("sync failed", "err", err)
			}
			lastSync = a.now()
		}
	}
}

// write replaces OutDir/name atomically (temp file + rename), mode 0600.
func (a *Agent) write(name string, data []byte) error {
	f, err := os.CreateTemp(a.cfg.OutDir, "."+name+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, werr := f.Write(data)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Chmod(tmp, 0o600)
	}
	if werr == nil {
		werr = os.Rename(tmp, filepath.Join(a.cfg.OutDir, name))
	}
	if werr != nil {
		_ = os.Remove(tmp)
	}
	return werr
}

// call tries each address until one answers.
func (a *Agent) call(ctx context.Context, method, path string, body, out any) error {
	var last error
	for _, addr := range a.cfg.Addrs {
		var rd io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		}
		req, err := http.NewRequestWithContext(ctx, method, "https://"+addr+path, rd)
		if err != nil {
			return err
		}
		resp, err := a.client.Do(req)
		if err != nil {
			last = err
			continue // node down: try the next
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		_ = resp.Body.Close()
		if err != nil {
			last = err
			continue
		}
		if resp.StatusCode >= 300 {
			var e struct {
				Error string `json:"error"`
			}
			_ = json.Unmarshal(data, &e)
			last = fmt.Errorf("%s: %s", resp.Status, e.Error)
			if resp.StatusCode == http.StatusServiceUnavailable {
				continue // sealed or busy: another node may serve it
			}
			return last
		}
		return json.Unmarshal(data, out)
	}
	return last
}
