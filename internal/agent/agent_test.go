package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hamad-tariq/SecretsManager/internal/api"
	"github.com/hamad-tariq/SecretsManager/internal/audit"
	"github.com/hamad-tariq/SecretsManager/internal/barrier"
	"github.com/hamad-tariq/SecretsManager/internal/lease"
	"github.com/hamad-tariq/SecretsManager/internal/pki"
	"github.com/hamad-tariq/SecretsManager/internal/storage"
)

type server struct {
	t     *testing.T
	addr  string
	caPEM []byte
	admin *http.Client
}

// newServer runs an initialised, unsealed API with an intermediate CA, a
// secret the orders-api service may read, and Kubernetes login configured.
func newServer(t *testing.T, opts ...func(*api.Config)) *server {
	root, _ := pki.NewRoot("root", time.Hour)
	roots := x509.NewCertPool()
	roots.AddCert(root.Cert)

	seal := barrier.NewSeal(storage.NewInmem())
	t.Cleanup(seal.Seal)
	adminID := pki.Identity{Kind: pki.Admin, Name: "alice"}
	shares, err := seal.Init(3, 2, nil, adminID.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range shares[:2] {
		_, _ = seal.Unseal(s)
	}
	cfg := api.Config{Seal: seal, Audit: audit.New(io.Discard, []byte("k"), audit.Head{}), Roots: roots,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	for _, o := range opts {
		o(&cfg)
	}
	srv := api.New(cfg)
	hs := httptest.NewUnstartedServer(srv.Handler())
	nk, _ := pki.NewKey()
	nc, _ := root.Issue(pki.Identity{Kind: pki.Node, Name: "node-1"}, nk.Public(), time.Hour, "127.0.0.1")
	hs.TLS = api.TLSConfig(pki.TLSCertificate(nc, nk), roots)
	hs.StartTLS()
	t.Cleanup(hs.Close)

	ak, _ := pki.NewKey()
	ac, _ := root.Issue(adminID, ak.Public(), time.Hour)
	s := &server{t: t, addr: strings.TrimPrefix(hs.URL, "https://"), caPEM: pki.EncodeCert(root.Cert),
		admin: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{pki.TLSCertificate(ac, ak)}}}}}

	inter, _ := root.NewIntermediate("inter", time.Hour)
	ik, _ := pki.EncodeKey(inter.Key.(*ecdsa.PrivateKey))
	s.do("PUT", "/v1/sys/pki/intermediate", map[string]string{"cert_pem": string(pki.EncodeCert(inter.Cert)), "key_pem": string(ik)})
	s.do("PUT", "/v1/kv/prod/orders/db", map[string]string{"value": "pw-v1"})
	s.do("PUT", "/v1/sys/policies/orders", json.RawMessage(`{"name":"orders","rules":[{"path":"kv/prod/orders/*","capabilities":["read"]}]}`))
	s.do("PUT", "/v1/sys/bindings/svc/orders-api", map[string]any{"policies": []string{"orders"}})
	return s
}

func (s *server) do(method, path string, body any) map[string]any {
	s.t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(method, "https://"+s.addr+path, bytes.NewReader(b))
	resp, err := s.admin.Do(req)
	if err != nil {
		s.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode != 200 {
		s.t.Fatalf("%s %s: %d %v", method, path, resp.StatusCode, out)
	}
	return out
}

func (s *server) tokenFile(dir string) string {
	tok := s.do("POST", "/v1/sys/enroll-tokens", map[string]string{"service": "orders-api"})["token"].(string)
	p := filepath.Join(dir, "token")
	_ = os.WriteFile(p, []byte(tok+"\n"), 0o600)
	return p
}

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestTokenLoginSyncRenew(t *testing.T) {
	s := newServer(t)
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	a, err := New(Config{Addrs: []string{"127.0.0.1:1", s.addr}, CAPEM: s.caPEM, OutDir: out, Auth: "token",
		TokenFile: s.tokenFile(dir), Secrets: map[string]string{"prod/orders/db": "db-password"}, Log: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := a.Sync(ctx); err == nil {
		t.Fatal("sync before login should fail (no certificate)")
	}
	if err := a.Login(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.Login(ctx); err == nil {
		t.Fatal("enrollment token reused")
	}
	if err := a.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if got := read(t, filepath.Join(out, "db-password")); got != "pw-v1" {
		t.Fatalf("secret file %q", got)
	}
	certs, err := pki.ParseCerts([]byte(read(t, filepath.Join(out, "tls.crt"))))
	if err != nil || len(certs) != 2 {
		t.Fatalf("tls.crt: %v", err)
	}
	if id, _ := pki.IdentityFromCert(certs[0]); id.String() != "spiffe://sm/svc/orders-api" {
		t.Fatalf("identity %v", id)
	}
	if _, err := tls.LoadX509KeyPair(filepath.Join(out, "tls.crt"), filepath.Join(out, "tls.key")); err != nil {
		t.Fatalf("cert/key pair: %v", err)
	}
	if read(t, filepath.Join(out, "ca.crt")) != string(s.caPEM) {
		t.Fatal("ca.crt")
	}

	// A new version is written; an unchanged one isn't rewritten.
	s.do("PUT", "/v1/kv/prod/orders/db", map[string]string{"value": "pw-v2"})
	_ = a.Sync(ctx)
	if got := read(t, filepath.Join(out, "db-password")); got != "pw-v2" {
		t.Fatalf("after update %q", got)
	}
	st1, _ := os.Stat(filepath.Join(out, "db-password"))
	time.Sleep(20 * time.Millisecond)
	_ = a.Sync(ctx)
	st2, _ := os.Stat(filepath.Join(out, "db-password"))
	if !st1.ModTime().Equal(st2.ModTime()) {
		t.Fatal("unchanged secret rewritten")
	}

	// Renewal: nothing before 2/3 of the lifetime, a new certificate after.
	first := a.cert
	if err := a.Renew(ctx); err != nil || a.cert != first {
		t.Fatalf("renewed too early: %v", err)
	}
	a.now = func() time.Time { return renewAt(first).Add(time.Second) }
	if err := a.Renew(ctx); err != nil {
		t.Fatal(err)
	}
	if a.cert.SerialNumber.Cmp(first.SerialNumber) == 0 {
		t.Fatal("certificate not renewed")
	}
	if err := a.Sync(ctx); err != nil {
		t.Fatalf("sync with renewed certificate: %v", err)
	}
	// Expired with a single-use token: the operator must issue a new token.
	a.now = func() time.Time { return a.cert.NotAfter.Add(time.Minute) }
	if err := a.Renew(ctx); err == nil || !strings.Contains(err.Error(), "new token") {
		t.Fatalf("expired token-auth renewal: %v", err)
	}

	runPythonSDK(t, "LiveTest", "SM_TEST_ADDR="+s.addr, "SM_TEST_AGENT_DIR="+out,
		"SM_TEST_PATH=prod/orders/db", "SM_TEST_VALUE=pw-v2")
}

// runPythonSDK runs one of the SDK's live test classes with the agent's certificate.
func runPythonSDK(t *testing.T, class string, env ...string) {
	py, err := exec.LookPath("python3")
	if err != nil {
		if py, err = exec.LookPath("python"); err != nil {
			t.Log("python not found; skipping SDK live test")
			return
		}
	}
	cmd := exec.Command(py, "-m", "unittest", "-v", "tests.test_smclient."+class)
	cmd.Dir = filepath.Join("..", "..", "sdk", "python")
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if err != nil || !bytes.Contains(out, []byte("OK")) || bytes.Contains(out, []byte("skipped")) {
		t.Fatalf("python SDK live test failed: %v\n%s", err, out)
	}
}

func fakeK8s(t *testing.T) (string, string) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Spec struct{ Token string } `json:"spec"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		st := map[string]any{"authenticated": false}
		if req.Spec.Token == "good" {
			st = map[string]any{"authenticated": true, "audiences": []string{"sm"},
				"user": map[string]string{"username": "system:serviceaccount:shop:orders"}}
		}
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": st})
	}))
	t.Cleanup(srv.Close)
	return srv.URL, string(pki.EncodeCert(srv.Certificate()))
}

func TestKubernetesSidecar(t *testing.T) {
	s := newServer(t)
	url, ca := fakeK8s(t)
	s.do("PUT", "/v1/sys/auth/kubernetes", map[string]any{"host": url, "ca_pem": ca, "reviewer_token": "r",
		"audience": "sm", "roles": map[string]string{"shop/orders": "orders-api"}})
	dir := t.TempDir()
	jwt := filepath.Join(dir, "jwt")
	_ = os.WriteFile(jwt, []byte("bad"), 0o600)
	out := filepath.Join(dir, "out")
	a, err := New(Config{Addrs: []string{s.addr}, CAPEM: s.caPEM, OutDir: out, Auth: "kubernetes", JWTFile: jwt,
		Secrets: map[string]string{"prod/orders/db": "db"}, Refresh: 50 * time.Millisecond, Log: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := a.Run(ctx); err == nil {
		t.Fatal("login with a rejected token should fail")
	}
	_ = os.WriteFile(jwt, []byte("good"), 0o600) // kubelet rotated the token

	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	waitFile := func(want string) {
		t.Helper()
		for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(20 * time.Millisecond) {
			if b, _ := os.ReadFile(filepath.Join(out, "db")); string(b) == want {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("file never became %q", want)
			}
		}
	}
	waitFile("pw-v1")
	s.do("PUT", "/v1/kv/prod/orders/db", map[string]string{"value": "rotated"})
	waitFile("rotated") // picked up by the refresh loop

	// Expired certificate with kubernetes auth: renewal logs in again.
	a.now = func() time.Time { return time.Now().Add(48 * time.Hour) }
	if err := a.Renew(ctx); err != nil {
		t.Fatalf("re-login after expiry: %v", err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestNewValidates(t *testing.T) {
	ca := pki.EncodeCert(mustRoot(t).Cert)
	base := Config{Addrs: []string{"x:1"}, CAPEM: ca, OutDir: t.TempDir(), Auth: "token"}
	cases := map[string]func(c *Config){
		"no addrs":     func(c *Config) { c.Addrs = nil },
		"bad auth":     func(c *Config) { c.Auth = "password" },
		"bad CA":       func(c *Config) { c.CAPEM = []byte("x") },
		"reserved":     func(c *Config) { c.Secrets = map[string]string{"a": "tls.key"} },
		"traversal":    func(c *Config) { c.Secrets = map[string]string{"a": "../etc/passwd"} },
		"hidden":       func(c *Config) { c.Secrets = map[string]string{"a": ".x"} },
		"same file":    func(c *Config) { c.Secrets = map[string]string{"a": "x"}; c.DBCreds = map[string]string{"r": "x"} },
		"db reserved":  func(c *Config) { c.DBCreds = map[string]string{"r": "tls.crt"} },
		"missing file": func(c *Config) { c.Auth = "kubernetes"; c.JWTFile = filepath.Join(t.TempDir(), "none") },
	}
	for name, mod := range cases {
		c := base
		mod(&c)
		a, err := New(c)
		if name == "missing file" {
			if err != nil || a.Login(context.Background()) == nil {
				t.Errorf("%s: expected a login error", name)
			}
			continue
		}
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func mustRoot(t *testing.T) *pki.CA {
	r, err := pki.NewRoot("r", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// memDB stands in for a database (the real ones are tested in internal/lease).
type memDB struct {
	mu    sync.Mutex
	users map[string]string
}

func (d *memDB) Create(_ context.Context, _ string, u lease.User) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.users[u.Name] = u.Password
	return nil
}

func (d *memDB) Drop(_ context.Context, _ string, u lease.User) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.users, u.Name)
	return nil
}

func (d *memDB) n() int { d.mu.Lock(); defer d.mu.Unlock(); return len(d.users) }

func (d *memDB) has(user, pw string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	p, ok := d.users[user]
	return ok && p == pw
}

func TestDatabaseCredentials(t *testing.T) {
	db := &memDB{users: map[string]string{}}
	lease.Databases["mem"] = db
	t.Cleanup(func() { delete(lease.Databases, "mem") })
	s := newServer(t)
	s.do("PUT", "/v1/kv/db/admin", map[string]string{"value": "admin-dsn"})
	s.do("PUT", "/v1/sys/db-roles/orders-rw", map[string]any{"plugin": "mem", "admin": "db/admin", "default_ttl": "1h", "max_ttl": "3h"})
	s.do("PUT", "/v1/sys/db-roles/orders-ro", map[string]any{"plugin": "mem", "admin": "db/admin", "default_ttl": "1h", "max_ttl": "1h"})
	s.do("PUT", "/v1/sys/policies/orders-db", json.RawMessage(`{"name":"orders-db","rules":[{"path":"db/creds/orders-rw","capabilities":["read"]},{"path":"db/creds/orders-ro","capabilities":["read"]}]}`))
	s.do("PUT", "/v1/sys/bindings/svc/orders-api", map[string]any{"policies": []string{"orders", "orders-db"}})

	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	a, err := New(Config{Addrs: []string{s.addr}, CAPEM: s.caPEM, OutDir: out, Auth: "token", TokenFile: s.tokenFile(dir),
		DBCreds: map[string]string{"orders-rw": "rw.json", "orders-ro": "ro.json"}, Log: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := a.Login(ctx); err != nil {
		t.Fatal(err)
	}
	load := func(name string) (f struct {
		Username string `json:"username"`
		Password string `json:"password"`
		LeaseID  string `json:"lease_id"`
	}) {
		_ = json.Unmarshal([]byte(read(t, filepath.Join(out, name))), &f)
		return f
	}
	if err := a.DBCreds(ctx); err != nil {
		t.Fatal(err)
	}
	rw1, ro1 := load("rw.json"), load("ro.json")
	if !db.has(rw1.Username, rw1.Password) || !db.has(ro1.Username, ro1.Password) || rw1.Username == ro1.Username {
		t.Fatalf("credentials not issued: %+v %+v", rw1, ro1)
	}
	if st, _ := os.Stat(filepath.Join(out, "rw.json")); st.Mode().Perm()&0o077 != 0 && runtime.GOOS != "windows" {
		t.Fatalf("mode %v", st.Mode())
	}

	// Before 2/3 of the lease: nothing happens.
	start := time.Now()
	_ = a.DBCreds(ctx)
	if load("rw.json") != rw1 || load("ro.json") != ro1 {
		t.Fatal("credentials replaced too early")
	}
	// At 2/3: orders-rw (max 3h) is renewed in place; orders-ro (already at
	// max) gets new credentials, and its old user stays until it expires.
	a.now = func() time.Time { return start.Add(41 * time.Minute) }
	before := a.leases["orders-rw"].Expires
	if err := a.DBCreds(ctx); err != nil {
		t.Fatal(err)
	}
	if load("rw.json") != rw1 || !a.leases["orders-rw"].Expires.After(before) {
		t.Fatal("orders-rw should have been renewed, not replaced")
	}
	ro2 := load("ro.json")
	if ro2.Username == ro1.Username || !db.has(ro2.Username, ro2.Password) || !db.has(ro1.Username, ro1.Password) {
		t.Fatalf("orders-ro replacement: old %+v new %+v", ro1, ro2)
	}

	// An operator revokes orders-rw: the next renewal fails and the agent
	// gets new credentials.
	s.do("POST", "/v1/sys/leases/revoke-prefix/db/orders-rw", nil)
	if db.has(rw1.Username, rw1.Password) {
		t.Fatal("revoked user still exists")
	}
	a.now = func() time.Time { return start.Add(90 * time.Minute) }
	if err := a.DBCreds(ctx); err != nil {
		t.Fatal(err)
	}
	if rw2 := load("rw.json"); rw2.Username == rw1.Username || !db.has(rw2.Username, rw2.Password) {
		t.Fatalf("after revocation: %+v", rw2)
	}

	users := db.n()
	runPythonSDK(t, "DBLiveTest", "SM_TEST_ADDR="+s.addr, "SM_TEST_AGENT_DIR="+out, "SM_TEST_DB_ROLE=orders-rw")
	if db.n() != users {
		t.Fatalf("python SDK left a user behind (%d -> %d)", users, db.n())
	}
}

// When the server refuses a renewal (the last full login is too old), a
// Kubernetes agent logs in again at once; a token-auth agent reports it.
func TestRenewalRefusedLogsInAgain(t *testing.T) {
	s := newServer(t, func(c *api.Config) { c.MaxLineage = time.Nanosecond }) // every renewal is "too old"
	url, ca := fakeK8s(t)
	s.do("PUT", "/v1/sys/auth/kubernetes", map[string]any{"host": url, "ca_pem": ca, "reviewer_token": "r",
		"audience": "sm", "roles": map[string]string{"shop/orders": "orders-api"}})
	dir := t.TempDir()
	jwt := filepath.Join(dir, "jwt")
	_ = os.WriteFile(jwt, []byte("good"), 0o600)
	a, err := New(Config{Addrs: []string{s.addr}, CAPEM: s.caPEM, OutDir: filepath.Join(dir, "k8s"), Auth: "kubernetes", JWTFile: jwt, Log: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := a.Login(ctx); err != nil {
		t.Fatal(err)
	}
	first := a.cert
	a.now = func() time.Time { return renewAt(first).Add(time.Second) }
	if err := a.Renew(ctx); err != nil {
		t.Fatalf("refused renewal should fall back to login: %v", err)
	}
	if a.cert.SerialNumber.Cmp(first.SerialNumber) == 0 {
		t.Fatal("no new certificate")
	}

	tokAgent, err := New(Config{Addrs: []string{s.addr}, CAPEM: s.caPEM, OutDir: filepath.Join(dir, "tok"), Auth: "token",
		TokenFile: s.tokenFile(dir), Log: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	if err := tokAgent.Login(ctx); err != nil {
		t.Fatal(err)
	}
	tokAgent.now = func() time.Time { return renewAt(tokAgent.cert).Add(time.Second) }
	if err := tokAgent.Renew(ctx); err == nil || !strings.Contains(err.Error(), "log in again") {
		t.Fatalf("token agent: %v", err)
	}
}
