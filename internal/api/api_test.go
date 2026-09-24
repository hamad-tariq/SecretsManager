package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"github.com/hamad-tariq/SecretsManager/internal/audit"
	"github.com/hamad-tariq/SecretsManager/internal/barrier"
	"github.com/hamad-tariq/SecretsManager/internal/pki"
	"github.com/hamad-tariq/SecretsManager/internal/rotation"
	"github.com/hamad-tariq/SecretsManager/internal/storage"
)

const canary = "CANARY-api-9d1e"

type env struct {
	t        *testing.T
	url      string
	auditLog string
	ca       *pki.CA
	roots    *x509.CertPool
	seal     *barrier.Seal
	srv      *Server
	cluster  *fakeCluster
	shares   []string // from ready()
}

func newEnv(t *testing.T) *env {
	root, _ := pki.NewRoot("test", time.Hour)
	roots := x509.NewCertPool()
	roots.AddCert(root.Cert)
	raw := storage.NewInmem()
	fc := &fakeCluster{raw: raw, leader: true}
	seal := barrier.NewSeal(raw)
	t.Cleanup(seal.Seal)
	logPath := filepath.Join(t.TempDir(), "audit.log")
	al, err := audit.OpenFile(logPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = al.Close() })
	srv := New(Config{Seal: seal, Audit: al, Cluster: fc, Roots: roots, Rate: 1000, Burst: 1000})

	hs := httptest.NewUnstartedServer(srv.Handler())
	key, _ := pki.NewKey()
	nodeCert, _ := root.Issue(pki.Identity{Kind: pki.Node, Name: "node-1"}, key.Public(), time.Hour, "127.0.0.1")
	hs.TLS = TLSConfig(pki.TLSCertificate(nodeCert, key), roots)
	hs.StartTLS()
	t.Cleanup(hs.Close)
	return &env{t: t, url: hs.URL, auditLog: logPath, ca: root, roots: roots, seal: seal, srv: srv, cluster: fc}
}

// client returns an HTTP client presenting a certificate for id (zero id = no certificate).
func (e *env) client(id pki.Identity) *http.Client {
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: e.roots}
	if id.Name != "" {
		key, _ := pki.NewKey()
		c, err := e.ca.Issue(id, key.Public(), time.Hour)
		if err != nil {
			e.t.Fatal(err)
		}
		cfg.Certificates = []tls.Certificate{pki.TLSCertificate(c, key)}
	}
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg}}
}

func (e *env) do(c *http.Client, method, path string, body any) (int, map[string]any) {
	e.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	default:
		j, _ := json.Marshal(b)
		rd = bytes.NewReader(j)
	}
	req, _ := http.NewRequest(method, e.url+path, rd)
	resp, err := c.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (e *env) expect(c *http.Client, method, path string, body any, want int) map[string]any {
	e.t.Helper()
	code, out := e.do(c, method, path, body)
	if code != want {
		e.t.Fatalf("%s %s: status %d, want %d (%v)", method, path, code, want, out)
	}
	return out
}

var (
	rootAdmin  = pki.Identity{Kind: pki.Admin, Name: "alice"}
	otherAdmin = pki.Identity{Kind: pki.Admin, Name: "bob"}
	orders     = pki.Identity{Kind: pki.Service, Name: "orders-api"}
	billing    = pki.Identity{Kind: pki.Service, Name: "billing-api"}
	// shareHolder unseals: an admin certificate with no bindings.
	shareHolder = pki.Identity{Kind: pki.Admin, Name: "holder"}
)

// ready initialises and unseals, returning the root admin's client.
func (e *env) ready() *http.Client {
	admin := e.client(rootAdmin)
	out := e.expect(admin, "POST", "/v1/sys/init", initRequest{Shares: 3, Threshold: 2}, 200)
	shares := out["shares"].([]any)
	for _, sh := range shares {
		e.shares = append(e.shares, sh.(string))
	}
	holder := e.client(shareHolder)
	e.expect(holder, "POST", "/v1/sys/unseal", map[string]string{"share": shares[0].(string)}, 200)
	st := e.expect(holder, "POST", "/v1/sys/unseal", map[string]string{"share": shares[1].(string)}, 200)
	if st["sealed"] != false {
		e.t.Fatalf("still sealed: %v", st)
	}
	return admin
}

func TestInitAndUnsealFlow(t *testing.T) {
	e := newEnv(t)
	anon := e.client(pki.Identity{})

	e.expect(anon, "GET", "/v1/sys/health", nil, 501)
	e.expect(anon, "POST", "/v1/sys/init", initRequest{Shares: 3, Threshold: 2}, 401)
	e.expect(e.client(orders), "POST", "/v1/sys/init", initRequest{Shares: 3, Threshold: 2}, 403)
	e.expect(e.client(rootAdmin), "POST", "/v1/sys/init", initRequest{Shares: 1, Threshold: 2}, 400)

	admin := e.client(rootAdmin)
	out := e.expect(admin, "POST", "/v1/sys/init", initRequest{Shares: 3, Threshold: 2}, 200)
	shares := out["shares"].([]any)
	e.expect(admin, "POST", "/v1/sys/init", initRequest{Shares: 3, Threshold: 2}, 409)

	e.expect(anon, "GET", "/v1/sys/health", nil, 503)
	e.expect(admin, "GET", "/v1/kv/prod/db", nil, 503) // sealed
	// Unseal needs an admin certificate (a share holder's, with no rights otherwise).
	e.expect(anon, "POST", "/v1/sys/unseal", map[string]string{"share": shares[0].(string)}, 401)
	e.expect(e.client(orders), "POST", "/v1/sys/unseal", map[string]string{"share": shares[0].(string)}, 403)
	holder := e.client(shareHolder)
	e.expect(holder, "POST", "/v1/sys/unseal", map[string]string{"share": "junk"}, 400)
	e.expect(holder, "POST", "/v1/sys/unseal", map[string]string{"share": shares[0].(string)}, 200)
	e.expect(holder, "POST", "/v1/sys/unseal", map[string]string{"share": shares[0].(string)}, 400) // duplicate
	e.expect(holder, "POST", "/v1/sys/unseal", map[string]string{"share": shares[2].(string)}, 200)
	h := e.expect(anon, "GET", "/v1/sys/health", nil, 200)
	if h["sealed"] != false || h["initialized"] != true {
		t.Fatalf("health %v", h)
	}
	e.expect(holder, "POST", "/v1/sys/unseal", "not json", 400)
}

func TestPoliciesBindingsAndSecrets(t *testing.T) {
	e := newEnv(t)
	admin := e.ready()
	svc := e.client(orders)
	other := e.client(billing)

	// Root admin writes a secret; services have no access yet.
	e.expect(admin, "PUT", "/v1/kv/prod/orders/db", map[string]string{"value": canary}, 200)
	e.expect(svc, "GET", "/v1/kv/prod/orders/db", nil, 403)
	e.expect(svc, "GET", "/v1/kv/prod/orders/missing", nil, 403) // same answer: no existence oracle
	e.expect(e.client(pki.Identity{}), "GET", "/v1/kv/prod/orders/db", nil, 401)

	pol := `{"name":"orders","rules":[{"path":"kv/prod/orders/*","capabilities":["read","list"]},{"path":"kv/prod/orders/admin/*","deny":true}]}`
	e.expect(admin, "PUT", "/v1/sys/policies/orders", pol, 200)
	e.expect(admin, "PUT", "/v1/sys/policies/other", pol, 400) // name mismatch
	e.expect(admin, "PUT", "/v1/sys/policies/bad", `{"name":"bad","rules":[{"path":"x","capabilites":["read"]}]}`, 400)
	e.expect(admin, "PUT", "/v1/sys/bindings/svc/orders-api", map[string]any{"policies": []string{"orders"}}, 200)
	e.expect(admin, "PUT", "/v1/sys/bindings/svc/orders-api", map[string]any{"policies": []string{"Bad Name"}}, 400)
	e.expect(admin, "PUT", "/v1/sys/bindings/root/x", map[string]any{"policies": []string{"orders"}}, 400)

	got := e.expect(svc, "GET", "/v1/kv/prod/orders/db", nil, 200)
	if got["value"] != canary || got["version"] != float64(1) {
		t.Fatalf("read: %v", got)
	}
	e.expect(svc, "PUT", "/v1/kv/prod/orders/db", map[string]string{"value": "x"}, 403) // read-only
	e.expect(other, "GET", "/v1/kv/prod/orders/db", nil, 403)                           // other service
	e.expect(admin, "PUT", "/v1/kv/prod/orders/admin/key", map[string]string{"value": "x"}, 200)
	e.expect(svc, "GET", "/v1/kv/prod/orders/admin/key", nil, 403) // deny rule
	e.expect(svc, "GET", "/v1/kv/prod/orders/nope", nil, 404)      // allowed path, no secret

	list := e.expect(svc, "GET", "/v1/kv/prod/orders/?list", nil, 403) // list on the folder itself needs a rule for kv/prod/orders
	_ = list
	e.expect(admin, "GET", "/v1/kv/prod/orders/?list", nil, 200)
	keys := e.expect(admin, "GET", "/v1/kv/?list", nil, 200)["keys"].([]any)
	if len(keys) != 2 {
		t.Fatalf("list all: %v", keys)
	}

	// Policy and binding reads, list, delete.
	e.expect(admin, "GET", "/v1/sys/policies/orders", nil, 200)
	e.expect(admin, "GET", "/v1/sys/policies/none", nil, 404)
	if ps := e.expect(admin, "GET", "/v1/sys/policies", nil, 200)["policies"].([]any); len(ps) != 1 {
		t.Fatalf("policies %v", ps)
	}
	e.expect(admin, "GET", "/v1/sys/bindings/svc/orders-api", nil, 200)
	e.expect(admin, "GET", "/v1/sys/bindings/svc/nobody", nil, 404)
	e.expect(svc, "GET", "/v1/sys/policies/orders", nil, 403) // services can't read policies
	e.expect(admin, "DELETE", "/v1/sys/bindings/svc/orders-api", nil, 200)
	e.expect(svc, "GET", "/v1/kv/prod/orders/db", nil, 403) // access gone
	e.expect(admin, "DELETE", "/v1/sys/policies/orders", nil, 200)

	// A non-root admin has no implicit rights.
	e.expect(e.client(otherAdmin), "GET", "/v1/kv/prod/orders/db", nil, 403)
	e.expect(admin, "GET", "/v1/sys/policies/BAD", nil, 400)
}

func TestSecretLifecycle(t *testing.T) {
	e := newEnv(t)
	admin := e.ready()
	w := func(v string, cas any, want int) map[string]any {
		body := map[string]any{"value": v}
		if cas != nil {
			body["cas"] = cas
		}
		return e.expect(admin, "PUT", "/v1/kv/app/key", body, want)
	}
	w("v1", 0, 200)
	w("x", 0, 409) // create-only on existing
	w("v2", 1, 200)
	w("x", 1, 409) // stale version
	w("v3", nil, 200)
	e.expect(admin, "PUT", "/v1/kv/app/key", `{"nope":1}`, 400)
	e.expect(admin, "PUT", "/v1/kv/app/key", `{}`, 400)

	if v := e.expect(admin, "GET", "/v1/kv/app/key?version=1", nil, 200)["value"]; v != "v1" {
		t.Fatalf("version 1 = %v", v)
	}
	if v := e.expect(admin, "GET", "/v1/kv/app/key?label=previous", nil, 200)["value"]; v != "v2" {
		t.Fatalf("previous = %v", v)
	}
	e.expect(admin, "GET", "/v1/kv/app/key?version=0", nil, 400)
	e.expect(admin, "GET", "/v1/kv/app/key?version=9", nil, 404)
	m := e.expect(admin, "GET", "/v1/kv/app/key?metadata", nil, 200)
	if m["latest"] != float64(3) {
		t.Fatalf("metadata %v", m)
	}
	if _, has := m["value"]; has {
		t.Fatal("metadata leaked a value")
	}

	e.expect(admin, "DELETE", "/v1/kv/app/key", nil, 200)
	e.expect(admin, "GET", "/v1/kv/app/key", nil, 404)
	e.expect(admin, "POST", "/v1/kv/app/key?op=bogus", nil, 400)
	e.expect(admin, "POST", "/v1/kv/app/key?op=undelete", nil, 200)
	e.expect(admin, "POST", "/v1/kv/app/key?op=undelete", nil, 409)
	e.expect(admin, "GET", "/v1/kv/app/key", nil, 200)
	e.expect(admin, "DELETE", "/v1/kv/app/key?destroy", nil, 200)
	e.expect(admin, "GET", "/v1/kv/app/key?metadata", nil, 404)
	e.expect(admin, "DELETE", "/v1/kv/app/key", nil, 404)

	e.expect(admin, "GET", "/v1/kv/a%20b", nil, 400)
	// The router cleans "//" and ".." (redirecting to the clean path) before any
	// handler runs, so the path that is policy-checked is the one that is served.
	e.expect(admin, "PUT", "/v1/kv/b", map[string]string{"value": "b"}, 200)
	if v := e.expect(admin, "GET", "/v1/kv/a/../b", nil, 200)["path"]; v != "b" {
		t.Fatalf("dot-dot path served %v", v)
	}
}

func TestCreateVersusUpdatePermission(t *testing.T) {
	e := newEnv(t)
	admin := e.ready()
	e.expect(admin, "PUT", "/v1/sys/policies/creator", `{"name":"creator","rules":[{"path":"kv/drop/*","capabilities":["create"]}]}`, 200)
	e.expect(admin, "PUT", "/v1/sys/bindings/svc/orders-api", map[string]any{"policies": []string{"creator"}}, 200)
	svc := e.client(orders)
	e.expect(svc, "PUT", "/v1/kv/drop/a", map[string]string{"value": "1"}, 200)
	e.expect(svc, "PUT", "/v1/kv/drop/a", map[string]string{"value": "2"}, 403) // exists: needs update
	// Soft-deleted still exists: writing would revive its old versions.
	e.expect(admin, "DELETE", "/v1/kv/drop/a", nil, 200)
	e.expect(svc, "PUT", "/v1/kv/drop/a", map[string]string{"value": "3"}, 403)
	e.expect(svc, "PUT", "/v1/kv/drop/b", map[string]any{"value": "1", "cas": -1}, 400)
}

func TestSysOperations(t *testing.T) {
	e := newEnv(t)
	admin := e.ready()
	e.expect(admin, "PUT", "/v1/kv/a", map[string]string{"value": "before"}, 200)
	if term := e.expect(admin, "POST", "/v1/sys/rotate", nil, 200)["term"]; term != float64(2) {
		t.Fatalf("term %v", term)
	}
	e.expect(admin, "PUT", "/v1/kv/b", map[string]string{"value": "after"}, 200)
	e.expect(e.client(orders), "POST", "/v1/sys/rotate", nil, 403)
	e.expect(e.client(orders), "POST", "/v1/sys/seal", nil, 403)
	e.expect(admin, "POST", "/v1/sys/rekey", map[string]any{"shares": []string{"x", "y"}, "new_shares": 3, "threshold": 2}, 400)

	e.expect(admin, "POST", "/v1/sys/seal", nil, 200)
	e.expect(admin, "GET", "/v1/kv/a", nil, 503)
	e.expect(admin, "POST", "/v1/sys/seal", nil, 503)
}

func TestRekeyOverAPI(t *testing.T) {
	e := newEnv(t)
	admin := e.client(rootAdmin)
	shares := e.expect(admin, "POST", "/v1/sys/init", initRequest{Shares: 3, Threshold: 2}, 200)["shares"].([]any)
	holder := e.client(shareHolder)
	for _, s := range shares[:2] {
		e.expect(holder, "POST", "/v1/sys/unseal", map[string]string{"share": s.(string)}, 200)
	}
	out := e.expect(admin, "POST", "/v1/sys/rekey", map[string]any{
		"shares": []string{shares[0].(string), shares[1].(string)}, "new_shares": 4, "threshold": 3}, 200)
	if len(out["shares"].([]any)) != 4 {
		t.Fatalf("rekey: %v", out)
	}
}

func TestRateLimit(t *testing.T) {
	e := newEnv(t)
	admin := e.ready()
	e.srv.lim.r, e.srv.lim.b = 1, 3
	e.srv.lim.m = map[string]*rate.Limiter{}
	codes := map[int]int{}
	for range 10 {
		code, _ := e.do(admin, "GET", "/v1/kv/x", nil)
		codes[code]++
	}
	if codes[429] < 5 {
		t.Fatalf("rate limit not enforced: %v", codes)
	}
	// Another identity has its own bucket.
	if code, _ := e.do(e.client(orders), "GET", "/v1/kv/x", nil); code == 429 {
		t.Fatal("rate limit shared across identities")
	}
}

func TestAuditTrail(t *testing.T) {
	e := newEnv(t)
	admin := e.ready()
	e.expect(admin, "PUT", "/v1/kv/prod/db", map[string]string{"value": canary}, 200)
	e.expect(admin, "GET", "/v1/kv/prod/db", nil, 200)
	e.expect(e.client(orders), "GET", "/v1/kv/prod/db", nil, 403)

	data, _ := os.ReadFile(e.auditLog)
	if strings.Contains(string(data), canary) {
		t.Fatal("plaintext secret in audit log")
	}
	if _, err := audit.Verify(bytes.NewReader(data)); err != nil {
		t.Fatalf("audit chain: %v", err)
	}
	var denied, hmacd int
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var r audit.Record
		_ = json.Unmarshal([]byte(line), &r)
		if r.Result == "denied:403" && r.Identity == orders.String() && r.Path == "kv/prod/db" {
			denied++
		}
		if r.HMACs["value"] != "" {
			hmacd++
		}
		if r.Operation == "sys.init" && strings.Contains(line, "shares") {
			t.Fatal("shares in audit log")
		}
	}
	if denied != 1 || hmacd != 2 {
		t.Fatalf("denied entries %d, HMAC'd values %d", denied, hmacd)
	}
}

func TestAuditFailureFailsClosed(t *testing.T) {
	e := newEnv(t)
	admin := e.ready()
	e.expect(admin, "PUT", "/v1/kv/a", map[string]string{"value": canary}, 200)
	// Break the audit log: every request must now fail without data.
	broken := audit.New(failingWriter{}, []byte("k"), audit.Head{})
	e.srv.audit = broken
	code, out := e.do(admin, "GET", "/v1/kv/a", nil)
	if code != 500 || fmt.Sprint(out) == "" || strings.Contains(fmt.Sprint(out), canary) {
		t.Fatalf("with broken audit: %d %v", code, out)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, fmt.Errorf("disk full") }

func TestRotationRoutes(t *testing.T) {
	e := newEnv(t)
	admin := e.ready()
	settings := map[string]any{"interval": "720h", "plugin": "random", "params": map[string]string{"length": "24"}}

	e.expect(e.client(orders), "PUT", "/v1/sys/rotation/app/key", settings, 403)
	e.expect(admin, "PUT", "/v1/sys/rotation/app/key", map[string]any{"interval": "1s", "plugin": "random"}, 400)
	e.expect(admin, "PUT", "/v1/sys/rotation/app/key", map[string]any{"interval": "1h", "plugin": "nope"}, 400)
	e.expect(admin, "GET", "/v1/sys/rotation/app/key", nil, 404)

	out := e.expect(admin, "PUT", "/v1/sys/rotation/app/key", settings, 200)
	if out["plugin"] != "random" || out["next_due"] == nil {
		t.Fatalf("configure: %v", out)
	}
	// The engine (running on the leader in smd) picks it up.
	rotation.New(rotation.Config{Backend: e.seal.Barrier, Sealed: e.seal.Sealed, Leader: func() bool { return true },
		Audit: e.srv.audit, Identity: "spiffe://sm/node/node-1"}).Tick(context.Background())
	sec := e.expect(admin, "GET", "/v1/kv/app/key", nil, 200)
	if v, _ := sec["value"].(string); len(v) != 24 {
		t.Fatalf("rotated value %q", v)
	}
	if got := e.expect(admin, "GET", "/v1/sys/rotation/app/key", nil, 200); got["last_rotated"] == nil {
		t.Fatalf("status after rotation: %v", got)
	}

	e.expect(admin, "POST", "/v1/sys/rotation/app/key", nil, 400)
	e.expect(admin, "POST", "/v1/sys/rotation/app/key?op=rotate", nil, 200)
	e.expect(admin, "DELETE", "/v1/sys/rotation/app/key", nil, 200)
	e.expect(admin, "GET", "/v1/sys/rotation/app/key", nil, 404)
	e.expect(admin, "POST", "/v1/sys/rotation/app/key?op=rotate", nil, 404)
	e.expect(admin, "GET", "/v1/kv/app/key", nil, 200) // secret kept
}
