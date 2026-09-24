package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hamad-tariq/SecretsManager/internal/api"
	"github.com/hamad-tariq/SecretsManager/internal/audit"
	"github.com/hamad-tariq/SecretsManager/internal/barrier"
	"github.com/hamad-tariq/SecretsManager/internal/pki"
	"github.com/hamad-tariq/SecretsManager/internal/storage"
)

type result struct {
	code        int
	out, errOut string
}

func cliRun(stdin string, args ...string) result {
	var out, errOut bytes.Buffer
	code := run(args, strings.NewReader(stdin), &out, &errOut)
	return result{code, out.String(), errOut.String()}
}

func must(t *testing.T, r result, want int) result {
	t.Helper()
	if r.code != want {
		t.Fatalf("exit %d, want %d\nstdout: %s\nstderr: %s", r.code, want, r.out, r.errOut)
	}
	return r
}

// setup issues certificates with the CLI's own pki commands and starts three
// API nodes sharing one storage (as a Raft cluster would present it).
func setup(t *testing.T) (dir string, addrs string) {
	dir = t.TempDir()
	must(t, cliRun("", "pki", "root-init", "-out", dir), 0)
	must(t, cliRun("", "pki", "root-init", "-out", dir), 1) // never overwrites keys
	must(t, cliRun("", "pki", "intermediate", "-ca-cert", dir+"/root.pem", "-ca-key", dir+"/root.key", "-out", dir), 0)
	issue := func(kind, name string, extra ...string) {
		args := append([]string{"pki", "issue", "-ca-cert", dir + "/intermediate.pem", "-ca-key", dir + "/intermediate.key",
			"-kind", kind, "-name", name, "-out", dir}, extra...)
		must(t, cliRun("", args...), 0)
	}
	issue("node", "node-1", "-host", "127.0.0.1")
	issue("admin", "alice")
	issue("svc", "orders-api")
	must(t, cliRun("", "pki", "issue", "-ca-cert", dir+"/intermediate.pem", "-ca-key", dir+"/intermediate.key",
		"-kind", "svc", "-name", "x", "-host", "evil", "-out", dir), 1) // services can't carry hosts
	must(t, cliRun("", "pki", "issue", "-ca-cert", dir+"/alice.pem", "-ca-key", dir+"/alice.key",
		"-kind", "svc", "-name", "y", "-out", dir), 1) // a leaf is not a CA

	cert, err := tls.LoadX509KeyPair(dir+"/node-1.pem", dir+"/node-1.key")
	if err != nil {
		t.Fatal(err)
	}
	rootPEM, _ := os.ReadFile(dir + "/root.pem")
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(rootPEM)

	raw := storage.NewInmem()
	var list []string
	for i := range 3 {
		seal := barrier.NewSeal(raw)
		t.Cleanup(seal.Seal)
		al, err := audit.OpenFile(filepath.Join(dir, "audit-"+string(rune('0'+i))+".log"), nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = al.Close() })
		hs := httptest.NewUnstartedServer(api.New(api.Config{Seal: seal, Audit: al, Roots: roots}).Handler())
		hs.TLS = api.TLSConfig(cert, roots)
		hs.StartTLS()
		t.Cleanup(hs.Close)
		list = append(list, strings.TrimPrefix(hs.URL, "https://"))
	}
	return dir, strings.Join(list, ",")
}

func TestCLIEndToEnd(t *testing.T) {
	dir, addrs := setup(t)
	admin := func(stdin string, args ...string) result {
		return cliRun(stdin, append([]string{"-addr", addrs, "-ca", dir + "/root.pem",
			"-cert", dir + "/alice.pem", "-key", dir + "/alice.key"}, args...)...)
	}
	svc := func(args ...string) result {
		return cliRun("", append([]string{"-addr", addrs, "-ca", dir + "/root.pem",
			"-cert", dir + "/orders-api.pem", "-key", dir + "/orders-api.key"}, args...)...)
	}
	statusOf := func() map[string]map[string]any {
		var st map[string]map[string]any
		if err := json.Unmarshal([]byte(must(t, admin("", "operator", "status"), 0).out), &st); err != nil {
			t.Fatal(err)
		}
		if len(st) != 3 {
			t.Fatalf("status for %d nodes", len(st))
		}
		return st
	}

	for _, st := range statusOf() {
		if st["initialized"] != false {
			t.Fatalf("status before init: %v", st)
		}
	}

	// Init and unseal every node, one share at a time.
	var initOut struct{ Shares []string }
	r := must(t, admin("", "operator", "init", "-shares", "3", "-threshold", "2"), 0)
	if err := json.Unmarshal([]byte(r.out), &initOut); err != nil || len(initOut.Shares) != 3 {
		t.Fatalf("init output: %s", r.out)
	}
	if !strings.Contains(r.errOut, "shown only once") {
		t.Fatal("init did not warn about shares")
	}
	must(t, admin(initOut.Shares[0]+"\n", "operator", "unseal"), 0)
	must(t, admin(initOut.Shares[1]+"\n", "operator", "unseal"), 0)
	for addr, st := range statusOf() {
		if st["sealed"] != false {
			t.Fatalf("%s still sealed: %v", addr, st)
		}
	}
	must(t, admin("", "operator", "unseal"), 1) // no share on stdin

	// Secrets. The value comes from stdin and is only printed with -reveal.
	must(t, admin("s3cret\n", "kv", "put", "prod/db"), 0)
	if r := must(t, admin("", "kv", "get", "prod/db"), 0); strings.Contains(r.out, "s3cret") || !strings.Contains(r.out, "hidden") {
		t.Fatalf("value printed without -reveal: %s", r.out)
	}
	if r := must(t, admin("", "kv", "get", "-reveal", "prod/db"), 0); r.out != "s3cret\n" {
		t.Fatalf("revealed %q", r.out)
	}
	must(t, admin("v2", "kv", "put", "-cas", "1", "prod/db"), 0)
	must(t, admin("v3", "kv", "put", "-cas", "1", "prod/db"), 1) // stale
	if r := must(t, admin("", "kv", "get", "-reveal", "-version", "1", "prod/db"), 0); r.out != "s3cret\n" {
		t.Fatalf("version 1: %q", r.out)
	}
	if r := must(t, admin("", "kv", "get", "-reveal", "-label", "previous", "prod/db"), 0); r.out != "s3cret\n" {
		t.Fatalf("previous: %q", r.out)
	}
	must(t, admin("x", "kv", "put", "prod/orders/db"), 0)
	if r := must(t, admin("", "kv", "list", "prod"), 0); !strings.Contains(r.out, "prod/orders/db") {
		t.Fatalf("list: %s", r.out)
	}
	must(t, admin("", "kv", "list"), 0)
	if r := must(t, admin("", "kv", "history", "prod/db"), 0); !strings.Contains(r.out, `"latest": 2`) {
		t.Fatalf("history: %s", r.out)
	}
	must(t, admin("", "kv", "delete", "prod/db"), 0)
	must(t, admin("", "kv", "get", "prod/db"), 1)
	must(t, admin("", "kv", "undelete", "prod/db"), 0)
	must(t, admin("", "kv", "get", "prod/db"), 0)
	must(t, admin("", "kv", "destroy", "prod/db"), 0)
	must(t, admin("", "kv", "history", "prod/db"), 1)

	// Policies and identities.
	polFile := filepath.Join(dir, "orders.json")
	_ = os.WriteFile(polFile, []byte(`{"name":"orders","rules":[{"path":"kv/prod/orders/*","capabilities":["read"]}]}`), 0o600)
	must(t, svc("kv", "get", "prod/orders/db"), 1) // no binding yet
	must(t, admin("", "policy", "write", "orders", polFile), 0)
	must(t, admin("", "policy", "write", "orders", dir+"/missing.json"), 1)
	if r := must(t, admin("", "policy", "list"), 0); !strings.Contains(r.out, "orders") {
		t.Fatalf("policy list: %s", r.out)
	}
	must(t, admin("", "policy", "read", "orders"), 0)
	must(t, admin("", "identity", "bind", "svc/orders-api", "orders"), 0)
	must(t, admin("", "identity", "bind", "root/x", "orders"), 1)
	must(t, admin("", "identity", "bind", "no-slash", "orders"), 2)
	if r := must(t, admin("", "identity", "show", "svc/orders-api"), 0); !strings.Contains(r.out, "orders") {
		t.Fatalf("identity show: %s", r.out)
	}
	if r := must(t, svc("kv", "get", "-reveal", "prod/orders/db"), 0); r.out != "x" {
		t.Fatalf("service read: %q", r.out)
	}
	must(t, admin("", "identity", "unbind", "svc/orders-api"), 0)
	must(t, svc("kv", "get", "prod/orders/db"), 1)
	must(t, admin("", "policy", "delete", "orders"), 0)

	// Service onboarding: upload the issuing CA, mint an enrollment token,
	// configure Kubernetes login.
	must(t, admin("", "pki", "upload", "-cert", dir+"/alice.pem", "-key", dir+"/alice.key"), 1) // not a CA
	must(t, admin("", "pki", "upload", "-cert", dir+"/intermediate.pem", "-key", dir+"/intermediate.key"), 0)
	if r := must(t, admin("", "enroll", "token", "-service", "orders-api", "-ttl", "5m"), 0); !strings.Contains(r.out, `"token": "smt_`) {
		t.Fatalf("enroll token: %s", r.out)
	}
	must(t, admin("", "enroll", "token"), 2)
	must(t, admin("", "enroll", "token", "-service", "x", "-ttl", "9h"), 1)
	_ = os.WriteFile(dir+"/reviewer", []byte("tok\n"), 0o600)
	must(t, admin("", "auth", "kubernetes", "-host", "https://k8s.example:6443", "-ca-file", dir+"/root.pem",
		"-reviewer-token-file", dir+"/reviewer", "-role", "shop/orders=orders-api"), 0)
	must(t, admin("", "auth", "kubernetes", "-host", "https://k8s.example:6443", "-ca-file", dir+"/root.pem",
		"-reviewer-token-file", dir+"/reviewer", "-role", "no-equals"), 2)
	must(t, svc("enroll", "token", "-service", "orders-api"), 1) // services can't mint tokens

	// Database roles and leases (issuing against real databases is tested in
	// internal/lease; here the role points at a database that isn't there).
	_ = os.WriteFile(dir+"/role.json", []byte(`{"plugin":"postgres","admin":"db/admin","grants":["GRANT SELECT ON t TO {{name}}"]}`), 0o600)
	_ = os.WriteFile(dir+"/bad-role.json", []byte(`{"plugin":"oracle","admin":"db/admin"}`), 0o600)
	must(t, admin("", "db", "write-role", "orders-rw", dir+"/role.json"), 0)
	must(t, admin("", "db", "write-role", "orders-rw", dir+"/bad-role.json"), 1)
	if r := must(t, admin("", "db", "read-role", "orders-rw"), 0); !strings.Contains(r.out, `"plugin": "postgres"`) {
		t.Fatalf("read-role: %s", r.out)
	}
	must(t, admin("", "db", "creds", "orders-rw"), 1) // no admin credentials stored: fails cleanly
	if r := must(t, admin("", "lease", "list"), 0); !strings.Contains(r.out, `"leases": []`) {
		t.Fatalf("lease list after a failed issue: %s", r.out)
	}
	must(t, admin("", "lease", "revoke-prefix", "db/orders-rw"), 0)
	must(t, admin("", "lease", "revoke-prefix"), 2)
	must(t, svc("lease", "list"), 1)
	must(t, admin("", "db", "delete-role", "orders-rw"), 0)
	must(t, admin("", "db", "read-role", "orders-rw"), 1)

	// Revocation and the root admin.
	must(t, admin("", "cert", "revoke", "-cert", dir+"/orders-api.pem", "-reason", "test"), 0)
	if r := must(t, svc("kv", "get", "prod/orders/db"), 1); !strings.Contains(r.errOut, "certificate revoked") {
		t.Fatalf("revoked certificate: %s", r.errOut)
	}
	if r := must(t, admin("", "cert", "revocations"), 0); !strings.Contains(r.out, `"reason": "test"`) {
		t.Fatalf("revocations: %s", r.out)
	}
	must(t, admin("", "cert", "revoke", "-identity", "admin/alice"), 1) // the root admin can't be revoked
	must(t, admin("", "cert", "revoke"), 2)
	must(t, admin("", "cert", "revoke", "-serial", "1", "-identity", "svc/x"), 2)
	svcPEM, _ := os.ReadFile(dir + "/orders-api.pem")
	svcCert, _ := pki.ParseCert(svcPEM)
	must(t, admin("", "cert", "unrevoke", "-serial", svcCert.SerialNumber.Text(16)), 0)
	// -cert also revoked its lineage (every renewal): still refused.
	must(t, svc("kv", "get", "prod/orders/db"), 1)
	lineage := "spiffe://sm/svc/orders-api@" + pki.LoginTime(svcCert).UTC().Format(time.RFC3339)
	must(t, admin("", "cert", "unrevoke", "-lineage", lineage), 0)
	if r := must(t, svc("kv", "get", "prod/orders/db"), 1); strings.Contains(r.errOut, "revoked") || !strings.Contains(r.errOut, "403") {
		t.Fatalf("after unrevoke (no binding, so 403): %s", r.errOut)
	}
	must(t, admin(initOut.Shares[0]+"\n", "operator", "root-admin", "-identity", "admin/bob"), 1) // one share is not enough
	must(t, admin("", "operator", "root-admin"), 2)

	// Snapshots and membership need a real cluster (see cmd/smd's DR drill);
	// here: offline verification and clean failures.
	_ = os.WriteFile(dir+"/bad-snap.json", []byte(`{"format":"sm-snapshot-1","created":"2026-01-01T00:00:00Z","keys":1,"sha256":"00","data":{"raw/seal":"AA=="}}`), 0o600)
	must(t, cliRun("", "snapshot", "verify", dir+"/bad-snap.json"), 1)
	must(t, admin("", "snapshot", "restore", dir+"/bad-snap.json"), 1) // checked before sending
	must(t, admin("", "snapshot", "save", "-out", dir+"/snap.json"), 1)
	must(t, admin("", "snapshot", "save"), 2)
	must(t, admin("", "operator", "members"), 1)
	must(t, admin("", "operator", "remove-node"), 2)

	// Rotation settings (the engine itself is tested in internal/rotation).
	if r := must(t, admin("", "rotation", "set", "-interval", "720h", "-plugin", "postgres", "-param", "admin=db/admin",
		"-param", "users=app_a,app_b", "prod/orders/db"), 0); !strings.Contains(r.out, `"users": "app_a,app_b"`) {
		t.Fatalf("rotation set: %s", r.out)
	}
	must(t, admin("", "rotation", "set", "-interval", "1s", "-plugin", "random", "x"), 1)
	must(t, admin("", "rotation", "set", "-plugin", "random", "x"), 2)
	must(t, admin("", "rotation", "set", "-interval", "1h", "-plugin", "random", "-param", "no-equals", "x"), 2)
	if r := must(t, admin("", "rotation", "get", "prod/orders/db"), 0); !strings.Contains(r.out, `"next_due"`) {
		t.Fatalf("rotation get: %s", r.out)
	}
	must(t, admin("", "rotation", "now", "prod/orders/db"), 0)
	must(t, svc("rotation", "now", "prod/orders/db"), 1)
	must(t, admin("", "rotation", "delete", "prod/orders/db"), 0)
	must(t, admin("", "rotation", "get", "prod/orders/db"), 1)

	// Key operations.
	if r := must(t, admin("", "operator", "rotate"), 0); !strings.Contains(r.out, `"term": 2`) {
		t.Fatalf("rotate: %s", r.out)
	}
	var rekeyOut struct{ Shares []string }
	r = must(t, admin(initOut.Shares[0]+"\n"+initOut.Shares[2]+"\n", "operator", "rekey", "-shares", "4", "-threshold", "3"), 0)
	if err := json.Unmarshal([]byte(r.out), &rekeyOut); err != nil || len(rekeyOut.Shares) != 4 {
		t.Fatalf("rekey output: %s", r.out)
	}
	must(t, admin("", "operator", "seal", "-all"), 0)
	for addr, st := range statusOf() {
		if st["sealed"] != true {
			t.Fatalf("%s not sealed: %v", addr, st)
		}
	}
	// Old shares are dead; three new ones unseal every node.
	must(t, admin(initOut.Shares[0]+"\n", "operator", "unseal"), 0)
	must(t, admin(initOut.Shares[1]+"\n", "operator", "unseal"), 0)
	must(t, admin(initOut.Shares[2]+"\n", "operator", "unseal"), 1) // third old share completes a bad set
	for _, s := range rekeyOut.Shares[:3] {
		must(t, admin(s+"\n", "operator", "unseal"), 0)
	}
	for addr, st := range statusOf() {
		if st["sealed"] != false {
			t.Fatalf("%s sealed after unseal with new shares: %v", addr, st)
		}
	}
	must(t, admin("", "operator", "seal"), 0) // one node

	// Audit logs verify offline; tampering is caught.
	logPath := filepath.Join(dir, "audit-0.log")
	if r := must(t, cliRun("", "audit", "verify", logPath), 0); !strings.HasPrefix(r.out, "ok: ") {
		t.Fatalf("verify: %s", r.out)
	}
	data, _ := os.ReadFile(logPath)
	if bytes.Contains(data, []byte("s3cret")) {
		t.Fatal("secret in audit log")
	}
	_ = os.WriteFile(logPath, bytes.Replace(data, []byte(`"kv.read"`), []byte(`"kv.hide"`), 1), 0o600)
	must(t, cliRun("", "audit", "verify", logPath), 1)
}

func TestCLIUsageErrors(t *testing.T) {
	must(t, cliRun(""), 2)
	must(t, cliRun("", "bogus", "cmd"), 2)
	must(t, cliRun("", "-nope"), 2)
	must(t, cliRun("", "kv", "get"), 2)
	must(t, cliRun("", "kv", "get", "-nope", "x"), 2)
	must(t, cliRun("", "operator", "init", "extra"), 2)
	must(t, cliRun("", "pki", "issue"), 2)
	must(t, cliRun("", "audit", "verify"), 2)
	must(t, cliRun("", "audit", "verify", "missing.log"), 1)
	if r := must(t, cliRun("", "-ca", "x", "kv", "get", "a"), 1); !strings.Contains(r.errOut, "no server address") {
		t.Fatalf("missing addr: %s", r.errOut)
	}
	if r := must(t, cliRun("", "-addr", "127.0.0.1:1", "kv", "get", "a"), 1); !strings.Contains(r.errOut, "no CA") {
		t.Fatalf("missing CA: %s", r.errOut)
	}
	// Unreachable node: the error is reported, not hidden.
	dir := t.TempDir()
	must(t, cliRun("", "pki", "root-init", "-out", dir), 0)
	must(t, cliRun("", "-addr", "127.0.0.1:1", "-ca", dir+"/root.pem", "kv", "get", "a"), 1)
}
