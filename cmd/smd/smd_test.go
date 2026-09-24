package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hamad-tariq/SecretsManager/internal/audit"
	"github.com/hamad-tariq/SecretsManager/internal/pki"
)

type proc struct {
	id, api, rpc, dir string
	cmd               *exec.Cmd
	log               *bytes.Buffer
}

func freePort(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func writePEM(t *testing.T, path string, data []byte) {
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestThreeProcessCluster runs three real smd processes: form a cluster,
// init and unseal over the API, replicate a secret, and survive the leader
// dying in the middle of a rotation (the new leader finishes it).
func TestThreeProcessCluster(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the server binary")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "smd")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	root, _ := pki.NewRoot("test root", time.Hour)
	inter, _ := root.NewIntermediate("test intermediate", time.Hour)
	roots := x509.NewCertPool()
	roots.AddCert(root.Cert)
	caPath := filepath.Join(dir, "root.pem")
	writePEM(t, caPath, pki.EncodeCert(root.Cert))

	var procs []*proc
	for i, id := range []string{"node-1", "node-2", "node-3"} {
		p := &proc{id: id, api: freePort(t), rpc: freePort(t), dir: filepath.Join(dir, id), log: &bytes.Buffer{}}
		key, _ := pki.NewKey()
		cert, _ := inter.Issue(pki.Identity{Kind: pki.Node, Name: id}, key.Public(), time.Hour, "127.0.0.1")
		keyPEM, _ := pki.EncodeKey(key)
		certPath, keyPath := filepath.Join(dir, id+".pem"), filepath.Join(dir, id+".key")
		writePEM(t, certPath, append(pki.EncodeCert(cert), pki.EncodeCert(inter.Cert)...))
		writePEM(t, keyPath, keyPEM)

		args := []string{"-id", id, "-data", p.dir, "-raft-addr", freePort(t), "-rpc-addr", p.rpc,
			"-api-addr", p.api, "-cert", certPath, "-key", keyPath, "-ca", caPath, "-rotation-check", "200ms"}
		if i == 0 {
			args = append(args, "-bootstrap")
		} else {
			args = append(args, "-join", procs[0].rpc)
		}
		p.cmd = exec.Command(bin, args...)
		p.cmd.Stdout, p.cmd.Stderr = p.log, p.log
		if err := p.cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = p.cmd.Process.Kill(); _ = p.cmd.Wait() })
		procs = append(procs, p)
	}

	client := func(id pki.Identity) *http.Client {
		cfg := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}
		if id.Name != "" {
			key, _ := pki.NewKey()
			c, _ := inter.Issue(id, key.Public(), time.Hour)
			cfg.Certificates = []tls.Certificate{pki.TLSCertificate(c, key, inter.Cert)}
		}
		return &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg}}
	}
	call := func(c *http.Client, p *proc, method, path string, body any) (int, map[string]any) {
		var rd io.Reader
		if body != nil {
			j, _ := json.Marshal(body)
			rd = bytes.NewReader(j)
		}
		req, _ := http.NewRequest(method, "https://"+p.api+path, rd)
		resp, err := c.Do(req)
		if err != nil {
			return 0, nil
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	waitFor := func(what string, cond func() bool) {
		t.Helper()
		for deadline := time.Now().Add(30 * time.Second); !cond(); time.Sleep(100 * time.Millisecond) {
			if time.Now().After(deadline) {
				for _, p := range procs {
					t.Logf("--- %s log:\n%s", p.id, p.log.String())
				}
				t.Fatalf("timed out waiting for %s", what)
			}
		}
	}

	anon := client(pki.Identity{})
	for _, p := range procs {
		waitFor(p.id+" API up", func() bool { code, _ := call(anon, p, "GET", "/v1/sys/health?standbyok", nil); return code == 501 })
	}

	admin := client(pki.Identity{Kind: pki.Admin, Name: "alice"})
	var shares []any
	waitFor("init", func() bool {
		code, out := call(admin, procs[0], "POST", "/v1/sys/init", map[string]int{"shares": 3, "threshold": 2})
		if code == 200 {
			shares = out["shares"].([]any)
		}
		return code == 200
	})
	for _, p := range procs {
		for _, s := range shares[:2] {
			if code, out := call(admin, p, "POST", "/v1/sys/unseal", map[string]any{"share": s}); code != 200 {
				t.Fatalf("unseal %s: %d %v", p.id, code, out)
			}
		}
		if code, _ := call(anon, p, "GET", "/v1/sys/health?standbyok", nil); code != 200 {
			t.Fatalf("%s not healthy after unseal: %d", p.id, code)
		}
	}

	if code, out := call(admin, procs[1], "PUT", "/v1/kv/prod/db", map[string]string{"value": "s3cret"}); code != 200 {
		t.Fatalf("write via node-2: %d %v", code, out)
	}
	for _, p := range procs {
		if code, out := call(admin, p, "GET", "/v1/kv/prod/db", nil); code != 200 || out["value"] != "s3cret" {
			t.Fatalf("read via %s: %d %v", p.id, code, out)
		}
	}

	// A rotation through an HTTP hook. The hook holds the leader's first
	// "set" call; we kill that leader mid-rotation. The other two keep quorum,
	// and the new leader must finish the rotation with the same value.
	type hookCall struct{ node, step, value string }
	calls := make(chan hookCall, 16)
	release := make(chan struct{})
	var held atomic.Bool // only the first leader's set call is held
	hook := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, _ := pki.PeerIdentity(r.TLS)
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		calls <- hookCall{id.Name, body["step"], body["value"]}
		if body["step"] == "set" && held.CompareAndSwap(false, true) {
			<-release
		}
	}))
	hkey, _ := pki.NewKey()
	hcert, _ := inter.Issue(pki.Identity{Kind: pki.Service, Name: "billing"}, hkey.Public(), time.Hour)
	hook.TLS = pki.ServerTLS(pki.TLSCertificate(hcert, hkey, inter.Cert), roots)
	hook.Config.ErrorLog = log.New(io.Discard, "", 0)
	hook.StartTLS()
	defer hook.Close()
	defer close(release)

	if code, out := call(admin, procs[2], "PUT", "/v1/sys/rotation/app/billing-key", map[string]any{"interval": "720h",
		"plugin": "http", "params": map[string]string{"url": hook.URL + "/rotate", "identity": "svc/billing"}}); code != 200 {
		t.Fatalf("configure rotation: %d %v", code, out)
	}
	var first hookCall
	select {
	case first = <-calls:
	case <-time.After(30 * time.Second):
		t.Fatal("no hook call from the leader")
	}
	var victim *proc
	var survivors []*proc
	for _, p := range procs {
		if p.id == first.node {
			victim = p
		} else {
			survivors = append(survivors, p)
		}
	}
	if first.step != "set" || victim == nil {
		t.Fatalf("first hook call %+v", first)
	}
	_ = victim.cmd.Process.Kill()
	_ = victim.cmd.Wait()

	waitFor("rotation finished by the new leader", func() bool {
		code, out := call(admin, survivors[0], "GET", "/v1/sys/rotation/app/billing-key", nil)
		return code == 200 && out["last_rotated"] != nil && out["step"] == nil
	})
	var steps []hookCall
	for len(calls) > 0 {
		steps = append(steps, <-calls)
	}
	if len(steps) != 2 || steps[0].step != "set" || steps[1].step != "test" || steps[0].node == victim.id ||
		steps[0].value != first.value || steps[1].value != first.value {
		t.Fatalf("after failover the hook saw %+v (first: %+v)", steps, first)
	}
	if code, out := call(admin, survivors[1], "GET", "/v1/kv/app/billing-key", nil); code != 200 || out["value"] != first.value {
		t.Fatalf("rotated value: %d %v", code, out)
	}

	// Reads and writes keep working on the survivors.
	waitFor("write after the leader died", func() bool {
		code, _ := call(admin, survivors[1], "PUT", "/v1/kv/prod/db", map[string]string{"value": "v2"})
		return code == 200
	})
	if code, out := call(admin, survivors[0], "GET", "/v1/kv/prod/db", nil); code != 200 || out["value"] != "v2" {
		t.Fatalf("read after failover: %d %v", code, out)
	}

	for _, p := range procs {
		f, err := os.Open(filepath.Join(p.dir, "audit.log"))
		if err != nil {
			t.Fatal(err)
		}
		h, err := audit.Verify(f)
		f.Close()
		if err != nil || h.Seq == 0 {
			t.Fatalf("%s audit log: seq %d, %v", p.id, h.Seq, err)
		}
		data, _ := os.ReadFile(filepath.Join(p.dir, "audit.log"))
		if bytes.Contains(data, []byte("s3cret")) {
			t.Fatalf("%s audit log contains the secret", p.id)
		}
	}
}
