package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hamad-tariq/SecretsManager/internal/audit"
	"github.com/hamad-tariq/SecretsManager/internal/pki"
)

// syslogCollector is the off-host audit copy: an RFC 5425 receiver that
// keeps what each node sent, keyed by the syslog HOSTNAME (node ID).
type syslogCollector struct {
	ln    net.Listener
	mu    sync.Mutex
	lines map[string][]string
}

func newSyslogCollector(t *testing.T, cfg *tls.Config) *syslogCollector {
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	c := &syslogCollector{ln: ln, lines: map[string][]string{}}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				r := bufio.NewReader(conn)
				for {
					n, err := r.ReadString(' ')
					if err != nil {
						return
					}
					size, _ := strconv.Atoi(strings.TrimSpace(n))
					msg := make([]byte, size)
					if _, err := io.ReadFull(r, msg); err != nil {
						return
					}
					// <110>1 TIMESTAMP HOSTNAME smd - - - JSON
					f := strings.SplitN(string(msg), " ", 8)
					c.mu.Lock()
					c.lines[f[2]] = append(c.lines[f[2]], f[7])
					c.mu.Unlock()
				}
			}()
		}
	}()
	return c
}

// chain returns a node's forwarded log, deduplicated by sequence number.
func (c *syslogCollector) chain(node string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	bySeq := map[int]string{}
	for _, l := range c.lines[node] {
		var r struct {
			Seq int `json:"seq"`
		}
		_ = json.Unmarshal([]byte(l), &r)
		bySeq[r.Seq] = l
	}
	seqs := slices.Sorted(func(yield func(int) bool) {
		for s := range bySeq {
			if !yield(s) {
				return
			}
		}
	})
	var b strings.Builder
	for _, s := range seqs {
		b.WriteString(bySeq[s] + "\n")
	}
	return b.String()
}

func build(t *testing.T, dir, pkg, name string) string {
	bin := filepath.Join(dir, name)
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	if out, err := exec.Command("go", "build", "-o", bin, pkg).CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", pkg, err, out)
	}
	return bin
}

// TestDisasterRecovery is the iteration 11 exit criterion: destroy all three
// nodes, rebuild from a snapshot and the original shares, and verify every
// secret and the audit chain (from the off-host copy, since the nodes' own
// logs are gone). It drives the real smctl binary, as an operator would.
func TestDisasterRecovery(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the binaries")
	}
	dir := t.TempDir()
	smd, smctl := build(t, dir, ".", "smd"), build(t, dir, "../smctl", "smctl")

	root, _ := pki.NewRoot("dr root", time.Hour)
	inter, _ := root.NewIntermediate("dr intermediate", time.Hour)
	roots := x509.NewCertPool()
	roots.AddCert(root.Cert)
	caPath := filepath.Join(dir, "root.pem")
	writePEM(t, caPath, pki.EncodeCert(root.Cert))
	issue := func(id pki.Identity, hosts ...string) (certPath, keyPath string, c tls.Certificate) {
		key, _ := pki.NewKey()
		leaf, _ := inter.Issue(id, key.Public(), time.Hour, hosts...)
		keyPEM, _ := pki.EncodeKey(key)
		certPath, keyPath = filepath.Join(dir, id.Name+".pem"), filepath.Join(dir, id.Name+".key")
		writePEM(t, certPath, append(pki.EncodeCert(leaf), pki.EncodeCert(inter.Cert)...))
		writePEM(t, keyPath, keyPEM)
		return certPath, keyPath, pki.TLSCertificate(leaf, key, inter.Cert)
	}
	_, _, collectorCert := issue(pki.Identity{Kind: pki.Node, Name: "collector"}, "127.0.0.1")
	col := newSyslogCollector(t, pki.ServerTLS(collectorCert, roots))
	adminCert, adminKey, _ := issue(pki.Identity{Kind: pki.Admin, Name: "alice"})
	svcCert, svcKey, _ := issue(pki.Identity{Kind: pki.Service, Name: "orders-api"})

	// startCluster runs three fresh nodes in new data directories.
	startCluster := func(gen string) ([]*proc, string) {
		var procs []*proc
		var apis []string
		for i, id := range []string{"node-1", "node-2", "node-3"} {
			certPath, keyPath, _ := issue(pki.Identity{Kind: pki.Node, Name: id}, "127.0.0.1")
			p := &proc{id: id, api: freePort(t), rpc: freePort(t), dir: filepath.Join(dir, gen, id), log: &bytes.Buffer{}}
			args := []string{"-id", id, "-data", p.dir, "-raft-addr", freePort(t), "-rpc-addr", p.rpc, "-api-addr", p.api,
				"-cert", certPath, "-key", keyPath, "-ca", caPath, "-rotation-check", "200ms", "-audit-forward", col.ln.Addr().String()}
			if i == 0 {
				args = append(args, "-bootstrap")
			} else {
				args = append(args, "-join", procs[0].rpc)
			}
			p.cmd = exec.Command(smd, args...)
			p.cmd.Stdout, p.cmd.Stderr = p.log, p.log
			if err := p.cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = p.cmd.Process.Kill(); _ = p.cmd.Wait() })
			procs = append(procs, p)
			apis = append(apis, p.api)
		}
		return procs, strings.Join(apis, ",")
	}

	var procs []*proc
	var addrs string
	ctl := func(stdin string, cert, key string, args ...string) (string, error) {
		cmd := exec.Command(smctl, args...)
		cmd.Env = append(os.Environ(), "SM_ADDR="+addrs, "SM_CERT="+cert, "SM_KEY="+key, "SM_CA="+caPath)
		cmd.Stdin = strings.NewReader(stdin)
		var out, errOut bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errOut
		err := cmd.Run()
		if err != nil {
			err = fmt.Errorf("smctl %v: %v: %s", args, err, errOut.String())
		}
		return out.String(), err
	}
	admin := func(stdin string, args ...string) string {
		t.Helper()
		out, err := ctl(stdin, adminCert, adminKey, args...)
		if err != nil {
			for _, p := range procs {
				t.Logf("--- %s log:\n%s", p.id, p.log.String())
			}
			t.Fatal(err)
		}
		return out
	}
	eventually := func(what string, f func() error) {
		t.Helper()
		var err error
		for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
			if err = f(); err == nil {
				return
			}
		}
		t.Fatalf("%s: %v", what, err)
	}

	// ---- Day 1: a working cluster with data. ----
	procs, addrs = startCluster("before")
	var initOut struct{ Shares []string }
	eventually("init", func() error {
		out, err := ctl("", adminCert, adminKey, "operator", "init", "-shares", "3", "-threshold", "2")
		if err == nil {
			err = json.Unmarshal([]byte(out), &initOut)
		}
		return err
	})
	allInitialized := func() error { // every node has joined and sees the keyring
		var st map[string]map[string]any
		_ = json.Unmarshal([]byte(admin("", "operator", "status")), &st)
		for a, s := range st {
			if s["initialized"] != true {
				return fmt.Errorf("%s: %v", a, s)
			}
		}
		return nil
	}
	eventually("all nodes see the init", allInitialized)
	for _, s := range initOut.Shares[:2] {
		admin(s+"\n", "operator", "unseal")
	}
	want := map[string]string{"prod/orders/db": "db-v3", "prod/orders/api-key": "ak-1", "prod/billing/stripe": "sk-2"}
	for path, v := range map[string][]string{"prod/orders/db": {"db-v1", "db-v2", "db-v3"}, "prod/orders/api-key": {"ak-1"}} {
		for _, val := range v {
			admin(val, "kv", "put", path)
		}
	}
	admin("", "operator", "rotate") // later data under a second keyring term
	admin("sk-1", "kv", "put", "prod/billing/stripe")
	admin("sk-2", "kv", "put", "prod/billing/stripe")
	_ = os.WriteFile(filepath.Join(dir, "orders.json"), []byte(`{"name":"orders","rules":[{"path":"kv/prod/orders/*","capabilities":["read"]}]}`), 0o600)
	admin("", "policy", "write", "orders", filepath.Join(dir, "orders.json"))
	admin("", "identity", "bind", "svc/orders-api", "orders")
	admin("", "rotation", "set", "-interval", "720h", "-plugin", "random", "app/session-key")
	var rotated string
	eventually("first rotation", func() error {
		out, err := ctl("", adminCert, adminKey, "kv", "get", "-reveal", "app/session-key")
		rotated = out
		return err
	})
	want["app/session-key"] = rotated

	// Back up, and check the file offline.
	snapPath := filepath.Join(dir, "backup.json")
	admin("", "snapshot", "save", "-out", snapPath)
	if out := admin("", "snapshot", "verify", snapPath); !strings.HasPrefix(out, "ok: ") {
		t.Fatalf("verify: %s", out)
	}
	snap, _ := os.ReadFile(snapPath)
	for _, v := range []string{"db-v1", "db-v3", "sk-2", rotated} {
		if bytes.Contains(snap, []byte(v)) {
			t.Fatalf("snapshot contains plaintext %q", v)
		}
	}
	// Wait until the off-host copy of every node's audit log is complete
	// (same head as the local file), keep it, then lose everything.
	offHost := map[string]string{}
	localHeads := map[string]audit.Head{}
	for _, p := range procs {
		eventually(p.id+" audit log forwarded", func() error {
			f, err := os.Open(filepath.Join(p.dir, "audit.log"))
			if err != nil {
				return err
			}
			local, err := audit.Verify(f)
			f.Close()
			if err != nil {
				return err
			}
			remote, err := audit.Verify(strings.NewReader(col.chain(p.id)))
			if err != nil || remote != local {
				return fmt.Errorf("remote head %+v, local %+v, %v", remote, local, err)
			}
			offHost[p.id], localHeads[p.id] = col.chain(p.id), local
			return nil
		})
	}
	for _, p := range procs {
		_ = p.cmd.Process.Kill()
		_ = p.cmd.Wait()
		if err := os.RemoveAll(p.dir); err != nil {
			t.Fatal(err)
		}
	}

	// ---- The rebuild: new nodes, the snapshot, the original shares. ----
	procs, addrs = startCluster("after")
	eventually("new cluster up", func() error {
		_, err := ctl("", adminCert, adminKey, "snapshot", "restore", snapPath)
		return err
	})
	if _, err := ctl("", adminCert, adminKey, "snapshot", "restore", snapPath); err == nil {
		t.Fatal("a second restore over restored data was accepted")
	}
	eventually("all nodes see the restored keyring", allInitialized)
	for _, s := range initOut.Shares[1:] { // any 2 of the original 3
		admin(s+"\n", "operator", "unseal")
	}
	var status map[string]map[string]any
	_ = json.Unmarshal([]byte(admin("", "operator", "status")), &status)
	for addr, st := range status {
		if st["sealed"] != false || st["initialized"] != true {
			t.Fatalf("%s after unseal: %v", addr, st)
		}
	}

	// Every secret, its history, policies and rotation settings are back.
	for path, v := range want {
		if got := admin("", "kv", "get", "-reveal", path); got != v {
			t.Fatalf("%s: got %q, want %q", path, got, v)
		}
	}
	if got := admin("", "kv", "get", "-reveal", "-version", "1", "prod/orders/db"); got != "db-v1" {
		t.Fatalf("history: %q", got)
	}
	if out, err := ctl("", svcCert, svcKey, "kv", "get", "-reveal", "prod/orders/db"); err != nil || out != "db-v3" {
		t.Fatalf("service read after restore: %q %v", out, err)
	}
	if _, err := ctl("", svcCert, svcKey, "kv", "get", "prod/billing/stripe"); err == nil {
		t.Fatal("policy not restored: service read billing")
	}
	if out := admin("", "rotation", "get", "app/session-key"); !strings.Contains(out, `"plugin": "random"`) {
		t.Fatalf("rotation settings: %s", out)
	}
	admin("new", "kv", "put", "prod/after-restore") // writable
	if out := admin("", "operator", "members"); !strings.Contains(out, `"node-3"`) {
		t.Fatalf("members: %s", out)
	}

	// The destroyed cluster's audit trail survives off-host: complete (its
	// head matched the local file's before the disks were wiped) and intact.
	var saved bool
	for id, chain := range offHost {
		head, err := audit.Verify(strings.NewReader(chain))
		if err != nil || head != localHeads[id] || head.Seq < 2 {
			t.Fatalf("%s: off-host audit chain: %+v, %v", id, head, err)
		}
		for _, secretValue := range []string{"db-v1", "sk-2", rotated} {
			if strings.Contains(chain, secretValue) {
				t.Fatalf("%s: audit log contains a secret value", id)
			}
		}
		saved = saved || strings.Contains(chain, `"op":"sys.snapshot.save"`)
	}
	if !saved {
		t.Fatal("the snapshot itself isn't in the off-host audit trail")
	}
	// The new nodes' own logs verify too.
	for _, p := range procs {
		f, err := os.Open(filepath.Join(p.dir, "audit.log"))
		if err != nil {
			t.Fatal(err)
		}
		_, err = audit.Verify(f)
		f.Close()
		if err != nil {
			t.Fatalf("%s: new audit log: %v", p.id, err)
		}
	}
}
