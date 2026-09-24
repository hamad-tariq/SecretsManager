package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/hamad-tariq/SecretsManager/internal/cluster"
	"github.com/hamad-tariq/SecretsManager/internal/pki"
	"github.com/hamad-tariq/SecretsManager/internal/storage"
)

// fakeCluster is a one-node "cluster" over the env's in-memory storage.
type fakeCluster struct {
	mu      sync.Mutex
	raw     *storage.Inmem
	leader  bool
	removed []string
	stepped int
}

func (f *fakeCluster) IsLeader() bool            { f.mu.Lock(); defer f.mu.Unlock(); return f.leader }
func (f *fakeCluster) Leader() string            { return "node-1" }
func (f *fakeCluster) Voters() ([]string, error) { return []string{"node-1"}, nil }
func (f *fakeCluster) Members() map[string]string {
	return map[string]string{"node-1": "127.0.0.1:8202"}
}
func (f *fakeCluster) Remove(id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removed = append(f.removed, id)
	return nil
}
func (f *fakeCluster) StepDown() error                  { f.mu.Lock(); defer f.mu.Unlock(); f.stepped++; return nil }
func (f *fakeCluster) Dump() (map[string][]byte, error) { return f.raw.Snapshot(), nil }
func (f *fakeCluster) Restore(d map[string][]byte) error {
	if len(f.raw.Snapshot()) > 0 {
		return cluster.ErrNotEmpty
	}
	f.raw.Replace(d)
	return nil
}

func (e *env) raw(c *http.Client, method, path string, body []byte) (int, []byte) {
	e.t.Helper()
	req, _ := http.NewRequest(method, e.url+path, bytes.NewReader(body))
	resp, err := c.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func TestHealthCodes(t *testing.T) {
	e := newEnv(t)
	anon := e.client(pki.Identity{})
	e.expect(anon, "GET", "/v1/sys/health", nil, 501)
	admin := e.ready()
	if out := e.expect(anon, "GET", "/v1/sys/health", nil, 200); out["leader"] != true {
		t.Fatalf("leader health: %v", out)
	}
	e.cluster.mu.Lock()
	e.cluster.leader = false
	e.cluster.mu.Unlock()
	if out := e.expect(anon, "GET", "/v1/sys/health", nil, 429); out["standby"] != true || out["sealed"] != false {
		t.Fatalf("standby health: %v", out)
	}
	e.expect(anon, "GET", "/v1/sys/health?standbyok", nil, 200)
	e.expect(admin, "POST", "/v1/sys/seal", nil, 200)
	e.expect(anon, "GET", "/v1/sys/health?standbyok", nil, 503)
}

func TestSnapshotRestoreIntoNewCluster(t *testing.T) {
	src := newEnv(t)
	admin := src.ready()
	src.expect(admin, "PUT", "/v1/kv/prod/db", map[string]string{"value": canary}, 200)
	src.expect(admin, "PUT", "/v1/kv/prod/db", map[string]string{"value": "v2"}, 200)
	src.expect(admin, "POST", "/v1/sys/rotate", nil, 200) // data under two keyring terms
	src.expect(admin, "PUT", "/v1/kv/prod/api", map[string]string{"value": "k"}, 200)

	src.expect(src.client(orders), "GET", "/v1/sys/snapshot", nil, 403)
	code, snap := src.raw(admin, "GET", "/v1/sys/snapshot", nil)
	if code != 200 || bytes.Contains(snap, []byte(canary)) {
		t.Fatalf("snapshot: %d, plaintext inside: %v", code, bytes.Contains(snap, []byte(canary)))
	}

	// A new, empty cluster: restore, then unseal with the ORIGINAL shares.
	dst := newEnv(t)
	anon := dst.client(pki.Identity{})
	if c, _ := dst.raw(anon, "POST", "/v1/sys/snapshot/restore", snap); c != 401 {
		t.Fatalf("restore without a certificate: %d", c)
	}
	if c, _ := dst.raw(dst.client(orders), "POST", "/v1/sys/snapshot/restore", snap); c != 403 {
		t.Fatalf("restore by a service: %d", c)
	}
	tampered := bytes.Replace(snap, []byte(`"keys":`), []byte(`"keys":1`), 1)
	if c, body := dst.raw(dst.client(rootAdmin), "POST", "/v1/sys/snapshot/restore", tampered); c != 400 {
		t.Fatalf("tampered snapshot: %d %s", c, body)
	}
	c, body := dst.raw(dst.client(rootAdmin), "POST", "/v1/sys/snapshot/restore", snap)
	if c != 200 || !strings.Contains(string(body), `"sealed":true`) {
		t.Fatalf("restore: %d %s", c, body)
	}
	if c, _ := dst.raw(dst.client(rootAdmin), "POST", "/v1/sys/snapshot/restore", snap); c != 409 {
		t.Fatalf("second restore: %d", c)
	}

	// The shares from the source's init unseal the restored cluster.
	for _, sh := range src.shares[:2] {
		dst.expect(dst.client(shareHolder), "POST", "/v1/sys/unseal", map[string]string{"share": sh}, 200)
	}
	dadmin := dst.client(rootAdmin) // the root admin came along in the keyring
	if got := dst.expect(dadmin, "GET", "/v1/kv/prod/db", nil, 200); got["value"] != "v2" || got["version"] != float64(2) {
		t.Fatalf("restored secret: %v", got)
	}
	if got := dst.expect(dadmin, "GET", "/v1/kv/prod/db?version=1", nil, 200); got["value"] != canary {
		t.Fatalf("restored history: %v", got)
	}
	dst.expect(dadmin, "GET", "/v1/kv/prod/api", nil, 200)
}

func TestClusterRoutesAndMetrics(t *testing.T) {
	e := newEnv(t)
	admin := e.ready()
	svc := e.client(orders)
	if out := e.expect(admin, "GET", "/v1/sys/cluster", nil, 200); out["leader"] != "node-1" {
		t.Fatalf("cluster: %v", out)
	}
	e.expect(svc, "DELETE", "/v1/sys/cluster/members/node-3", nil, 403)
	e.expect(admin, "DELETE", "/v1/sys/cluster/members/Bad!", nil, 400)
	e.expect(admin, "DELETE", "/v1/sys/cluster/members/node-3", nil, 200)
	e.expect(admin, "POST", "/v1/sys/cluster/step-down", nil, 200)
	if len(e.cluster.removed) != 1 || e.cluster.removed[0] != "node-3" || e.cluster.stepped != 1 {
		t.Fatalf("removed %v stepped %d", e.cluster.removed, e.cluster.stepped)
	}

	e.expect(svc, "GET", "/v1/kv/nope", nil, 403)
	e.expect(svc, "GET", "/v1/sys/metrics", nil, 403)
	// A scraper identity gets read on sys/metrics and nothing else.
	e.expect(admin, "PUT", "/v1/sys/policies/metrics", `{"name":"metrics","rules":[{"path":"sys/metrics","capabilities":["read"]}]}`, 200)
	e.expect(admin, "PUT", "/v1/sys/bindings/svc/prometheus", map[string]any{"policies": []string{"metrics"}}, 200)
	code, body := e.raw(e.client(pki.Identity{Kind: pki.Service, Name: "prometheus"}), "GET", "/v1/sys/metrics", nil)
	m := string(body)
	for _, want := range []string{
		"# TYPE sm_requests_total counter",
		`sm_requests_total{op="kv.read",code="403"} 1`,
		`sm_requests_total{op="sys.cluster.remove",code="200"} 1`,
		"sm_sealed 0",
		"sm_leader 1",
		`sm_request_duration_seconds_count{op="sys.init"} 1`,
	} {
		if !strings.Contains(m, want) {
			t.Errorf("metrics missing %q", want)
		}
	}
	if code != 200 || t.Failed() {
		t.Fatalf("metrics %d:\n%s", code, m)
	}
	var ignored map[string]any
	if json.Unmarshal(body, &ignored) == nil {
		t.Fatal("metrics should be text, not JSON")
	}
}
