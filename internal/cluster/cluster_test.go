package cluster

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/raft"

	"github.com/hamad-tariq/SecretsManager/internal/pki"
	"github.com/hamad-tariq/SecretsManager/internal/storage"
	"github.com/hamad-tariq/SecretsManager/internal/storage/storagetest"
)

type harness struct {
	t     testing.TB
	ca    *pki.CA
	roots *x509.CertPool
	dir   string
	cfgs  map[string]Config
	nodes map[string]*Node
	raft  *raft.Config
}

func newHarness(t testing.TB) *harness {
	root, err := pki.NewRoot("test root", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root.Cert)
	rc := raft.DefaultConfig()
	// Short enough for fast tests, long enough not to churn elections when
	// the machine is busy running other packages' tests in parallel.
	rc.HeartbeatTimeout = 300 * time.Millisecond
	rc.ElectionTimeout = 300 * time.Millisecond
	rc.LeaderLeaseTimeout = 200 * time.Millisecond
	rc.CommitTimeout = 5 * time.Millisecond
	h := &harness{t: t, ca: root, roots: roots, dir: t.TempDir(),
		cfgs: map[string]Config{}, nodes: map[string]*Node{}, raft: rc}
	t.Cleanup(func() {
		for _, n := range h.nodes {
			n.Shutdown()
		}
	})
	return h
}

func freeAddr(t testing.TB) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func (h *harness) cert(name string) tls.Certificate {
	key, _ := pki.NewKey()
	c, err := h.ca.Issue(pki.Identity{Kind: pki.Node, Name: name}, key.Public(), time.Hour, "127.0.0.1")
	if err != nil {
		h.t.Fatal(err)
	}
	return pki.TLSCertificate(c, key)
}

func (h *harness) start(id string, bootstrap bool) *Node {
	h.t.Helper()
	cfg, ok := h.cfgs[id]
	if !ok {
		cfg = Config{ID: id, RaftAddr: freeAddr(h.t), RPCAddr: freeAddr(h.t),
			DataDir: filepath.Join(h.dir, id), Cert: h.cert(id), Roots: h.roots,
			Raft: h.raft, Logger: hclog.NewNullLogger(), Timeout: 3 * time.Second}
		h.cfgs[id] = cfg
	}
	cfg.Bootstrap = bootstrap
	n, err := Start(cfg)
	if err != nil {
		h.t.Fatal(err)
	}
	h.nodes[id] = n
	return n
}

func (h *harness) stop(id string) {
	h.nodes[id].Shutdown()
	delete(h.nodes, id)
}

// cluster3 starts node-1 (bootstrap) and joins node-2 and node-3.
func (h *harness) cluster3() {
	h.t.Helper()
	n1 := h.start("node-1", true)
	h.waitLeader()
	for _, id := range []string{"node-2", "node-3"} {
		if err := h.start(id, false).Join(n1.cfg.RPCAddr); err != nil {
			h.t.Fatal(err)
		}
	}
	waitFor(h.t, "3 members", func() bool {
		v, _ := n1.Voters()
		return len(v) == 3 && len(n1.Members()) == 3
	})
}

func (h *harness) waitLeader() *Node {
	h.t.Helper()
	var leader *Node
	waitFor(h.t, "a ready leader", func() bool {
		for _, n := range h.nodes {
			if n.IsLeader() && n.ready.Load() {
				leader = n
				return true
			}
		}
		return false
	})
	return leader
}

func (h *harness) follower() *Node {
	for _, n := range h.nodes {
		if !n.IsLeader() {
			return n
		}
	}
	h.t.Fatal("no follower")
	return nil
}

func waitFor(t testing.TB, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestConformance(t *testing.T) {
	h := newHarness(t)
	h.cluster3()
	t.Run("via follower", func(t *testing.T) { storagetest.Conformance(t, h.follower()) })
	t.Run("via leader", func(t *testing.T) {
		l := h.waitLeader()
		for _, k := range []string{"a/1", "a/2", "a/sub/x", "b/1"} {
			_ = l.Delete(k)
		}
		storagetest.Conformance(t, l)
	})
}

func TestWritesVisibleOnEveryNode(t *testing.T) {
	h := newHarness(t)
	h.cluster3()
	for id, n := range h.nodes {
		if err := n.Put("k/"+id, []byte(id)); err != nil {
			t.Fatal(err)
		}
	}
	for _, reader := range h.nodes {
		for id := range h.nodes {
			// Linearizable: a completed write is visible immediately, from any node.
			v, err := reader.Get("k/" + id)
			if err != nil || string(v) != id {
				t.Fatalf("%s reading k/%s: %q %v", reader.cfg.ID, id, v, err)
			}
		}
	}
}

func TestLeaderFailoverLosesNoAckedWrite(t *testing.T) {
	h := newHarness(t)
	h.cluster3()
	leader := h.waitLeader()
	var survivors []*Node
	for _, n := range h.nodes {
		if n != leader {
			survivors = append(survivors, n)
		}
	}

	var (
		mu    sync.Mutex
		acked []string
		wg    sync.WaitGroup
		count atomic.Int64
		stop  = make(chan struct{})
	)
	for w := range 4 {
		wg.Go(func() {
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				key := fmt.Sprintf("w%d/%d", w, i)
				if survivors[w%2].Put(key, []byte(key)) == nil {
					mu.Lock()
					acked = append(acked, key)
					mu.Unlock()
					count.Add(1)
				}
			}
		})
	}
	waitFor(t, "writes before failover", func() bool { return count.Load() > 100 })
	h.stop(leader.cfg.ID)
	before := count.Load()
	waitFor(t, "writes after failover", func() bool { return count.Load() > before+100 })
	close(stop)
	wg.Wait()

	newLeader := h.waitLeader()
	if newLeader == leader {
		t.Fatal("leader did not change")
	}
	for _, k := range acked {
		v, err := survivors[0].Get(k)
		if err != nil || string(v) != k {
			t.Fatalf("acknowledged write %s lost: %q %v", k, v, err)
		}
	}
	t.Logf("%d acknowledged writes, all present after failover", len(acked))
}

func TestMinorityRefusesWritesAndReads(t *testing.T) {
	h := newHarness(t)
	h.cluster3()
	leader := h.waitLeader()
	if err := leader.Put("before", []byte("x")); err != nil {
		t.Fatal(err)
	}
	for id, n := range h.nodes {
		if n != leader {
			h.stop(id)
		}
	}
	if err := leader.Put("after", []byte("x")); !errors.Is(err, ErrNoLeader) {
		t.Fatalf("write without quorum: got %v", err)
	}
	if _, err := leader.Get("before"); !errors.Is(err, ErrNoLeader) {
		t.Fatalf("read without quorum must not return possibly stale data: got %v", err)
	}
}

func TestRestartAllKeepsState(t *testing.T) {
	h := newHarness(t)
	h.raft.SnapshotThreshold = 20 // force snapshots so restart exercises Restore
	h.raft.TrailingLogs = 5
	h.raft.SnapshotInterval = 100 * time.Millisecond
	h.cluster3()
	leader := h.waitLeader()
	for i := range 100 {
		if err := leader.Put(fmt.Sprintf("k/%03d", i), []byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(500 * time.Millisecond) // let snapshots happen

	ids := []string{"node-1", "node-2", "node-3"}
	for _, id := range ids {
		h.stop(id)
	}
	for _, id := range ids {
		h.start(id, id == "node-1") // bootstrap is a no-op with existing state
	}
	l := h.waitLeader()
	keys, err := l.List("k/")
	if err != nil || len(keys) != 100 {
		t.Fatalf("after restart: %d keys, %v", len(keys), err)
	}
	if v, _ := h.follower().Get("k/042"); !bytes.Equal(v, []byte{42}) {
		t.Fatalf("k/042 = %v", v)
	}
	if len(l.Members()) != 3 {
		t.Fatalf("members after restart: %v", l.Members())
	}
}

func TestRemoveNode(t *testing.T) {
	h := newHarness(t)
	h.cluster3()
	f := h.follower()
	var victim string
	for id := range h.nodes {
		if id != f.cfg.ID && !h.nodes[id].IsLeader() {
			victim = id
		}
	}
	if err := f.Remove(victim); err != nil { // issued on a follower: forwarded
		t.Fatal(err)
	}
	h.stop(victim)
	l := h.waitLeader()
	voters, _ := l.Voters()
	if len(voters) != 2 || len(l.Members()) != 2 {
		t.Fatalf("after remove: voters %v members %v", voters, l.Members())
	}
	if err := f.Put("still-works", []byte("x")); err != nil {
		t.Fatalf("2-node cluster should still have quorum: %v", err)
	}
}

func TestIdentityChecks(t *testing.T) {
	h := newHarness(t)
	h.cluster3()
	target := h.nodes["node-1"].cfg.RPCAddr

	// Node ID must match its own certificate.
	cfg := Config{ID: "node-4", RaftAddr: freeAddr(t), RPCAddr: freeAddr(t), DataDir: t.TempDir(),
		Cert: h.cert("node-5"), Roots: h.roots}
	if _, err := Start(cfg); err == nil {
		t.Fatal("started with a certificate for a different node")
	}
	if _, err := Start(Config{ID: "x"}); err == nil {
		t.Fatal("started without a certificate")
	}

	post := func(cert tls.Certificate, body string) (int, error) {
		c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
			TLSClientConfig: pki.ClientTLS(cert, h.roots)}}
		resp, err := c.Post("https://"+target+"/cluster/join", "application/json", bytes.NewBufferString(body))
		if err != nil {
			return 0, err
		}
		resp.Body.Close()
		return resp.StatusCode, nil
	}

	// A node certificate may not join under another node's name.
	code, err := post(h.cert("node-5"), `{"id":"node-9","raft_addr":"127.0.0.1:1","rpc_addr":"127.0.0.1:2"}`)
	if err != nil || code != http.StatusForbidden {
		t.Fatalf("join as another node: %d %v", code, err)
	}
	// Malformed request.
	if code, _ := post(h.cert("node-5"), `{"id":`); code != http.StatusBadRequest {
		t.Fatalf("malformed join: %d", code)
	}

	// A service certificate cannot talk to the cluster ports at all.
	key, _ := pki.NewKey()
	svc, _ := h.ca.Issue(pki.Identity{Kind: pki.Service, Name: "orders-api"}, key.Public(), time.Hour)
	if _, err := post(pki.TLSCertificate(svc, key), `{}`); err == nil {
		t.Fatal("service certificate reached the cluster RPC port")
	}
	conn, err := tls.Dial("tcp", h.nodes["node-1"].cfg.RaftAddr, pki.ClientTLS(pki.TLSCertificate(svc, key), h.roots))
	if err == nil {
		// TLS 1.3: the client may finish first; the server's rejection shows on first read.
		_, err = conn.Read(make([]byte, 1))
		conn.Close()
	}
	if err == nil {
		t.Fatal("service certificate reached the Raft port")
	}
}

func TestForwardedWriteRejectsMemberOp(t *testing.T) {
	h := newHarness(t)
	h.cluster3()
	f := h.follower()
	err := f.withLeader(false,
		func() error { return f.leaderApply(command{Op: "member", ID: "evil", RPC: "x"}) },
		func(addr string) error {
			return f.call(addr, "/cluster/apply", command{Op: "member", ID: "evil", RPC: "x"}, nil)
		})
	if err == nil {
		t.Fatal("member op accepted via apply")
	}
	if _, ok := h.waitLeader().Members()["evil"]; ok {
		t.Fatal("rogue member registered")
	}
}

// BenchmarkPut measures replicated write throughput on a local 3-node cluster.
func BenchmarkPut(b *testing.B) {
	h := newHarness(b)
	h.cluster3()
	l := h.waitLeader()
	val := bytes.Repeat([]byte("x"), 256)
	var i atomic.Int64
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if err := l.Put(fmt.Sprintf("bench/%d", i.Add(1)), val); err != nil {
				b.Error(err)
			}
		}
	})
}

var _ storage.Backend = (*Node)(nil)

func TestDumpRestoreAndStepDown(t *testing.T) {
	src := newHarness(t)
	src.cluster3()
	f := src.follower()
	for i := range 50 {
		if err := f.Put(fmt.Sprintf("k/%02d", i), []byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	dump, err := f.Dump() // via a follower: forwarded, consistent
	if err != nil || len(dump) != 50 || dump["k/07"][0] != 7 {
		t.Fatalf("dump: %d keys, %v", len(dump), err)
	}

	// A new, empty cluster takes it; every node gets it through Raft.
	dst := newHarness(t)
	dst.cluster3()
	if err := dst.follower().Restore(dump); err != nil {
		t.Fatal(err)
	}
	for id, n := range dst.nodes {
		waitFor(t, id+" restored", func() bool { d, _ := n.fsm.data.Get("k/49"); return len(d) == 1 && d[0] == 49 })
	}
	if len(dst.waitLeader().Members()) != 3 {
		t.Fatal("restore replaced the member directory")
	}
	// A cluster with data refuses, from leader or follower.
	if err := dst.follower().Restore(dump); !errors.Is(err, ErrNotEmpty) {
		t.Fatalf("restore over data: %v", err)
	}
	if err := dst.waitLeader().Restore(dump); !errors.Is(err, ErrNotEmpty) {
		t.Fatalf("restore over data on leader: %v", err)
	}

	// Step-down asked of a follower moves leadership elsewhere.
	old := src.waitLeader()
	before := old.LeaderChanges()
	if err := src.follower().StepDown(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "new leader", func() bool { l := src.waitLeader(); return l != old })
	if old.LeaderChanges() == before {
		t.Fatal("leader change not counted")
	}
	if err := f.Put("after-step-down", []byte("x")); err != nil {
		t.Fatal(err)
	}
}

// A removed node's certificate stays valid, so the cluster must keep it out
// by ID: no rejoining, no RPC. A replacement joins under a new ID.
func TestRemovedNodeStaysOut(t *testing.T) {
	h := newHarness(t)
	h.cluster3()
	leader := h.waitLeader()
	var victim string
	for id, n := range h.nodes {
		if n != leader {
			victim = id
			break
		}
	}
	if err := leader.Remove(victim); err != nil {
		t.Fatal(err)
	}
	h.stop(victim)

	// The same certificate (and data) comes back.
	back := h.start(victim, false)
	back.timeout = time.Second
	if err := back.Join(leader.cfg.RPCAddr); err == nil || !strings.Contains(err.Error(), "removed") {
		t.Fatalf("removed node rejoined: %v", err)
	}
	var res readResponse
	if err := back.call(leader.cfg.RPCAddr, "/cluster/read", readRequest{Op: "dump"}, &res); err == nil || len(res.Data) > 0 {
		t.Fatalf("removed node read the data: %v", err)
	}
	if err := back.call(leader.cfg.RPCAddr, "/cluster/apply", command{Op: "put", Key: "evil", Value: []byte("x")}, nil); err == nil {
		t.Fatal("removed node wrote through RPC")
	}
	if _, err := leader.Get("evil"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatal("the write landed")
	}
	h.stop(victim)

	// A replacement with a new ID joins normally.
	if err := h.start("node-4", false).Join(leader.cfg.RPCAddr); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "3 voters again", func() bool { v, _ := leader.Voters(); return len(v) == 3 })
	if err := h.nodes["node-4"].Put("after-replace", []byte("ok")); err != nil {
		t.Fatal(err)
	}
}
