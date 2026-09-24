// Package cluster replicates a storage.Backend across nodes with Raft.
//
// Every node runs two mTLS listeners, both accepting only node certificates:
//   - RaftAddr: Raft's own traffic.
//   - RPCAddr: a small HTTPS API for joining and for followers forwarding
//     writes and consistent reads to the leader.
//
// Reads are linearizable: they are served by the leader after it confirms it
// is still leader (VerifyLeader) and has applied everything from earlier terms
// (a Barrier run once when it gains leadership).
package cluster

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/raft"
	raftboltdb "github.com/hashicorp/raft-boltdb/v2"

	"github.com/hamad-tariq/SecretsManager/internal/pki"
	"github.com/hamad-tariq/SecretsManager/internal/storage"
)

const joinTimeout = 30 * time.Second

var (
	ErrNoLeader = errors.New("cluster: no leader available")
	// errRetry marks a transient condition (election, leader not ready).
	errRetry = errors.New("cluster: retry")
)

type Config struct {
	ID        string          // must equal the name in the node certificate
	RaftAddr  string          // host:port, bound and advertised to peers
	RPCAddr   string          // host:port for join and forwarding
	DataDir   string          // Raft log, stable store and snapshots
	Cert      tls.Certificate // node certificate (pki.Node identity) + chain
	Roots     *x509.CertPool  // root CA that signed every node certificate
	Bootstrap bool            // first node of a new cluster

	// Optional.
	Raft    *raft.Config  // overrides (tests use short timeouts); LocalID, Logger, NotifyCh are set here
	Logger  hclog.Logger  // default: warnings and above to stderr
	Timeout time.Duration // how long an operation waits for a leader; default 10s
}

type Node struct {
	cfg     Config
	raft    *raft.Raft
	fsm     *fsm
	store   *raftboltdb.BoltStore
	trans   *raft.NetworkTransport
	rpc     *http.Server
	client  *http.Client
	logger  hclog.Logger
	timeout time.Duration

	ready    atomic.Bool   // leader has applied all earlier entries
	gen      atomic.Uint64 // leadership change counter
	notifyCh chan bool
	done     chan struct{}
	wg       sync.WaitGroup
}

var _ storage.Backend = (*Node)(nil)

// Start opens the node's data and joins Raft. A Bootstrap node forms a new
// single-node cluster (only if it has no existing state); others wait to be
// added via Join.
func Start(cfg Config) (*Node, error) {
	if err := checkNodeCert(cfg); err != nil {
		return nil, err
	}
	logger := cfg.Logger
	if logger == nil {
		logger = hclog.New(&hclog.LoggerOptions{Name: "cluster", Level: hclog.Warn})
	}
	n := &Node{cfg: cfg, fsm: newFSM(), logger: logger, timeout: cfg.Timeout,
		notifyCh: make(chan bool, 16), done: make(chan struct{})}
	if n.timeout == 0 {
		n.timeout = 10 * time.Second
	}

	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, err
	}
	var err error
	if n.store, err = raftboltdb.New(raftboltdb.Options{Path: filepath.Join(cfg.DataDir, "raft.db")}); err != nil {
		return nil, err
	}
	snaps, err := raft.NewFileSnapshotStoreWithLogger(cfg.DataDir, 2, logger)
	if err != nil {
		_ = n.store.Close()
		return nil, err
	}

	serverTLS, clientTLS := n.tlsConfigs()
	// Raft itself only talks to members (or, on a brand-new node, to whoever
	// the leader is when it first replicates here).
	raftTLS := serverTLS.Clone()
	raftTLS.VerifyConnection = func(cs tls.ConnectionState) error {
		if err := serverTLS.VerifyConnection(cs); err != nil {
			return err
		}
		if id, _ := pki.PeerIdentity(&cs); !n.fsm.admits(id.Name) {
			return fmt.Errorf("cluster: node %s is not a member", id.Name)
		}
		return nil
	}
	ln, err := tls.Listen("tcp", cfg.RaftAddr, raftTLS)
	if err != nil {
		_ = n.store.Close()
		return nil, err
	}
	n.trans = raft.NewNetworkTransportWithLogger(&streamLayer{Listener: ln, tls: clientTLS}, 3, 10*time.Second, logger)

	rc := raft.DefaultConfig()
	if cfg.Raft != nil {
		c := *cfg.Raft
		rc = &c
	}
	rc.LocalID = raft.ServerID(cfg.ID)
	rc.Logger = logger
	rc.NotifyCh = n.notifyCh

	if n.raft, err = raft.NewRaft(rc, n.fsm, n.store, n.store, snaps, n.trans); err != nil {
		_ = n.trans.Close()
		_ = n.store.Close()
		return nil, err
	}
	if cfg.Bootstrap {
		f := n.raft.BootstrapCluster(raft.Configuration{Servers: []raft.Server{
			{ID: rc.LocalID, Address: raft.ServerAddress(cfg.RaftAddr)},
		}})
		if err := f.Error(); err != nil && !errors.Is(err, raft.ErrCantBootstrap) {
			n.Shutdown()
			return nil, err
		}
	}

	n.client = &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: clientTLS}}
	rpcLn, err := tls.Listen("tcp", cfg.RPCAddr, serverTLS)
	if err != nil {
		n.Shutdown()
		return nil, err
	}
	n.rpc = &http.Server{Handler: n.rpcHandler(), ReadHeaderTimeout: 5 * time.Second}
	n.wg.Go(func() { _ = n.rpc.Serve(rpcLn) })
	n.wg.Go(n.watchLeadership)
	return n, nil
}

func checkNodeCert(cfg Config) error {
	if cfg.Cert.Leaf == nil {
		return errors.New("cluster: Cert.Leaf must be set")
	}
	id, err := pki.IdentityFromCert(cfg.Cert.Leaf)
	if err != nil || id != (pki.Identity{Kind: pki.Node, Name: cfg.ID}) {
		return fmt.Errorf("cluster: certificate identity %v does not match node %q", id, cfg.ID)
	}
	return nil
}

// tlsConfigs returns mTLS configs that only accept peers holding node
// certificates. Removed nodes (whose certificates stay valid) are kept out by
// ID: the Raft listener admits members only (see Start), and the RPC handlers
// check membership, with join refusing removed IDs with a clear message.
func (n *Node) tlsConfigs() (server, client *tls.Config) {
	onlyNodes := func(cs tls.ConnectionState) error {
		id, err := pki.PeerIdentity(&cs)
		if err != nil || id.Kind != pki.Node {
			return fmt.Errorf("cluster: peer is not a node (%v)", id)
		}
		return nil
	}
	server = pki.ServerTLS(n.cfg.Cert, n.cfg.Roots)
	server.VerifyConnection = onlyNodes
	client = pki.ClientTLS(n.cfg.Cert, n.cfg.Roots)
	client.VerifyConnection = onlyNodes
	return server, client
}

type streamLayer struct {
	net.Listener
	tls *tls.Config
}

func (s *streamLayer) Dial(addr raft.ServerAddress, timeout time.Duration) (net.Conn, error) {
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: timeout}, Config: s.tls}
	return d.Dial("tcp", string(addr))
}

// watchLeadership marks the node ready to serve consistent reads once, after
// gaining leadership, it has applied every earlier entry and registered its
// own RPC address.
func (n *Node) watchLeadership() {
	for {
		select {
		case <-n.done:
			return
		case isLeader := <-n.notifyCh:
			gen := n.gen.Add(1)
			n.ready.Store(false)
			if isLeader {
				n.wg.Go(func() { n.establish(gen) })
			}
		}
	}
}

// establish retries until it succeeds or leadership changes; a leader that
// gave up here would refuse reads for the rest of its term.
func (n *Node) establish(gen uint64) {
	for n.gen.Load() == gen {
		if n.tryEstablish() == nil {
			if n.gen.Load() == gen {
				n.ready.Store(true)
			}
			return
		}
		select {
		case <-n.done:
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func (n *Node) tryEstablish() error {
	if err := n.raft.Barrier(n.timeout).Error(); err != nil {
		return err
	}
	if addr, ok := n.fsm.memberRPC(n.cfg.ID); !ok || addr != n.cfg.RPCAddr {
		return n.applyLocal(command{Op: "member", ID: n.cfg.ID, RPC: n.cfg.RPCAddr})
	}
	return nil
}

func (n *Node) applyLocal(c command) error {
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	f := n.raft.Apply(b, n.timeout)
	if err := f.Error(); err != nil {
		if errors.Is(err, raft.ErrNotLeader) || errors.Is(err, raft.ErrLeadershipLost) {
			// The entry may or may not have committed. Retrying is safe for
			// a lone writer (put/delete are idempotent) but can reorder two
			// concurrent writers on one key; the KV layer (iteration 6) adds
			// check-and-set for callers that care.
			return errRetry
		}
		return err
	}
	if err, ok := f.Response().(error); ok {
		return err
	}
	return nil
}

// withLeader runs local on the leader or remote against the leader's RPC
// address, retrying through elections until the timeout.
func (n *Node) withLeader(consistentRead bool, local func() error, remote func(rpcAddr string) error) error {
	deadline := time.Now().Add(n.timeout)
	for {
		err := n.tryLeader(consistentRead, local, remote)
		if !errors.Is(err, errRetry) {
			return err
		}
		if time.Now().After(deadline) {
			return ErrNoLeader
		}
		select {
		case <-n.done:
			return ErrNoLeader
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func (n *Node) tryLeader(consistentRead bool, local func() error, remote func(string) error) error {
	if n.raft.State() == raft.Leader {
		if consistentRead {
			if !n.ready.Load() || n.raft.VerifyLeader().Error() != nil {
				return errRetry
			}
		}
		return local()
	}
	_, id := n.raft.LeaderWithID()
	addr, ok := n.fsm.memberRPC(string(id))
	if id == "" || !ok {
		return errRetry
	}
	return remote(addr)
}

func (n *Node) apply(c command) error {
	return n.withLeader(false,
		func() error { return n.leaderApply(c) },
		func(addr string) error { return n.call(addr, "/cluster/apply", c, nil) })
}

// leaderApply runs on the leader for local and forwarded writes.
func (n *Node) leaderApply(c command) error {
	switch c.Op {
	case "put", "put_if", "delete", "restore":
	case "unmember":
		if err := n.raft.RemoveServer(raft.ServerID(c.ID), 0, n.timeout).Error(); err != nil {
			if errors.Is(err, raft.ErrNotLeader) || errors.Is(err, raft.ErrLeadershipLost) {
				return errRetry
			}
			return err
		}
	default:
		// "member" is only written by join (identity-checked) and establish.
		return fmt.Errorf("cluster: op %q not allowed here", c.Op)
	}
	return n.applyLocal(c)
}

// Put, Delete, Get and List make a Node a storage.Backend.

func (n *Node) Put(key string, value []byte) error {
	return n.apply(command{Op: "put", Key: key, Value: value})
}

// PutIf is atomic on the leader. After a leadership change mid-write it may
// report ErrConflict for a write that did commit; callers re-read and decide.
func (n *Node) PutIf(key string, value, expected []byte) error {
	return n.apply(command{Op: "put_if", Key: key, Value: value, Expected: expected, Absent: expected == nil})
}

func (n *Node) Delete(key string) error {
	return n.apply(command{Op: "delete", Key: key})
}

func (n *Node) Get(key string) ([]byte, error) {
	var res readResponse
	err := n.withLeader(true,
		func() (err error) { res, err = n.readLocal(readRequest{Op: "get", Key: key}); return err },
		func(addr string) error { return n.call(addr, "/cluster/read", readRequest{Op: "get", Key: key}, &res) })
	if err != nil {
		return nil, err
	}
	if !res.Found {
		return nil, storage.ErrNotFound
	}
	return res.Value, nil
}

func (n *Node) List(prefix string) ([]string, error) {
	var res readResponse
	err := n.withLeader(true,
		func() (err error) { res, err = n.readLocal(readRequest{Op: "list", Key: prefix}); return err },
		func(addr string) error {
			return n.call(addr, "/cluster/read", readRequest{Op: "list", Key: prefix}, &res)
		})
	return res.Keys, err
}

func (n *Node) readLocal(r readRequest) (readResponse, error) {
	switch r.Op {
	case "get":
		v, err := n.fsm.data.Get(r.Key)
		if errors.Is(err, storage.ErrNotFound) {
			return readResponse{}, nil
		}
		return readResponse{Found: err == nil, Value: v}, err
	case "list":
		keys, err := n.fsm.data.List(r.Key)
		return readResponse{Keys: keys}, err
	case "dump":
		return readResponse{Data: n.fsm.data.Snapshot()}, nil
	}
	return readResponse{}, fmt.Errorf("cluster: unknown read op %q", r.Op)
}

// Join asks the cluster reachable at any member's RPC address to add this
// node. It waits up to joinTimeout: at startup the seed or leader may still
// be coming up or electing.
func (n *Node) Join(seedRPC string) error {
	req := joinRequest{ID: n.cfg.ID, RaftAddr: n.cfg.RaftAddr, RPCAddr: n.cfg.RPCAddr}
	addr := seedRPC
	deadline := time.Now().Add(max(n.timeout, joinTimeout))
	for {
		var res joinResponse
		err := n.call(addr, "/cluster/join", req, &res)
		if err == nil {
			return nil
		}
		if !errors.Is(err, errRetry) || time.Now().After(deadline) {
			return fmt.Errorf("cluster: join via %s: %w", addr, err)
		}
		if res.Leader != "" {
			addr = res.Leader // seed was a follower: go to the leader directly
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// Dump returns a consistent copy of all data (as stored: barrier ciphertext
// plus the sealed keyring), read on the leader at a single point in time.
func (n *Node) Dump() (map[string][]byte, error) {
	var res readResponse
	err := n.withLeader(true,
		func() (err error) { res, err = n.readLocal(readRequest{Op: "dump"}); return err },
		func(addr string) error { return n.call(addr, "/cluster/read", readRequest{Op: "dump"}, &res) })
	if res.Data == nil {
		res.Data = map[string][]byte{}
	}
	return res.Data, err
}

// Restore loads a Dump into a cluster that has no data yet (ErrNotEmpty
// otherwise). It replicates like any write; the member directory is kept.
func (n *Node) Restore(data map[string][]byte) error {
	err := n.apply(command{Op: "restore", Data: data})
	if err != nil && strings.Contains(err.Error(), ErrNotEmpty.Error()) {
		return ErrNotEmpty // forwarded errors arrive as text
	}
	return err
}

// StepDown hands leadership to another voter, e.g. before upgrading the
// leader. Any node may be asked; it's forwarded to the leader.
func (n *Node) StepDown() error {
	return n.withLeader(false, n.transfer, func(addr string) error { return n.call(addr, "/cluster/step-down", struct{}{}, nil) })
}

func (n *Node) transfer() error {
	return n.raft.LeadershipTransfer().Error()
}

// LeaderChanges counts leadership notifications on this node (for metrics).
func (n *Node) LeaderChanges() uint64 { return n.gen.Load() }

// Remove takes a node out of the Raft configuration and the member directory.
func (n *Node) Remove(id string) error {
	return n.apply(command{Op: "unmember", ID: id})
}

// IsLeader, Leader and Members are for status output and tests.
func (n *Node) IsLeader() bool { return n.raft.State() == raft.Leader }

func (n *Node) Leader() string {
	_, id := n.raft.LeaderWithID()
	return string(id)
}

func (n *Node) Members() map[string]string { return n.fsm.Members() }

// Voters returns the IDs in the current Raft configuration.
func (n *Node) Voters() ([]string, error) {
	f := n.raft.GetConfiguration()
	if err := f.Error(); err != nil {
		return nil, err
	}
	var ids []string
	for _, s := range f.Configuration().Servers {
		ids = append(ids, string(s.ID))
	}
	return ids, nil
}

// Shutdown stops the node. Its data stays on disk for the next Start.
func (n *Node) Shutdown() {
	select {
	case <-n.done:
		return
	default:
		close(n.done)
	}
	if n.rpc != nil {
		_ = n.rpc.Close()
	}
	_ = n.raft.Shutdown().Error()
	_ = n.trans.Close()
	_ = n.store.Close()
	n.wg.Wait()
}
