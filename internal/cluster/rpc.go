package cluster

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/hashicorp/raft"

	"github.com/hamad-tariq/SecretsManager/internal/pki"
	"github.com/hamad-tariq/SecretsManager/internal/storage"
)

type readRequest struct {
	Op  string `json:"op"` // get | list | dump
	Key string `json:"key"`
}

type readResponse struct {
	Found bool              `json:"found,omitempty"`
	Value []byte            `json:"value,omitempty"`
	Keys  []string          `json:"keys,omitempty"`
	Data  map[string][]byte `json:"data,omitempty"` // dump
}

type joinRequest struct {
	ID       string `json:"id"`
	RaftAddr string `json:"raft_addr"`
	RPCAddr  string `json:"rpc_addr"`
}

type joinResponse struct {
	Leader string `json:"leader,omitempty"` // set when the receiver is not the leader
}

type errorResponse struct {
	Error  string `json:"error"`
	Leader string `json:"leader,omitempty"`
}

// statusRetry tells the caller the receiver is not (ready as) leader.
const statusRetry = http.StatusMisdirectedRequest

// maxBody bounds RPC bodies, including whole-dataset dumps and restores.
//
// ponytail: snapshots travel as one JSON body, so the dataset is capped at
// this size; stream them if a cluster ever holds more.
const maxBody = 64 << 20

// memberOnly lets a request through only from a current member (join is the
// one route open to non-members, and it refuses removed IDs).
func (n *Node) memberOnly(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := pki.PeerIdentity(r.TLS)
		if err != nil || !n.fsm.admits(id.Name) {
			http.Error(w, `{"error":"not a member of this cluster"}`, http.StatusForbidden)
			return
		}
		h(w, r)
	}
}

func (n *Node) rpcHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /cluster/apply", n.memberOnly(func(w http.ResponseWriter, r *http.Request) {
		var c command
		if !decode(w, r, &c) {
			return
		}
		n.respond(w, n.leaderOnly(false, func() error { return n.leaderApply(c) }), nil)
	}))
	mux.HandleFunc("POST /cluster/read", n.memberOnly(func(w http.ResponseWriter, r *http.Request) {
		var req readRequest
		if !decode(w, r, &req) {
			return
		}
		var res readResponse
		err := n.leaderOnly(true, func() (err error) { res, err = n.readLocal(req); return err })
		n.respond(w, err, res)
	}))
	mux.HandleFunc("POST /cluster/step-down", n.memberOnly(func(w http.ResponseWriter, r *http.Request) {
		var req struct{}
		if !decode(w, r, &req) {
			return
		}
		n.respond(w, n.leaderOnly(false, n.transfer), nil)
	}))
	mux.HandleFunc("POST /cluster/join", func(w http.ResponseWriter, r *http.Request) {
		var req joinRequest
		if !decode(w, r, &req) {
			return
		}
		// A node may only join as itself, and never with a removed ID.
		if id, err := pki.PeerIdentity(r.TLS); err != nil || id.Name != req.ID {
			http.Error(w, `{"error":"certificate does not match node id"}`, http.StatusForbidden)
			return
		}
		if n.fsm.isBanned(req.ID) {
			http.Error(w, `{"error":"this node id was removed from the cluster; join with a new id"}`, http.StatusForbidden)
			return
		}
		// A current member re-joining with a different Raft address would
		// take over that voter's slot; only a genuinely new ID may join.
		if addr, ok := n.fsm.memberRPC(req.ID); ok && addr != req.RPCAddr {
			http.Error(w, `{"error":"a member with this id already exists at another address"}`, http.StatusConflict)
			return
		}
		n.respond(w, n.leaderOnly(false, func() error { return n.addVoter(req) }), joinResponse{})
	})
	return mux
}

func (n *Node) addVoter(req joinRequest) error {
	f := n.raft.AddVoter(raft.ServerID(req.ID), raft.ServerAddress(req.RaftAddr), 0, n.timeout)
	if err := f.Error(); err != nil {
		if errors.Is(err, raft.ErrNotLeader) || errors.Is(err, raft.ErrLeadershipLost) {
			return errRetry
		}
		return err
	}
	return n.applyLocal(command{Op: "member", ID: req.ID, RPC: req.RPCAddr})
}

// leaderOnly runs fn if this node is the (ready) leader, else returns errRetry.
// Forwarded requests are never forwarded again, so there are no loops.
func (n *Node) leaderOnly(consistentRead bool, fn func() error) error {
	return n.tryLeader(consistentRead, fn, func(string) error { return errRetry })
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return false
	}
	return true
}

func (n *Node) respond(w http.ResponseWriter, err error, body any) {
	w.Header().Set("Content-Type", "application/json")
	switch {
	case errors.Is(err, storage.ErrConflict):
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(errorResponse{Error: err.Error()})
	case errors.Is(err, errRetry):
		_, id := n.raft.LeaderWithID()
		leader, _ := n.fsm.memberRPC(string(id))
		w.WriteHeader(statusRetry)
		_ = json.NewEncoder(w).Encode(errorResponse{Error: "not leader", Leader: leader})
	case err != nil:
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(errorResponse{Error: err.Error()})
	default:
		if body == nil {
			body = struct{}{}
		}
		_ = json.NewEncoder(w).Encode(body)
	}
}

// call POSTs req to another node. A "not leader" reply becomes errRetry;
// for join, out (a *joinResponse) receives the leader hint.
func (n *Node) call(addr, path string, req, out any) error {
	b, err := json.Marshal(req)
	if err != nil {
		return err
	}
	resp, err := n.client.Post("https://"+addr+path, "application/json", bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("%w: %v", errRetry, err) // node down or unreachable: try again
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return fmt.Errorf("%w: %v", errRetry, err)
	}
	switch resp.StatusCode {
	case http.StatusOK:
		if out != nil {
			return json.Unmarshal(body, out)
		}
		return nil
	case http.StatusConflict:
		return storage.ErrConflict
	case statusRetry:
		var e errorResponse
		_ = json.Unmarshal(body, &e)
		if jr, ok := out.(*joinResponse); ok {
			jr.Leader = e.Leader
		}
		return errRetry
	default:
		var e errorResponse
		if json.Unmarshal(body, &e) != nil || e.Error == "" {
			e.Error = resp.Status
		}
		return fmt.Errorf("cluster: %s: %s", addr, e.Error)
	}
}
