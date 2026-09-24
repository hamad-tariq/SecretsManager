package cluster

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"sync"

	"github.com/hashicorp/raft"

	"github.com/hamad-tariq/SecretsManager/internal/storage"
)

// command is one entry in the Raft log.
type command struct {
	Op       string `json:"op"` // put | put_if | delete | member | unmember | restore
	Key      string `json:"key,omitempty"`
	Value    []byte `json:"value,omitempty"`
	Expected []byte `json:"expected,omitempty"` // put_if: required current value
	Absent   bool   `json:"absent,omitempty"`   // put_if: key must not exist
	ID       string `json:"id,omitempty"`       // member ops: node ID
	RPC      string `json:"rpc,omitempty"`      // member ops: node's cluster RPC address

	Data map[string][]byte `json:"data,omitempty"` // restore: the whole dataset
}

// ErrNotEmpty: a snapshot can only be restored into a cluster with no data.
var ErrNotEmpty = errors.New("cluster: restore needs an empty cluster (no data at all)")

// fsm is the replicated state: user data plus the member directory
// (node ID → RPC address), which followers need to find the leader.
//
// ponytail: whole state lives in RAM and is rebuilt from snapshot + log on
// start. Fine for secrets (small, already ciphertext); move data into bbolt
// if the dataset outgrows memory or restart replay gets slow.
type fsm struct {
	data *storage.Inmem

	mu      sync.RWMutex
	members map[string]string
	banned  map[string]bool // removed node IDs: never let back in (a replacement uses a new ID)
}

func newFSM() *fsm {
	return &fsm{data: storage.NewInmem(), members: map[string]string{}, banned: map[string]bool{}}
}

func (f *fsm) Apply(l *raft.Log) any {
	var c command
	if err := json.Unmarshal(l.Data, &c); err != nil {
		return fmt.Errorf("cluster: bad log entry %d: %w", l.Index, err)
	}
	switch c.Op {
	case "put":
		return f.data.Put(c.Key, c.Value)
	case "put_if":
		if c.Absent {
			return f.data.PutIf(c.Key, c.Value, nil)
		}
		if c.Expected == nil {
			c.Expected = []byte{} // JSON drops empty slices; empty != absent
		}
		return f.data.PutIf(c.Key, c.Value, c.Expected)
	case "delete":
		return f.data.Delete(c.Key)
	case "restore":
		// Checked inside the state machine, so it's atomic with respect to
		// every other write (e.g. a concurrent init).
		if len(f.data.Snapshot()) > 0 {
			return ErrNotEmpty
		}
		f.data.Replace(c.Data)
	case "member":
		f.mu.Lock()
		f.members[c.ID] = c.RPC
		f.mu.Unlock()
	case "unmember":
		f.mu.Lock()
		delete(f.members, c.ID)
		f.banned[c.ID] = true
		f.mu.Unlock()
	default:
		return fmt.Errorf("cluster: unknown op %q", c.Op)
	}
	return nil
}

func (f *fsm) memberRPC(id string) (string, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	a, ok := f.members[id]
	return a, ok
}

func (f *fsm) isBanned(id string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.banned[id]
}

// admits reports whether a peer may talk to this node: never a removed ID;
// otherwise only current members, except while this node knows no members
// at all (it is new and waiting for the leader to replicate to it).
func (f *fsm) admits(id string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.banned[id] {
		return false
	}
	_, ok := f.members[id]
	return ok || len(f.members) == 0
}

func (f *fsm) Members() map[string]string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return maps.Clone(f.members)
}

type snapshot struct {
	Data    map[string][]byte `json:"data"`
	Members map[string]string `json:"members"`
	Banned  map[string]bool   `json:"banned,omitempty"`
}

func (f *fsm) Snapshot() (raft.FSMSnapshot, error) {
	f.mu.RLock()
	banned := maps.Clone(f.banned)
	f.mu.RUnlock()
	return &snapshot{Data: f.data.Snapshot(), Members: f.Members(), Banned: banned}, nil
}

func (f *fsm) Restore(r io.ReadCloser) error {
	defer r.Close()
	var s snapshot
	if err := json.NewDecoder(r).Decode(&s); err != nil {
		return err
	}
	if s.Data == nil {
		s.Data = map[string][]byte{}
	}
	if s.Members == nil {
		s.Members = map[string]string{}
	}
	if s.Banned == nil {
		s.Banned = map[string]bool{}
	}
	f.data.Replace(s.Data)
	f.mu.Lock()
	f.members, f.banned = s.Members, s.Banned
	f.mu.Unlock()
	return nil
}

func (s *snapshot) Persist(sink raft.SnapshotSink) error {
	if err := json.NewEncoder(sink).Encode(s); err != nil {
		_ = sink.Cancel()
		return err
	}
	return sink.Close()
}

func (s *snapshot) Release() {}
