// Package audit writes a tamper-evident, append-only audit log.
//
// Each record is one JSON line. Its hash is SHA-256(prev hash ‖ record JSON
// without the hash field), so editing, deleting or reordering any line breaks
// the chain from that point on. Rewriting the whole tail is only detectable
// against a copy of a later head kept elsewhere (remote forwarding, iteration 11).
//
// Secret values are never logged: callers pass them as secret.Secret and the
// log stores HMAC-SHA256(auditKey, value), so an operator holding the key can
// check "was this value returned?" without the log containing it.
package audit

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/hamad-tariq/SecretsManager/internal/secret"
)

// Entry is what callers log.
type Entry struct {
	RequestID  string
	Identity   string
	Operation  string
	Path       string
	Result     string // "ok", "denied", "error", ...
	SourceIP   string
	CertSerial string
	// Sensitive values are HMAC'd before they reach the log.
	Sensitive map[string]secret.Secret
}

// Record is one line in the log.
type Record struct {
	Seq        uint64            `json:"seq"`
	Time       string            `json:"time"` // RFC 3339, UTC; a string so re-encoding is byte-identical
	RequestID  string            `json:"request_id,omitempty"`
	Identity   string            `json:"identity,omitempty"`
	Operation  string            `json:"op"`
	Path       string            `json:"path,omitempty"`
	Result     string            `json:"result"`
	SourceIP   string            `json:"source_ip,omitempty"`
	CertSerial string            `json:"cert_serial,omitempty"`
	HMACs      map[string]string `json:"hmacs,omitempty"`
	Prev       string            `json:"prev"`
	Hash       string            `json:"hash,omitempty"`
}

// Head identifies the last record of a chain.
type Head struct {
	Seq  uint64
	Hash string
}

// genesis is the Prev of the first record.
var genesis = hex.EncodeToString(make([]byte, sha256.Size))

var (
	ErrBroken = errors.New("audit: log is broken after a failed write")
	ErrNoKey  = errors.New("audit: no HMAC key yet; sensitive values can't be logged")
)

// Logger appends records to w. It is safe for concurrent use.
type Logger struct {
	mu   sync.Mutex
	w    io.Writer
	sync func() error
	key  []byte
	head Head
	err  error // sticky: after a failed write, every Log fails (fail closed)
	gate func() error
	now  func() time.Time
}

// New starts a logger that continues the chain from head (zero Head = new log).
// hmacKey may be nil until it's known (it lives behind the barrier); until
// SetHMACKey, entries with Sensitive values are refused.
func New(w io.Writer, hmacKey []byte, head Head) *Logger {
	if head.Hash == "" {
		head.Hash = genesis
	}
	return &Logger{w: w, key: hmacKey, head: head, now: time.Now}
}

// OpenFile opens (or creates) an append-only log file, verifies the existing
// chain, and continues it. Every Log call is fsynced before it returns.
func OpenFile(path string, hmacKey []byte) (*Logger, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600) // #nosec G304 -- operator-configured path
	if err != nil {
		return nil, err
	}
	head, err := Verify(f)
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("existing audit log failed verification: %w", err)
	}
	l := New(f, hmacKey, head)
	l.sync = f.Sync
	return l, nil
}

// SetHMACKey sets the key used to fingerprint sensitive values.
func (l *Logger) SetHMACKey(key []byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.key = key
}

// SetGate installs a check run before every write; while it returns an
// error, Log refuses (e.g. forwarding to the remote copy is too far behind).
func (l *Logger) SetGate(gate func() error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.gate = gate
}

// Log appends one record. If it returns an error, the request must fail.
func (l *Logger) Log(e Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err != nil {
		return l.err
	}
	if l.gate != nil {
		if err := l.gate(); err != nil {
			return err
		}
	}
	if len(e.Sensitive) > 0 && len(l.key) == 0 {
		return ErrNoKey
	}

	r := Record{
		Seq:        l.head.Seq + 1,
		Time:       l.now().UTC().Format(time.RFC3339Nano),
		RequestID:  e.RequestID,
		Identity:   e.Identity,
		Operation:  e.Operation,
		Path:       e.Path,
		Result:     e.Result,
		SourceIP:   e.SourceIP,
		CertSerial: e.CertSerial,
		Prev:       l.head.Hash,
	}
	if len(e.Sensitive) > 0 {
		r.HMACs = make(map[string]string, len(e.Sensitive))
		for k, v := range e.Sensitive {
			r.HMACs[k] = HMAC(l.key, v.Reveal())
		}
	}
	line, err := seal(&r)
	if err != nil {
		return err
	}
	if _, err := l.w.Write(line); err != nil {
		l.err = fmt.Errorf("%w: %v", ErrBroken, err)
		return l.err
	}
	if l.sync != nil {
		if err := l.sync(); err != nil {
			l.err = fmt.Errorf("%w: %v", ErrBroken, err)
			return l.err
		}
	}
	l.head = Head{Seq: r.Seq, Hash: r.Hash}
	return nil
}

// Close closes the underlying writer if it is closable. Later Log calls fail.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.err = errors.New("audit: logger closed")
	if c, ok := l.w.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

// Head returns the current end of the chain.
func (l *Logger) Head() Head {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.head
}

// HMAC returns the value's audit fingerprint, as stored in Record.HMACs.
func HMAC(key, value []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write(value)
	return "hmac-sha256:" + hex.EncodeToString(m.Sum(nil))
}

// seal fills r.Hash and returns the encoded line, newline included.
func seal(r *Record) ([]byte, error) {
	r.Hash = ""
	body, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	r.Hash = chainHash(r.Prev, body)
	line, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	return append(line, '\n'), nil
}

func chainHash(prev string, body []byte) string {
	p, _ := hex.DecodeString(prev)
	h := sha256.New()
	h.Write(p)
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

// Verify reads a whole log and checks the chain. It returns the head, or an
// error naming the first bad line.
func Verify(r io.Reader) (Head, error) {
	return verifyLog(r, nil)
}

// VerifyThrough is Verify, and also requires that the log contains the
// record `want` (e.g. the last one the off-host collector received). A log
// cut back to an earlier point then fails instead of verifying as shorter.
func VerifyThrough(r io.Reader, want Head) (Head, error) {
	found := false
	head, err := verifyLog(r, func(h Head) {
		if h.Seq == want.Seq {
			found = h.Hash == want.Hash
		}
	})
	if err == nil && !found {
		err = fmt.Errorf("the log doesn't contain record %d with the expected hash (last record is %d): truncated or replaced", want.Seq, head.Seq)
	}
	return head, err
}

func verifyLog(r io.Reader, each func(Head)) (Head, error) {
	head := Head{Hash: genesis}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for line := 1; sc.Scan(); line++ {
		var rec Record
		dec := json.NewDecoder(bytes.NewReader(sc.Bytes()))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&rec); err != nil {
			return head, fmt.Errorf("line %d: not a valid record: %w", line, err)
		}
		if dec.InputOffset() != int64(len(sc.Bytes())) {
			return head, fmt.Errorf("line %d: trailing data after record", line)
		}
		if rec.Seq != head.Seq+1 {
			return head, fmt.Errorf("line %d: seq %d, expected %d", line, rec.Seq, head.Seq+1)
		}
		if rec.Prev != head.Hash {
			return head, fmt.Errorf("line %d: prev hash does not match line %d", line, line-1)
		}
		want := rec.Hash
		canonical, err := seal(&rec)
		if err != nil {
			return head, err
		}
		if !hmac.Equal([]byte(rec.Hash), []byte(want)) {
			return head, fmt.Errorf("line %d: hash mismatch (record was modified)", line)
		}
		// The hash covers the decoded record, so also require the exact bytes
		// the logger writes. Otherwise a line with, say, a duplicate key in a
		// different case decodes (for Go) to the original record while other
		// readers (people, grep, Sentinel) see an edited one.
		if !bytes.Equal(canonical[:len(canonical)-1], sc.Bytes()) {
			return head, fmt.Errorf("line %d: not in the logger's exact encoding (record was modified)", line)
		}
		head = Head{Seq: rec.Seq, Hash: rec.Hash}
		if each != nil {
			each(head)
		}
	}
	if err := sc.Err(); err != nil {
		return head, err
	}
	return head, nil
}
