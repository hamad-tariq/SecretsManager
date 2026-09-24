package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/hamad-tariq/SecretsManager/internal/secret"
)

var key = []byte("0123456789abcdef0123456789abcdef")

func writeLog(t *testing.T, n int) []string {
	t.Helper()
	var buf bytes.Buffer
	l := New(&buf, key, Head{})
	for i := range n {
		if err := l.Log(Entry{Identity: "svc/orders", Operation: "read", Path: fmt.Sprintf("prod/orders/%d", i), Result: "ok"}); err != nil {
			t.Fatal(err)
		}
	}
	if h := l.Head(); h.Seq != uint64(n) {
		t.Fatalf("head seq %d", h.Seq)
	}
	return strings.SplitAfter(strings.TrimSuffix(buf.String(), "\n"), "\n")
}

func verify(lines []string) (Head, error) {
	return Verify(strings.NewReader(strings.Join(lines, "")))
}

func TestChainVerifies(t *testing.T) {
	lines := writeLog(t, 5)
	h, err := verify(lines)
	if err != nil || h.Seq != 5 {
		t.Fatalf("verify: %v, head %+v", err, h)
	}
	if _, err := Verify(strings.NewReader("")); err != nil {
		t.Fatalf("empty log should verify: %v", err)
	}
}

func TestTamperDetected(t *testing.T) {
	cases := map[string]struct {
		mutate  func([]string) []string
		badLine string
	}{
		"edit field": {func(l []string) []string {
			l[2] = strings.Replace(l[2], "prod/orders/2", "prod/orders/X", 1)
			return l
		}, "line 3"},
		"edit result": {func(l []string) []string {
			l[0] = strings.Replace(l[0], `"result":"ok"`, `"result":"denied"`, 1)
			return l
		}, "line 1"},
		"delete line": {func(l []string) []string { return append(l[:1], l[2:]...) }, "line 2"},
		"swap lines":  {func(l []string) []string { l[1], l[2] = l[2], l[1]; return l }, "line 2"},
		"truncated last line": {func(l []string) []string {
			l[4] = l[4][:len(l[4])/2]
			return l
		}, "line 5"},
		"trailing junk": {func(l []string) []string {
			l[3] = strings.TrimSuffix(l[3], "\n") + ` {}` + "\n"
			return l
		}, "line 4"},
		"unknown field": {func(l []string) []string {
			l[1] = strings.Replace(l[1], `{"seq"`, `{"x":1,"seq"`, 1)
			return l
		}, "line 2"},
	}
	for name, c := range cases {
		_, err := verify(c.mutate(writeLog(t, 5)))
		if err == nil || !strings.Contains(err.Error(), c.badLine+":") {
			t.Errorf("%s: want error at %s, got %v", name, c.badLine, err)
		}
	}
}

func TestSensitiveValuesAreHMACd(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, key, Head{})
	const canary = "s3cr3t-canary-value"
	err := l.Log(Entry{Operation: "read", Result: "ok", Sensitive: map[string]secret.Secret{"value": secret.New([]byte(canary))}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), canary) {
		t.Fatal("plaintext secret in audit log")
	}
	if !strings.Contains(buf.String(), HMAC(key, []byte(canary))) {
		t.Fatal("HMAC of value missing from log")
	}
	if HMAC(key, []byte("a")) == HMAC([]byte("other key"), []byte("a")) {
		t.Fatal("HMAC ignores key")
	}
}

type failWriter struct{ fail bool }

func (w *failWriter) Write(p []byte) (int, error) {
	if w.fail {
		return 0, errors.New("disk full")
	}
	return len(p), nil
}

func TestFailClosed(t *testing.T) {
	w := &failWriter{fail: true}
	l := New(w, key, Head{})
	if err := l.Log(Entry{Operation: "read"}); !errors.Is(err, ErrBroken) {
		t.Fatalf("want ErrBroken, got %v", err)
	}
	w.fail = false
	if err := l.Log(Entry{Operation: "read"}); !errors.Is(err, ErrBroken) {
		t.Fatal("logger must stay broken after a failed write")
	}
	if l.Head().Seq != 0 {
		t.Fatal("head advanced despite failure")
	}

	l = New(&bytes.Buffer{}, key, Head{})
	l.sync = func() error { return errors.New("fsync failed") }
	if err := l.Log(Entry{Operation: "read"}); !errors.Is(err, ErrBroken) {
		t.Fatalf("fsync failure: want ErrBroken, got %v", err)
	}
}

func TestOpenFileResumesChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	for round := range 3 {
		l, err := OpenFile(path, key)
		if err != nil {
			t.Fatal(err)
		}
		for range 2 {
			if err := l.Log(Entry{Operation: "read", Result: "ok"}); err != nil {
				t.Fatal(err)
			}
		}
		if got := l.Head().Seq; got != uint64(2*(round+1)) {
			t.Fatalf("round %d: seq %d", round, got)
		}
		if err := l.Close(); err != nil {
			t.Fatal(err)
		}
		if err := l.Log(Entry{}); err == nil {
			t.Fatal("Log after Close should fail")
		}
	}

	data, _ := os.ReadFile(path)
	if err := os.WriteFile(path, bytes.Replace(data, []byte(`"op":"read"`), []byte(`"op":"wipe"`), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFile(path, key); err == nil {
		t.Fatal("OpenFile accepted a tampered log")
	}
	if _, err := OpenFile(filepath.Join(t.TempDir(), "missing-dir", "a.log"), key); err == nil {
		t.Fatal("OpenFile should fail for a bad path")
	}
}

func TestConcurrentLogging(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, key, Head{})
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Go(func() {
			if err := l.Log(Entry{Operation: "read", Path: fmt.Sprint(i)}); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if h, err := Verify(&buf); err != nil || h.Seq != 50 {
		t.Fatalf("verify after concurrent writes: %v %+v", err, h)
	}
}

func TestSensitiveNeedsKey(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, nil, Head{})
	e := Entry{Operation: "read", Sensitive: map[string]secret.Secret{"v": secret.New([]byte("x"))}}
	if err := l.Log(e); !errors.Is(err, ErrNoKey) {
		t.Fatalf("want ErrNoKey, got %v", err)
	}
	if err := l.Log(Entry{Operation: "unseal"}); err != nil {
		t.Fatalf("non-sensitive entry without key: %v", err)
	}
	l.SetHMACKey(key)
	if err := l.Log(e); err != nil {
		t.Fatal(err)
	}
	if h, err := Verify(&buf); err != nil || h.Seq != 2 {
		t.Fatalf("verify: %v %+v", err, h)
	}
}

// A line re-encoded with a duplicate key in another case decodes (for Go) to
// the original record, so its hash still matches; the exact-bytes check must
// catch it, because every other reader sees the edited value.
func TestEditedLineWithDuplicateKeyRejected(t *testing.T) {
	lines := writeLog(t, 3)
	orig := strings.TrimSuffix(lines[1], "\n")
	var rec map[string]any
	_ = json.Unmarshal([]byte(orig), &rec)
	forged := strings.Replace(orig, `"op":"`+rec["op"].(string)+`"`, `"op":"harmless.op"`, 1)
	forged = strings.TrimSuffix(forged, "}") + `,"Op":"` + rec["op"].(string) + `"}`
	lines[1] = forged + "\n"
	if _, err := verify(lines); err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("forged line accepted: %v", err)
	}
}

func TestVerifyThroughCatchesTruncation(t *testing.T) {
	lines := writeLog(t, 5)
	full, _ := verify(lines)
	var third Head
	_ = json.Unmarshal([]byte(lines[2]), &third)
	if _, err := VerifyThrough(strings.NewReader(strings.Join(lines, "")), full); err != nil {
		t.Fatalf("complete log: %v", err)
	}
	if _, err := VerifyThrough(strings.NewReader(strings.Join(lines[:3], "")), full); err == nil {
		t.Fatal("truncated log verified against the collector's head")
	}
	if _, err := VerifyThrough(strings.NewReader(strings.Join(lines, "")), Head{Seq: 3, Hash: strings.Repeat("0", 64)}); err == nil {
		t.Fatal("wrong hash for record 3 accepted")
	}
	if _, err := VerifyThrough(strings.NewReader(""), full); err == nil {
		t.Fatal("empty log verified against a non-empty head")
	}
}
