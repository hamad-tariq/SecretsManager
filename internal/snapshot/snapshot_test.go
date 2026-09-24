package snapshot

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestRoundTripAndTamper(t *testing.T) {
	data := map[string][]byte{"raw/seal": {1, 2}, "kv/a": {3}, "kv/b": {4}}
	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode(New(data, time.Now()))
	f, err := Read(bytes.NewReader(buf.Bytes()))
	if err != nil || len(f.Data) != 3 || f.Data["kv/b"][0] != 4 {
		t.Fatalf("round trip: %v", err)
	}

	for name, mutate := range map[string]func(f *File){
		"value changed": func(f *File) { f.Data["kv/a"] = []byte{9} },
		"key dropped":   func(f *File) { delete(f.Data, "kv/b") },
		"format":        func(f *File) { f.Format = "other" },
	} {
		g, _ := Read(bytes.NewReader(buf.Bytes()))
		mutate(g)
		if g.Verify() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := New(map[string][]byte{"kv/a": {1}}, time.Now()).Verify(); err == nil || !strings.Contains(err.Error(), "keyring") {
		t.Fatalf("snapshot of an uninitialised cluster: %v", err)
	}
	if _, err := Read(strings.NewReader(`{"format":"sm-snapshot-1","extra":1}`)); err == nil {
		t.Fatal("unknown field accepted")
	}
}
