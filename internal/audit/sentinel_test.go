package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hamad-tariq/SecretsManager/internal/secret"
)

// TestSentinelReadsRealLogs checks that Sentinel (sentinel/, Python) parses
// logs exactly as this package writes them: field names, RFC 3339 nano
// timestamps, HMAC'd values, and chain links, plainly and as forwarded
// syslog lines.
func TestSentinelReadsRealLogs(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		if py, err = exec.LookPath("python"); err != nil {
			t.Skip("python not found")
		}
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	l, err := OpenFile(path, []byte("k"))
	if err != nil {
		t.Fatal(err)
	}
	svc := "spiffe://sm/svc/orders-api"
	for i := range 5 {
		_ = l.Log(Entry{RequestID: fmt.Sprint(i), Identity: svc, Operation: "kv.read", Path: "kv/prod/orders/db",
			Result: "ok", SourceIP: "10.42.1.5", CertSerial: "ab12", Sensitive: map[string]secret.Secret{"value": secret.New([]byte("s3cret"))}})
	}
	for i := range 12 { // someone probing paths it may not read
		_ = l.Log(Entry{Identity: svc, Operation: "kv.read", Path: fmt.Sprintf("kv/prod/x/%d", i), Result: "denied:403",
			SourceIP: "10.42.1.5", CertSerial: "ab12"})
	}
	_ = l.Log(Entry{Operation: "sys.unseal", Path: "/v1/sys/unseal", Result: "ok", SourceIP: "10.0.0.9"})
	_ = l.Close()

	// The same log as a collector receives it.
	raw, _ := os.ReadFile(path)
	var syslog bytes.Buffer
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		fmt.Fprintf(&syslog, "<110>1 %s node-1 smd - - - %s\n", time.Now().UTC().Format(time.RFC3339Nano), sc.Text())
	}
	syslogPath := filepath.Join(dir, "collector.log")
	_ = os.WriteFile(syslogPath, syslog.Bytes(), 0o600)

	for _, file := range []string{path, syslogPath} {
		cmd := exec.Command(py, "-m", "sentinel", "replay", file)
		cmd.Dir = filepath.Join("..", "..", "sentinel")
		var out, errOut bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errOut
		if err := cmd.Run(); err != nil {
			t.Fatalf("sentinel: %v\n%s", err, errOut.String())
		}
		rules := map[string]int{}
		for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
			var a struct{ Rule string }
			if err := json.Unmarshal([]byte(line), &a); err != nil {
				t.Fatalf("alert line %q: %v", line, err)
			}
			rules[a.Rule]++
		}
		var summary struct {
			Summary struct{ Records, Malformed, Duplicates int }
		}
		if err := json.Unmarshal(errOut.Bytes(), &summary); err != nil {
			t.Fatalf("summary %q: %v", errOut.String(), err)
		}
		if rules["denial_burst"] != 1 || rules["governance"] != 1 || rules["audit_gap"] != 0 || len(rules) != 2 {
			t.Fatalf("%s: alerts %v", filepath.Base(file), rules)
		}
		if s := summary.Summary; s.Records != 18 || s.Malformed != 0 || s.Duplicates != 0 {
			t.Fatalf("%s: summary %+v", filepath.Base(file), s)
		}
		if strings.Contains(out.String(), "s3cret") {
			t.Fatal("secret value in alerts")
		}
	}
}
