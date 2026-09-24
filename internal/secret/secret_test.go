package secret

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

const canary = "hunter2-canary"

func TestNeverLeaks(t *testing.T) {
	s := New([]byte(canary))

	type exported struct{ Pw Secret }
	type unexported struct{ pw Secret }

	var out []string
	for _, verb := range []string{"%s", "%v", "%+v", "%#v", "%x", "%X", "%q", "%d"} {
		out = append(out,
			fmt.Sprintf(verb, s),
			fmt.Sprintf(verb, exported{s}),
			fmt.Sprintf(verb, unexported{s}),
			fmt.Sprintf(verb, &unexported{s}),
		)
	}
	out = append(out, fmt.Sprint(s), fmt.Sprintln([]Secret{s}))

	j, _ := json.Marshal(exported{s})
	out = append(out, string(j))

	var logs bytes.Buffer
	for _, h := range []slog.Handler{slog.NewTextHandler(&logs, nil), slog.NewJSONHandler(&logs, nil)} {
		l := slog.New(h)
		l.Info("direct", "pw", s)
		l.Info("struct", "exp", exported{s}, "unexp", unexported{s})
	}
	out = append(out, logs.String())

	hexCanary := fmt.Sprintf("%x", canary)
	for _, o := range out {
		if strings.Contains(o, canary) || strings.Contains(o, hexCanary) {
			t.Fatalf("secret leaked: %s", o)
		}
	}
	if !strings.Contains(logs.String(), redacted) {
		t.Fatal("expected [REDACTED] in logs")
	}
}

func TestRevealAndZero(t *testing.T) {
	s := New([]byte(canary))
	if string(s.Reveal()) != canary {
		t.Fatal("Reveal returned wrong bytes")
	}
	s.Zero()
	if !bytes.Equal(s.Reveal(), make([]byte, len(canary))) {
		t.Fatal("Zero did not clear bytes")
	}
	var empty Secret
	empty.Zero()
	if empty.Reveal() != nil {
		t.Fatal("zero Secret should reveal nil")
	}
}
