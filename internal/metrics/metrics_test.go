package metrics

import (
	"strings"
	"testing"
)

func TestTextFormat(t *testing.T) {
	r := New()
	r.Add("sm_requests_total", "API requests.", 1, "op", "kv.read", "code", "200")
	r.Add("sm_requests_total", "API requests.", 2, "op", "kv.read", "code", "200")
	r.Add("sm_requests_total", "API requests.", 1, "op", "kv.write", "code", "403")
	r.Gauge("sm_sealed", "1 if sealed.", func() []Sample { return One(Bool(true)) })
	r.Gauge("sm_cert_expiry_seconds", "Seconds left.", func() []Sample {
		return []Sample{{Labels: []string{"cert", `we"ird`}, Value: 3600.5}}
	})
	var b strings.Builder
	if err := r.Write(&b); err != nil {
		t.Fatal(err)
	}
	want := `# HELP sm_cert_expiry_seconds Seconds left.
# TYPE sm_cert_expiry_seconds gauge
sm_cert_expiry_seconds{cert="we\"ird"} 3600.5
# HELP sm_requests_total API requests.
# TYPE sm_requests_total counter
sm_requests_total{op="kv.read",code="200"} 3
sm_requests_total{op="kv.write",code="403"} 1
# HELP sm_sealed 1 if sealed.
# TYPE sm_sealed gauge
sm_sealed 1
`
	if b.String() != want {
		t.Fatalf("got:\n%s\nwant:\n%s", b.String(), want)
	}
	var nilReg *Registry
	nilReg.Add("x", "", 1) // no-op, no panic
}
