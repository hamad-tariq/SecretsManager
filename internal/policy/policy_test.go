package policy

import (
	"strings"
	"testing"
)

func mustParse(t *testing.T, js string) *Policy {
	t.Helper()
	p, err := Parse([]byte(js))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestMatching(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          bool
	}{
		{"prod/orders/db", "prod/orders/db", true},
		{"prod/orders/db", "prod/orders/db2", false},
		{"prod/orders/db", "prod/orders", false},
		{"prod/orders/db", "prod/orders/db/x", false},
		{"prod/orders/db", "Prod/orders/db", false}, // case-sensitive
		{"prod/orders/*", "prod/orders/db", true},
		{"prod/orders/*", "prod/orders/a/b/c", true},
		{"prod/orders/*", "prod/orders", false},
		{"prod/orders/*", "prod/ordersX/db", false},
		{"prod/+/db", "prod/orders/db", true},
		{"prod/+/db", "prod/orders/x/db", false},
		{"prod/+/db", "prod/db", false},
		{"+/orders/*", "stage/orders/db", true},
		{"*", "anything/at/all", true},
	}
	for _, c := range cases {
		p := mustParse(t, `{"name":"t","rules":[{"path":"`+c.pattern+`","capabilities":["read"]}]}`)
		if got := Allowed([]*Policy{p}, c.path, Read); got != c.want {
			t.Errorf("%q vs %q: got %v want %v", c.pattern, c.path, got, c.want)
		}
	}
}

func TestEvaluation(t *testing.T) {
	orders := mustParse(t, `{"name":"orders","rules":[
		{"path":"prod/orders/*","capabilities":["read","list"]},
		{"path":"prod/orders/admin/*","deny":true}]}`)
	writer := mustParse(t, `{"name":"writer","rules":[{"path":"prod/orders/db","capabilities":["update"]}]}`)
	denyAll := mustParse(t, `{"name":"lockdown","rules":[{"path":"*","deny":true}]}`)

	cases := []struct {
		name     string
		policies []*Policy
		path     string
		c        Capability
		want     bool
	}{
		{"granted", []*Policy{orders}, "prod/orders/db", Read, true},
		{"capability not granted", []*Policy{orders}, "prod/orders/db", Update, false},
		{"no policies", nil, "prod/orders/db", Read, false},
		{"no matching rule", []*Policy{orders}, "prod/billing/db", Read, false},
		{"deny beats broader grant", []*Policy{orders}, "prod/orders/admin/key", Read, false},
		{"union across policies", []*Policy{orders, writer}, "prod/orders/db", Update, true},
		{"deny in another policy wins", []*Policy{orders, denyAll}, "prod/orders/db", Read, false},
		{"unparsed policy grants nothing", []*Policy{{Name: "raw", Rules: []Rule{{Path: "*", Capabilities: []Capability{Read}}}}}, "a", Read, false},
	}
	for _, c := range cases {
		if got := Allowed(c.policies, c.path, c.c); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string]string{
		"bad json":           `{`,
		"trailing data":      `{"name":"a","rules":[{"path":"a","deny":true}]} {}`,
		"typo field":         `{"name":"a","rules":[{"path":"a","capabilites":["read"]}]}`,
		"no name":            `{"rules":[{"path":"a","deny":true}]}`,
		"no rules":           `{"name":"a","rules":[]}`,
		"neither":            `{"name":"a","rules":[{"path":"a"}]}`,
		"both":               `{"name":"a","rules":[{"path":"a","deny":true,"capabilities":["read"]}]}`,
		"unknown capability": `{"name":"a","rules":[{"path":"a","capabilities":["sudo"]}]}`,
		"star in middle":     `{"name":"a","rules":[{"path":"a/*/b","deny":true}]}`,
		"partial wildcard":   `{"name":"a","rules":[{"path":"a/db*","deny":true}]}`,
		"empty segment":      `{"name":"a","rules":[{"path":"a//b","deny":true}]}`,
		"dotdot":             `{"name":"a","rules":[{"path":"a/../b","deny":true}]}`,
		"bad char":           `{"name":"a","rules":[{"path":"a/b c","deny":true}]}`,
		"empty path":         `{"name":"a","rules":[{"path":"","deny":true}]}`,
	}
	for name, js := range cases {
		if _, err := Parse([]byte(js)); err == nil {
			t.Errorf("%s: accepted %s", name, js)
		}
	}
}

func TestValidPath(t *testing.T) {
	for _, ok := range []string{"a", "prod/orders/db", "a.b/c_d/e-f/V2"} {
		if err := ValidPath(ok); err != nil {
			t.Errorf("%q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "/a", "a/", "a//b", ".", "a/./b", "a/../b", "a b", "a/ü", "a\\b", "a/*", "a\x00b"} {
		if err := ValidPath(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func FuzzAllowed(f *testing.F) {
	f.Add("prod/+/db", "prod/orders/db")
	f.Add("prod/*", "prod/a/b")
	f.Fuzz(func(t *testing.T, pattern, path string) {
		p, err := Parse([]byte(`{"name":"f","rules":[{"path":` + quote(pattern) + `,"capabilities":["read"]}]}`))
		if err != nil || ValidPath(path) != nil {
			return
		}
		got := Allowed([]*Policy{p}, path, Read)
		if pattern == path && !got {
			t.Fatalf("exact pattern %q did not match itself", pattern)
		}
		if got && Allowed([]*Policy{p}, path, Delete) {
			t.Fatal("read-only rule granted delete")
		}
	})
}

func quote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}
