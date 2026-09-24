// Package policy decides whether an identity may perform an operation on a path.
//
// Rules: deny by default; any matching deny rule wins; otherwise the request is
// allowed if any matching rule, in any attached policy, grants the capability.
// Narrowing is done with deny rules, never by rule ordering or specificity.
//
// Path patterns are matched segment by segment, case-sensitively:
//
//	prod/orders/db   exact path
//	prod/+/db        "+" matches exactly one segment
//	prod/orders/*    "*" (last segment only) matches one or more remaining segments
package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

type Capability string

const (
	Read   Capability = "read"
	List   Capability = "list"
	Create Capability = "create"
	Update Capability = "update"
	Delete Capability = "delete"
	Rotate Capability = "rotate"
)

var known = []Capability{Read, List, Create, Update, Delete, Rotate}

// Rule grants capabilities on a path pattern, or denies everything on it.
type Rule struct {
	Path         string       `json:"path"`
	Capabilities []Capability `json:"capabilities,omitempty"`
	Deny         bool         `json:"deny,omitempty"`

	segs []string
}

type Policy struct {
	Name  string `json:"name"`
	Rules []Rule `json:"rules"`
}

// Parse decodes and validates a JSON policy. Unknown fields are rejected so a
// typo ("capabilites") can't silently grant nothing or everything.
func Parse(data []byte) (*Policy, error) {
	var p Policy
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("policy: trailing data")
	}
	if p.Name == "" {
		return nil, fmt.Errorf("policy: name is required")
	}
	if len(p.Rules) == 0 {
		return nil, fmt.Errorf("policy %q: no rules", p.Name)
	}
	for i := range p.Rules {
		r := &p.Rules[i]
		if err := validatePattern(r.Path); err != nil {
			return nil, fmt.Errorf("policy %q rule %d: %w", p.Name, i, err)
		}
		if r.Deny == (len(r.Capabilities) > 0) {
			return nil, fmt.Errorf("policy %q rule %d: set either deny or capabilities", p.Name, i)
		}
		for _, c := range r.Capabilities {
			if !slices.Contains(known, c) {
				return nil, fmt.Errorf("policy %q rule %d: unknown capability %q", p.Name, i, c)
			}
		}
		r.segs = strings.Split(r.Path, "/")
	}
	return &p, nil
}

// ValidPath reports whether path is a well-formed secret path: non-empty
// segments of [A-Za-z0-9._-], no "." or ".." segments, no leading or
// trailing slash. The API must reject anything else before calling Allowed.
func ValidPath(path string) error {
	if path == "" {
		return fmt.Errorf("empty path")
	}
	for _, s := range strings.Split(path, "/") {
		if s == "" || s == "." || s == ".." {
			return fmt.Errorf("invalid path %q", path)
		}
		for _, c := range s {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
				return fmt.Errorf("invalid character %q in path %q", c, path)
			}
		}
	}
	return nil
}

func validatePattern(pattern string) error {
	segs := strings.Split(pattern, "/")
	for i, s := range segs {
		switch {
		case s == "+":
		case s == "*":
			if i != len(segs)-1 {
				return fmt.Errorf("pattern %q: * is only allowed as the last segment", pattern)
			}
		case strings.ContainsAny(s, "*+"):
			return fmt.Errorf("pattern %q: wildcards must be whole segments", pattern)
		default:
			if err := ValidPath(s); err != nil {
				return fmt.Errorf("pattern %q: %w", pattern, err)
			}
		}
	}
	return nil
}

func (r *Rule) matches(path []string) bool {
	for i, s := range r.segs {
		if s == "*" {
			return len(path) > i
		}
		if i >= len(path) || (s != "+" && s != path[i]) {
			return false
		}
	}
	return len(path) == len(r.segs)
}

// Allowed evaluates every rule of every policy attached to the caller.
// path must already have passed ValidPath.
func Allowed(policies []*Policy, path string, c Capability) bool {
	segs := strings.Split(path, "/")
	granted := false
	for _, p := range policies {
		for i := range p.Rules {
			r := &p.Rules[i]
			if !r.matches(segs) {
				continue
			}
			if r.Deny {
				return false
			}
			if slices.Contains(r.Capabilities, c) {
				granted = true
			}
		}
	}
	return granted
}
