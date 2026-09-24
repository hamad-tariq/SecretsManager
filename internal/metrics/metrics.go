// Package metrics keeps counters and gauges and writes them in the
// Prometheus text format, so any Prometheus-compatible scraper can collect
// them (no client library needed).
package metrics

import (
	"fmt"
	"io"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
)

type Registry struct {
	mu       sync.Mutex
	counters map[string]map[string]float64 // name → labels → value
	gauges   map[string]func() []Sample    // name → current samples
	help     map[string]string
}

// Sample is one gauge value with its labels (k, v, k, v, ...).
type Sample struct {
	Labels []string
	Value  float64
}

func New() *Registry {
	return &Registry{counters: map[string]map[string]float64{}, gauges: map[string]func() []Sample{}, help: map[string]string{}}
}

// Add increments counter name by v. labels are k, v pairs. A nil Registry
// ignores everything, so callers need no checks.
func (r *Registry) Add(name, help string, v float64, labels ...string) {
	if r == nil {
		return
	}
	key := labelString(labels)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.counters[name] == nil {
		r.counters[name] = map[string]float64{}
		r.help[name] = help
	}
	r.counters[name][key] += v
}

// Gauge registers a function that reports name's current samples at scrape time.
func (r *Registry) Gauge(name, help string, f func() []Sample) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.gauges[name] = f
	r.help[name] = help
}

// One is a single unlabelled gauge sample.
func One(v float64) []Sample { return []Sample{{Value: v}} }

// Bool is 1 or 0.
func Bool(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func labelString(labels []string) string {
	var b strings.Builder
	for i := 0; i+1 < len(labels); i += 2 {
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(labels[i] + "=" + strconv.Quote(labels[i+1]))
	}
	return b.String()
}

// Write writes every metric, sorted by name, in Prometheus text format.
// Gauge functions run without the lock held (they may be slow).
func (r *Registry) Write(w io.Writer) error {
	r.mu.Lock()
	type counter struct {
		name   string
		values map[string]float64
	}
	var counters []counter
	for name, vals := range r.counters {
		counters = append(counters, counter{name, maps.Clone(vals)})
	}
	gauges, help := maps.Clone(r.gauges), maps.Clone(r.help)
	r.mu.Unlock()

	var names []string
	byName := map[string]func() (string, []string){}
	for _, c := range counters {
		names = append(names, c.name)
		byName[c.name] = func() (string, []string) {
			var lines []string
			for labels, v := range c.values {
				lines = append(lines, line(c.name, labels, v))
			}
			return "counter", lines
		}
	}
	for name, f := range gauges {
		names = append(names, name)
		byName[name] = func() (string, []string) {
			var lines []string
			for _, s := range f() {
				lines = append(lines, line(name, labelString(s.Labels), s.Value))
			}
			return "gauge", lines
		}
	}
	slices.Sort(names)
	for _, name := range names {
		typ, lines := byName[name]()
		slices.Sort(lines)
		if _, err := fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n%s", name, help[name], name, typ, strings.Join(lines, "")); err != nil {
			return err
		}
	}
	return nil
}

func line(name, labels string, v float64) string {
	if labels != "" {
		name += "{" + labels + "}"
	}
	return name + " " + strconv.FormatFloat(v, 'g', -1, 64) + "\n"
}
