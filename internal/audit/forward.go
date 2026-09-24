package audit

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Forwarder ships the local audit log to a remote collector the nodes can
// only append to (e.g. rsyslog or syslog-ng with write-once storage), as
// syslog over TLS (RFC 5425 framing, RFC 5424 messages, facility "log audit").
//
// The local file is the buffer: lines are sent from a saved offset, so a
// collector outage only delays them. If more than MaxLag bytes are waiting,
// Check fails, and a Logger gated on it refuses new entries: requests fail
// rather than go unrecorded off-host.
//
// Syslog has no acknowledgements. A line's offset is committed once it has
// been flushed and the collector hasn't hung up for `settle` afterwards;
// otherwise it's re-sent (duplicates are visible by sequence number).
//
// ponytail: a collector that dies without closing the connection (power
// loss) can still lose what was in flight; the local file keeps everything.
// Use RELP or an acknowledging receiver if that gap matters.
type Forwarder struct {
	Path     string      // local audit log
	Addr     string      // collector host:port
	TLS      *tls.Config // collector CA; our node certificate for mTLS
	Hostname string      // syslog HOSTNAME field (the node ID)
	MaxLag   int64       // bytes; default 64 MiB
	Log      *slog.Logger

	sent       atomic.Int64  // offset in Path forwarded so far
	maxBackoff time.Duration // between reconnects; default 30s
}

func (f *Forwarder) offsetPath() string { return f.Path + ".forwarded" }

// Start loads the saved offset. Call it before gating a Logger on Check.
func (f *Forwarder) Start() error {
	if f.MaxLag <= 0 {
		f.MaxLag = 64 << 20
	}
	if f.Log == nil {
		f.Log = slog.Default()
	}
	if f.maxBackoff == 0 {
		f.maxBackoff = 30 * time.Second
	}
	b, err := os.ReadFile(f.offsetPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil || n < 0 {
		return fmt.Errorf("audit: bad forwarding offset in %s", f.offsetPath())
	}
	f.sent.Store(n)
	return f.checkOffset()
}

// checkOffset fails if the local log no longer extends past what was already
// forwarded, or doesn't end a line there: it was truncated, replaced or
// restored from an older copy. Forwarding from that offset would silently
// skip records, so the forwarder (and, through Check, every request) stops
// until someone looks. Deleting the .forwarded file re-sends from the start.
func (f *Forwarder) checkOffset() error {
	n := f.sent.Load()
	if n == 0 {
		return nil
	}
	file, err := os.Open(f.Path)
	if err != nil {
		return err
	}
	defer file.Close()
	b := make([]byte, 1)
	if _, err := file.ReadAt(b, n-1); err != nil || b[0] != '\n' {
		return fmt.Errorf("audit: %s is shorter than, or differs from, what was already forwarded (offset %d): truncated or replaced? Investigate, then delete %s to re-send it all", f.Path, n, f.offsetPath())
	}
	return nil
}

// Lag is how many bytes of the local log haven't been forwarded yet.
func (f *Forwarder) Lag() int64 {
	st, err := os.Stat(f.Path)
	if err != nil {
		return 0
	}
	return max(st.Size()-f.sent.Load(), 0)
}

// Check fails while too much is waiting to be forwarded, or when the local
// log no longer matches what was forwarded.
func (f *Forwarder) Check() error {
	if st, err := os.Stat(f.Path); err == nil && st.Size() < f.sent.Load() {
		return fmt.Errorf("audit: %s is shorter than what was already forwarded; refusing new entries", f.Path)
	}
	if lag := f.Lag(); lag > f.MaxLag {
		return fmt.Errorf("audit: %d bytes not yet forwarded to %s (limit %d); refusing new entries", lag, f.Addr, f.MaxLag)
	}
	return nil
}

// Run forwards until ctx ends, reconnecting with backoff.
func (f *Forwarder) Run(ctx context.Context) {
	backoff := min(time.Second, f.maxBackoff)
	for ctx.Err() == nil {
		before := f.sent.Load()
		err := f.session(ctx)
		if ctx.Err() != nil {
			return
		}
		if f.sent.Load() > before {
			backoff = min(time.Second, f.maxBackoff) // it was working: retry quickly
		}
		f.Log.Warn("audit forwarding interrupted", "collector", f.Addr, "lag_bytes", f.Lag(), "err", err, "retry_in", backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, f.maxBackoff)
	}
}

// settle is how long flushed data must go without the collector hanging up
// before its offset is committed. A collector that closes or resets the
// connection is noticed within it, and the unconfirmed lines are re-sent.
const settle = 200 * time.Millisecond

var errCollectorGone = errors.New("audit: collector closed the connection")

// session holds one connection and sends new complete lines as they appear.
func (f *Forwarder) session(ctx context.Context) error {
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 10 * time.Second}, Config: f.TLS}
	conn, err := d.DialContext(ctx, "tcp", f.Addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	// The collector never sends anything: a read returning means it hung up.
	gone := make(chan struct{})
	go func() { _, _ = conn.Read(make([]byte, 1)); close(gone) }()

	file, err := os.Open(f.Path)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := f.checkOffset(); err != nil {
		return err
	}
	pos := f.sent.Load() // end of what's been written to the connection
	if _, err := file.Seek(pos, io.SeekStart); err != nil {
		return err
	}
	rd := bufio.NewReader(file)
	w := bufio.NewWriter(conn)
	var partial []byte
	// flushed/flushedAt: the last flush not yet committed.
	flushed, flushedAt := int64(-1), time.Time{}
	flush := func() error {
		if err := w.Flush(); err != nil {
			return err
		}
		if flushed < 0 {
			flushed, flushedAt = pos, time.Now()
		}
		return nil
	}
	commitSettled := func() error {
		select {
		case <-gone:
			return errCollectorGone
		default:
		}
		if flushed >= 0 && time.Since(flushedAt) >= settle {
			f.sent.Store(flushed)
			flushed = -1
			return f.saveOffset()
		}
		return nil
	}
	for {
		if err := commitSettled(); err != nil {
			return err
		}
		line, err := rd.ReadBytes('\n')
		partial = append(partial, line...)
		if errors.Is(err, io.EOF) {
			if err := flush(); err != nil {
				return err
			}
			select {
			case <-ctx.Done():
				return nil
			case <-gone:
				return errCollectorGone
			case <-time.After(settle):
			}
			// Everything flushed so far has now settled.
			if flushed >= 0 {
				flushed = pos
			}
			continue
		}
		if err != nil {
			return err
		}
		msg := fmt.Sprintf("<110>1 %s %s smd - - - %s", time.Now().UTC().Format(time.RFC3339Nano), f.Hostname,
			strings.TrimSuffix(string(partial), "\n"))
		if _, err := fmt.Fprintf(w, "%d %s", len(msg), msg); err != nil {
			return err
		}
		pos += int64(len(partial))
		partial = partial[:0]
		if pos-f.sent.Load() >= 256<<10 && flushed < 0 { // busy log: don't wait for a quiet moment
			if err := flush(); err != nil {
				return err
			}
		}
	}
}

func (f *Forwarder) saveOffset() error {
	tmp := f.offsetPath() + ".tmp"
	if err := os.WriteFile(tmp, []byte(strconv.FormatInt(f.sent.Load(), 10)), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, f.offsetPath())
}
