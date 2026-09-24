// Command smctl is the operator CLI.
//
//	smctl [-addr host:port[,host:port...]] [-cert admin.pem -key admin.key -ca root.pem] <group> <command> [flags] [args]
//
// Connection flags default to $SM_ADDR, $SM_CERT, $SM_KEY and $SM_CA. With
// several addresses, commands go to the first that answers; per-node commands
// (unseal, status, seal -all) go to every address.
//
// Secret input (values, shares) is read from stdin or a no-echo prompt, never
// from arguments: those end up in shell history and process listings.
package main

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/hamad-tariq/SecretsManager/internal/audit"
	"github.com/hamad-tariq/SecretsManager/internal/pki"
	"github.com/hamad-tariq/SecretsManager/internal/snapshot"
)

// version is set at release build time (scripts/release.sh).
var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// errUsage makes run exit with status 2 after printing usage.
var errUsage = errors.New("usage")

type cli struct {
	in     *bufio.Reader
	tty    bool // stdin is a terminal: prompt without echo
	out    io.Writer
	errw   io.Writer
	addrs  []string
	cert   string
	key    string
	ca     string
	client *http.Client
}

type command struct {
	usage string
	run   func(c *cli, args []string) error
}

var commands = map[string]command{
	"operator status": {"", (*cli).status},
	"operator init":   {"-shares N -threshold M [-recipient age1...]...", (*cli).initCmd},
	"operator unseal": {"(share read from stdin/prompt; sent to every -addr)", (*cli).unseal},
	"operator seal":   {"[-all]", (*cli).seal},
	"operator rotate": {"", (*cli).rotate},
	"operator rekey":  {"-shares N -threshold M [-recipient age1...]... (current shares read from stdin/prompt)", (*cli).rekey},

	"operator root-admin":  {"-identity admin/NAME   (hand root to another admin; current shares from stdin/prompt)", (*cli).rootAdmin},
	"operator members":     {"(leader, voters, member addresses)", (*cli).members},
	"operator remove-node": {"<node-id>   (take a dead node out so quorum counts the rest)", (*cli).removeNode},
	"operator step-down":   {"(hand leadership to another node, e.g. before upgrading the leader)", (*cli).stepDown},

	"snapshot save":    {"-out FILE   (encrypted as stored; restoring needs the current shares)", (*cli).snapshotSave},
	"snapshot restore": {"<file>   (into a new, empty cluster; then unseal with the snapshot's shares)", (*cli).snapshotRestore},
	"snapshot verify":  {"<file>   (offline checksum check)", (*cli).snapshotVerify},

	"kv get":      {"[-reveal] [-version N | -label L] <path>", (*cli).kvGet},
	"kv put":      {"[-cas N] <path>   (value read from stdin/prompt)", (*cli).kvPut},
	"kv list":     {"[prefix]", (*cli).kvList},
	"kv history":  {"<path>", (*cli).kvHistory},
	"kv delete":   {"<path>", (*cli).kvDelete},
	"kv undelete": {"<path>", (*cli).kvUndelete},
	"kv destroy":  {"<path>", (*cli).kvDestroy},

	"policy write":  {"<name> <file.json>", (*cli).policyWrite},
	"policy read":   {"<name>", (*cli).policyRead},
	"policy list":   {"", (*cli).policyList},
	"policy delete": {"<name>", (*cli).policyDelete},

	"identity bind":   {"<kind>/<name> <policy>[,<policy>...]", (*cli).identityBind},
	"identity show":   {"<kind>/<name>", (*cli).identityShow},
	"identity unbind": {"<kind>/<name>", (*cli).identityUnbind},

	"pki root-init":    {"-out DIR [-ttl 87600h]   (run offline)", (*cli).pkiRoot},
	"pki intermediate": {"-ca-cert root.pem -ca-key root.key -out DIR [-ttl 8760h]   (run offline)", (*cli).pkiIntermediate},
	"pki issue":        {"-ca-cert inter.pem -ca-key inter.key -kind svc|admin|node -name N [-host H]... [-ttl D] -out DIR", (*cli).pkiIssue},
	"pki upload":       {"-cert intermediate.pem -key intermediate.key   (cluster then issues service certificates)", (*cli).pkiUpload},

	"enroll token":    {"-service NAME [-ttl 15m]   (single-use token for sm-agent -auth token)", (*cli).enrollToken},
	"auth kubernetes": {"-host https://k8s:6443 -ca-file ca.crt -reviewer-token-file f -audience sm -role ns/sa=service...", (*cli).authKubernetes},

	"rotation set":    {"-interval 720h -plugin random|postgres|mysql|http [-param k=v]... <path>", (*cli).rotationSet},
	"rotation get":    {"<path>   (settings and progress)", (*cli).rotationGet},
	"rotation now":    {"<path>   (rotate at the next check, clearing any backoff)", (*cli).rotationNow},
	"rotation delete": {"<path>   (stop rotating; the secret is kept)", (*cli).rotationDelete},

	"db write-role":  {"<name> <role.json>   (plugin, admin, grants, default_ttl, max_ttl)", (*cli).dbWriteRole},
	"db read-role":   {"<name>", (*cli).dbReadRole},
	"db delete-role": {"<name>   (existing leases run their course)", (*cli).dbDeleteRole},
	"db creds":       {"[-ttl 30m] <role>   (a new database user; prints the password)", (*cli).dbCreds},

	"lease list":          {"[prefix]   (e.g. db/orders-rw)", (*cli).leaseList},
	"lease revoke-prefix": {"<prefix>   (drops the users and kills their sessions now; a full lease ID revokes one)", (*cli).leaseRevokePrefix},

	"cert revoke":      {"-cert FILE.pem (it and all its renewals) | -serial HEX | -identity kind/name  [-reason TEXT]", (*cli).certRevoke},
	"cert unrevoke":    {"-serial HEX | -identity kind/name | -lineage KEY", (*cli).certUnrevoke},
	"cert revocations": {"(list revoked serials and identities)", (*cli).certRevocations},

	"audit verify": {"[-head SEQ:HASH] <audit.log>   (-head: the collector's last record, to catch truncation)", (*cli).auditVerify},
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	c := &cli{in: bufio.NewReader(stdin), out: stdout, errw: stderr}
	if f, ok := stdin.(*os.File); ok {
		c.tty = term.IsTerminal(int(f.Fd()))
	}
	fs := flag.NewFlagSet("smctl", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", os.Getenv("SM_ADDR"), "node API address(es), comma-separated")
	fs.StringVar(&c.cert, "cert", os.Getenv("SM_CERT"), "client certificate PEM")
	fs.StringVar(&c.key, "key", os.Getenv("SM_KEY"), "client key PEM")
	fs.StringVar(&c.ca, "ca", os.Getenv("SM_CA"), "root CA PEM")
	showVersion := fs.Bool("version", false, "print the version and exit")
	fs.Usage = func() { c.usage() }
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintln(stdout, "smctl", version)
		return 0
	}
	rest := fs.Args()
	if len(rest) < 2 {
		c.usage()
		return 2
	}
	cmd, ok := commands[rest[0]+" "+rest[1]]
	if !ok {
		fmt.Fprintf(stderr, "smctl: unknown command %q\n", rest[0]+" "+rest[1])
		c.usage()
		return 2
	}
	for _, a := range strings.Split(*addr, ",") {
		if a = strings.TrimSpace(a); a != "" {
			c.addrs = append(c.addrs, a)
		}
	}
	err := cmd.run(c, rest[2:])
	if errors.Is(err, errUsage) {
		fmt.Fprintf(stderr, "usage: smctl %s %s %s\n", rest[0], rest[1], cmd.usage)
		return 2
	}
	if err != nil {
		fmt.Fprintln(stderr, "smctl:", err)
		return 1
	}
	return 0
}

func (c *cli) usage() {
	fmt.Fprintln(c.errw, "usage: smctl [-addr a,b,c] [-cert f] [-key f] [-ca f] <group> <command> ...")
	names := make([]string, 0, len(commands))
	for n := range commands {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		fmt.Fprintf(c.errw, "  %-18s %s\n", n, commands[n].usage)
	}
}

// ---- input ----

// readSecret reads one line: from a no-echo prompt on a terminal, else stdin.
func (c *cli) readSecret(prompt string) (string, error) {
	if c.tty {
		fmt.Fprint(c.errw, prompt)
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(c.errw)
		return strings.TrimSpace(string(b)), err
	}
	line, err := c.in.ReadString('\n')
	if err != nil && (err != io.EOF || line == "") {
		return "", fmt.Errorf("reading %s: %w", strings.TrimSuffix(prompt, ": "), err)
	}
	return strings.TrimSpace(line), nil
}

// readValue reads a secret value: one no-echo line on a terminal, else all of
// stdin exactly (so files with trailing newlines survive).
func (c *cli) readValue() ([]byte, error) {
	if c.tty {
		v, err := c.readSecret("Value: ")
		return []byte(v), err
	}
	return io.ReadAll(c.in)
}

// ---- HTTP ----

func (c *cli) httpClient() (*http.Client, error) {
	if c.client != nil {
		return c.client, nil
	}
	if len(c.addrs) == 0 {
		return nil, errors.New("no server address: use -addr or $SM_ADDR")
	}
	if c.ca == "" {
		return nil, errors.New("no CA: use -ca or $SM_CA")
	}
	caPEM, err := os.ReadFile(c.ca)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("%s: no certificates", c.ca)
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}
	if c.cert != "" {
		pair, err := tls.LoadX509KeyPair(c.cert, c.key)
		if err != nil {
			return nil, err
		}
		cfg.Certificates = []tls.Certificate{pair}
	}
	c.client = &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg}}
	return c.client, nil
}

type apiError struct {
	status int
	msg    string
}

func (e *apiError) Error() string { return fmt.Sprintf("%d: %s", e.status, e.msg) }

// callAt sends one request to one node and decodes a JSON reply into out.
func (c *cli) callAt(addr, method, path string, body, out any) error {
	hc, err := c.httpClient()
	if err != nil {
		return err
	}
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case []byte:
		rd = bytes.NewReader(b)
	default:
		j, err := json.Marshal(b)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(j)
	}
	req, err := http.NewRequest(method, "https://"+addr+path, rd)
	if err != nil {
		return err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(data, &e) != nil || e.Error == "" {
			e.Error = http.StatusText(resp.StatusCode)
		}
		return &apiError{resp.StatusCode, e.Error}
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

// call tries each address until one answers (any HTTP response counts).
func (c *cli) call(method, path string, body, out any) error {
	if _, err := c.httpClient(); err != nil {
		return err
	}
	var last error
	for _, a := range c.addrs {
		err := c.callAt(a, method, path, body, out)
		var ae *apiError
		if err == nil || errors.As(err, &ae) {
			return err
		}
		last = err
	}
	return last
}

func (c *cli) printJSON(v any) error {
	enc := json.NewEncoder(c.out)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// flags parses subcommand flags and returns the positional args.
func flags(args []string, def func(fs *flag.FlagSet)) ([]string, error) {
	fs := flag.NewFlagSet("", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if def != nil {
		def(fs)
	}
	if err := fs.Parse(args); err != nil {
		return nil, errUsage
	}
	return fs.Args(), nil
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

// ---- operator ----

func (c *cli) status(args []string) error {
	if _, err := flags(args, nil); err != nil {
		return err
	}
	if _, err := c.httpClient(); err != nil {
		return err
	}
	out := map[string]any{}
	for _, a := range c.addrs {
		out[a] = c.health(a)
	}
	return c.printJSON(out)
}

// health returns a node's seal status. Sealed and uninitialised nodes answer
// 503/501 with the same JSON body, so the body is decoded whatever the status.
func (c *cli) health(addr string) map[string]any {
	st := map[string]any{}
	resp, err := c.client.Get("https://" + addr + "/v1/sys/health")
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		return map[string]any{"error": err.Error()}
	}
	return st
}

func (c *cli) initCmd(args []string) error {
	var shares, threshold int
	var recips multi
	rest, err := flags(args, func(fs *flag.FlagSet) {
		fs.IntVar(&shares, "shares", 5, "")
		fs.IntVar(&threshold, "threshold", 3, "")
		fs.Var(&recips, "recipient", "")
	})
	if err != nil || len(rest) != 0 {
		return errUsage
	}
	body := map[string]any{"shares": shares, "threshold": threshold}
	if len(recips) > 0 {
		body["recipients"] = []string(recips)
	}
	var out map[string]any
	if err := c.call("POST", "/v1/sys/init", body, &out); err != nil {
		return err
	}
	fmt.Fprintln(c.errw, "Distribute each share to a different holder NOW. They are shown only once and never stored.")
	return c.printJSON(out)
}

func (c *cli) unseal(args []string) error {
	if rest, err := flags(args, nil); err != nil || len(rest) != 0 {
		return errUsage
	}
	share, err := c.readSecret("Unseal share: ")
	if err != nil {
		return err
	}
	if _, err := c.httpClient(); err != nil {
		return err
	}
	out := map[string]any{}
	var failed int
	for _, a := range c.addrs {
		var st map[string]any
		if err := c.callAt(a, "POST", "/v1/sys/unseal", map[string]string{"share": share}, &st); err != nil {
			failed++
			out[a] = map[string]string{"error": err.Error()}
			continue
		}
		out[a] = st
	}
	if err := c.printJSON(out); err != nil {
		return err
	}
	if failed > 0 {
		return fmt.Errorf("unseal failed on %d of %d nodes", failed, len(c.addrs))
	}
	return nil
}

func (c *cli) seal(args []string) error {
	var all bool
	if rest, err := flags(args, func(fs *flag.FlagSet) { fs.BoolVar(&all, "all", false, "") }); err != nil || len(rest) != 0 {
		return errUsage
	}
	if !all {
		return c.call("POST", "/v1/sys/seal", nil, nil)
	}
	if _, err := c.httpClient(); err != nil {
		return err
	}
	var errs []error
	for _, a := range c.addrs {
		if err := c.callAt(a, "POST", "/v1/sys/seal", nil, nil); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", a, err))
		}
	}
	return errors.Join(errs...)
}

func (c *cli) rotate(args []string) error {
	if rest, err := flags(args, nil); err != nil || len(rest) != 0 {
		return errUsage
	}
	var out map[string]any
	if err := c.call("POST", "/v1/sys/rotate", nil, &out); err != nil {
		return err
	}
	return c.printJSON(out)
}

// rekey collects current shares one at a time (each holder types theirs at
// the prompt), then submits them together.
func (c *cli) rekey(args []string) error {
	var shares, threshold, current int
	var recips multi
	rest, err := flags(args, func(fs *flag.FlagSet) {
		fs.IntVar(&shares, "shares", 5, "")
		fs.IntVar(&threshold, "threshold", 3, "")
		fs.IntVar(&current, "current-threshold", 0, "")
		fs.Var(&recips, "recipient", "")
	})
	if err != nil || len(rest) != 0 {
		return errUsage
	}
	if current == 0 {
		if _, err := c.httpClient(); err != nil {
			return err
		}
		t, _ := c.health(c.addrs[0])["threshold"].(float64)
		if current = int(t); current == 0 {
			return errors.New("could not read the current threshold; pass -current-threshold")
		}
	}
	var have []string
	for i := range current {
		s, err := c.readSecret(fmt.Sprintf("Current share %d of %d: ", i+1, current))
		if err != nil {
			return err
		}
		have = append(have, s)
	}
	body := map[string]any{"shares": have, "new_shares": shares, "threshold": threshold}
	if len(recips) > 0 {
		body["recipients"] = []string(recips)
	}
	var out map[string]any
	if err := c.call("POST", "/v1/sys/rekey", body, &out); err != nil {
		return err
	}
	if w, _ := out["warning"].(string); w != "" {
		fmt.Fprintln(c.errw, "WARNING:", w)
	}
	fmt.Fprintln(c.errw, "Old shares no longer work. Distribute the new shares NOW; they are shown only once.")
	return c.printJSON(out)
}

// ---- kv ----

func onePath(rest []string) (string, error) {
	if len(rest) != 1 || rest[0] == "" {
		return "", errUsage
	}
	return strings.Trim(rest[0], "/"), nil
}

func (c *cli) kvGet(args []string) error {
	var reveal bool
	var version int
	var label string
	rest, err := flags(args, func(fs *flag.FlagSet) {
		fs.BoolVar(&reveal, "reveal", false, "")
		fs.IntVar(&version, "version", 0, "")
		fs.StringVar(&label, "label", "", "")
	})
	if err != nil {
		return err
	}
	p, err := onePath(rest)
	if err != nil {
		return err
	}
	q := ""
	switch {
	case version > 0:
		q = fmt.Sprintf("?version=%d", version)
	case label != "":
		q = "?label=" + label
	}
	var out map[string]any
	if err := c.call("GET", "/v1/kv/"+p+q, nil, &out); err != nil {
		return err
	}
	if reveal {
		_, err := fmt.Fprint(c.out, out["value"])
		return err
	}
	out["value"] = "(hidden; use -reveal)"
	return c.printJSON(out)
}

func (c *cli) kvPut(args []string) error {
	cas := -1
	rest, err := flags(args, func(fs *flag.FlagSet) { fs.IntVar(&cas, "cas", -1, "") })
	if err != nil {
		return err
	}
	p, err := onePath(rest)
	if err != nil {
		return err
	}
	value, err := c.readValue()
	if err != nil {
		return err
	}
	body := map[string]any{"value": string(value)}
	if cas >= 0 {
		body["cas"] = cas
	}
	var out map[string]any
	if err := c.call("PUT", "/v1/kv/"+p, body, &out); err != nil {
		return err
	}
	return c.printJSON(out)
}

func (c *cli) kvList(args []string) error {
	rest, err := flags(args, nil)
	if err != nil || len(rest) > 1 {
		return errUsage
	}
	prefix := ""
	if len(rest) == 1 {
		prefix = strings.Trim(rest[0], "/") + "/"
	}
	var out map[string]any
	if err := c.call("GET", "/v1/kv/"+prefix+"?list", nil, &out); err != nil {
		return err
	}
	return c.printJSON(out)
}

func (c *cli) kvSimple(args []string, method, query string, print bool) error {
	rest, err := flags(args, nil)
	if err != nil {
		return err
	}
	p, err := onePath(rest)
	if err != nil {
		return err
	}
	var out map[string]any
	if err := c.call(method, "/v1/kv/"+p+query, nil, &out); err != nil {
		return err
	}
	if print {
		return c.printJSON(out)
	}
	return nil
}

func (c *cli) kvHistory(args []string) error  { return c.kvSimple(args, "GET", "?metadata", true) }
func (c *cli) kvDelete(args []string) error   { return c.kvSimple(args, "DELETE", "", false) }
func (c *cli) kvUndelete(args []string) error { return c.kvSimple(args, "POST", "?op=undelete", false) }
func (c *cli) kvDestroy(args []string) error  { return c.kvSimple(args, "DELETE", "?destroy", false) }

// ---- policies and identities ----

func (c *cli) policyWrite(args []string) error {
	rest, err := flags(args, nil)
	if err != nil || len(rest) != 2 {
		return errUsage
	}
	body, err := os.ReadFile(rest[1])
	if err != nil {
		return err
	}
	return c.call("PUT", "/v1/sys/policies/"+rest[0], body, nil)
}

func (c *cli) policyRead(args []string) error {
	rest, err := flags(args, nil)
	if err != nil || len(rest) != 1 {
		return errUsage
	}
	var out map[string]any
	if err := c.call("GET", "/v1/sys/policies/"+rest[0], nil, &out); err != nil {
		return err
	}
	return c.printJSON(out)
}

func (c *cli) policyList(args []string) error {
	if rest, err := flags(args, nil); err != nil || len(rest) != 0 {
		return errUsage
	}
	var out map[string]any
	if err := c.call("GET", "/v1/sys/policies", nil, &out); err != nil {
		return err
	}
	return c.printJSON(out)
}

func (c *cli) policyDelete(args []string) error {
	rest, err := flags(args, nil)
	if err != nil || len(rest) != 1 {
		return errUsage
	}
	return c.call("DELETE", "/v1/sys/policies/"+rest[0], nil, nil)
}

// identityPath checks "kind/name" and returns its API path.
func identityPath(s string) (string, error) {
	kind, name, ok := strings.Cut(s, "/")
	if !ok {
		return "", errUsage
	}
	if err := (pki.Identity{Kind: pki.Kind(kind), Name: name}).Validate(); err != nil {
		return "", err
	}
	return "/v1/sys/bindings/" + kind + "/" + name, nil
}

func (c *cli) identityBind(args []string) error {
	rest, err := flags(args, nil)
	if err != nil || len(rest) != 2 {
		return errUsage
	}
	p, err := identityPath(rest[0])
	if err != nil {
		return err
	}
	var out map[string]any
	if err := c.call("PUT", p, map[string][]string{"policies": strings.Split(rest[1], ",")}, &out); err != nil {
		return err
	}
	return c.printJSON(out)
}

func (c *cli) identityShow(args []string) error {
	rest, err := flags(args, nil)
	if err != nil || len(rest) != 1 {
		return errUsage
	}
	p, err := identityPath(rest[0])
	if err != nil {
		return err
	}
	var out map[string]any
	if err := c.call("GET", p, nil, &out); err != nil {
		return err
	}
	return c.printJSON(out)
}

func (c *cli) identityUnbind(args []string) error {
	rest, err := flags(args, nil)
	if err != nil || len(rest) != 1 {
		return errUsage
	}
	p, err := identityPath(rest[0])
	if err != nil {
		return err
	}
	return c.call("DELETE", p, nil, nil)
}

// ---- offline PKI ----

// writeNew writes a file that must not already exist (never overwrite keys).
func writeNew(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode) // #nosec G304 -- operator-chosen output path
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// saveCA writes name.pem (certificate, plus chain) and name.key (0600).
func saveCA(dir, name string, cert *x509.Certificate, key crypto.Signer, chain ...*x509.Certificate) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	certPEM := pki.EncodeCert(cert)
	for _, c := range chain {
		certPEM = append(certPEM, pki.EncodeCert(c)...)
	}
	ek, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return errors.New("only ECDSA keys are supported")
	}
	keyPEM, err := pki.EncodeKey(ek)
	if err != nil {
		return err
	}
	if err := writeNew(filepath.Join(dir, name+".key"), keyPEM, 0o600); err != nil {
		return err
	}
	return writeNew(filepath.Join(dir, name+".pem"), certPEM, 0o644)
}

func loadCA(certFile, keyFile string) (*pki.CA, []*x509.Certificate, error) {
	certPEM, err := os.ReadFile(certFile) // #nosec G304 -- operator-supplied path
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := os.ReadFile(keyFile) // #nosec G304 -- operator-supplied path
	if err != nil {
		return nil, nil, err
	}
	certs, err := pki.ParseCerts(certPEM)
	if err != nil {
		return nil, nil, err
	}
	key, err := pki.ParseKey(keyPEM)
	if err != nil {
		return nil, nil, err
	}
	if !certs[0].IsCA {
		return nil, nil, fmt.Errorf("%s is not a CA certificate", certFile)
	}
	return &pki.CA{Cert: certs[0], Key: key}, certs, nil
}

func (c *cli) pkiRoot(args []string) error {
	var out string
	var ttl time.Duration
	rest, err := flags(args, func(fs *flag.FlagSet) {
		fs.StringVar(&out, "out", "", "")
		fs.DurationVar(&ttl, "ttl", 10*365*24*time.Hour, "")
	})
	if err != nil || len(rest) != 0 || out == "" {
		return errUsage
	}
	root, err := pki.NewRoot("secrets manager root CA", ttl)
	if err != nil {
		return err
	}
	if err := saveCA(out, "root", root.Cert, root.Key); err != nil {
		return err
	}
	fmt.Fprintf(c.out, "wrote %s and %s; keep root.key offline\n", filepath.Join(out, "root.pem"), filepath.Join(out, "root.key"))
	return nil
}

func (c *cli) pkiIntermediate(args []string) error {
	var caCert, caKey, out string
	var ttl time.Duration
	rest, err := flags(args, func(fs *flag.FlagSet) {
		fs.StringVar(&caCert, "ca-cert", "", "")
		fs.StringVar(&caKey, "ca-key", "", "")
		fs.StringVar(&out, "out", "", "")
		fs.DurationVar(&ttl, "ttl", 365*24*time.Hour, "")
	})
	if err != nil || len(rest) != 0 || caCert == "" || caKey == "" || out == "" {
		return errUsage
	}
	root, _, err := loadCA(caCert, caKey)
	if err != nil {
		return err
	}
	inter, err := root.NewIntermediate("secrets manager intermediate CA", ttl)
	if err != nil {
		return err
	}
	if err := saveCA(out, "intermediate", inter.Cert, inter.Key); err != nil {
		return err
	}
	fmt.Fprintf(c.out, "wrote %s and %s\n", filepath.Join(out, "intermediate.pem"), filepath.Join(out, "intermediate.key"))
	return nil
}

func (c *cli) pkiIssue(args []string) error {
	var caCert, caKey, kind, name, out string
	var hosts multi
	var ttl time.Duration
	rest, err := flags(args, func(fs *flag.FlagSet) {
		fs.StringVar(&caCert, "ca-cert", "", "")
		fs.StringVar(&caKey, "ca-key", "", "")
		fs.StringVar(&kind, "kind", "", "")
		fs.StringVar(&name, "name", "", "")
		fs.Var(&hosts, "host", "")
		fs.DurationVar(&ttl, "ttl", 0, "")
		fs.StringVar(&out, "out", "", "")
	})
	if err != nil || len(rest) != 0 || caCert == "" || caKey == "" || kind == "" || name == "" || out == "" {
		return errUsage
	}
	ca, chain, err := loadCA(caCert, caKey)
	if err != nil {
		return err
	}
	key, err := pki.NewKey()
	if err != nil {
		return err
	}
	id := pki.Identity{Kind: pki.Kind(kind), Name: name}
	cert, err := ca.Issue(id, key.Public(), ttl, hosts...)
	if err != nil {
		return err
	}
	if err := saveCA(out, name, cert, key, chain...); err != nil {
		return err
	}
	fmt.Fprintf(c.out, "issued %s, valid until %s: %s, %s\n", id, cert.NotAfter.Format(time.RFC3339),
		filepath.Join(out, name+".pem"), filepath.Join(out, name+".key"))
	return nil
}

func (c *cli) pkiUpload(args []string) error {
	var certFile, keyFile string
	rest, err := flags(args, func(fs *flag.FlagSet) {
		fs.StringVar(&certFile, "cert", "", "")
		fs.StringVar(&keyFile, "key", "", "")
	})
	if err != nil || len(rest) != 0 || certFile == "" || keyFile == "" {
		return errUsage
	}
	certPEM, err := os.ReadFile(certFile) // #nosec G304 -- operator-supplied path
	if err != nil {
		return err
	}
	keyPEM, err := os.ReadFile(keyFile) // #nosec G304 -- operator-supplied path
	if err != nil {
		return err
	}
	var out map[string]any
	if err := c.call("PUT", "/v1/sys/pki/intermediate", map[string]string{"cert_pem": string(certPEM), "key_pem": string(keyPEM)}, &out); err != nil {
		return err
	}
	return c.printJSON(out)
}

// ---- service onboarding ----

func (c *cli) enrollToken(args []string) error {
	var service, ttl string
	rest, err := flags(args, func(fs *flag.FlagSet) {
		fs.StringVar(&service, "service", "", "")
		fs.StringVar(&ttl, "ttl", "", "")
	})
	if err != nil || len(rest) != 0 || service == "" {
		return errUsage
	}
	body := map[string]string{"service": service}
	if ttl != "" {
		body["ttl"] = ttl
	}
	var out map[string]any
	if err := c.call("POST", "/v1/sys/enroll-tokens", body, &out); err != nil {
		return err
	}
	fmt.Fprintln(c.errw, "Single use. Hand it to the service's sm-agent (-auth token -token-file ...) before it expires.")
	return c.printJSON(out)
}

func (c *cli) authKubernetes(args []string) error {
	var host, caFile, tokenFile, audience string
	var roles multi
	rest, err := flags(args, func(fs *flag.FlagSet) {
		fs.StringVar(&host, "host", "", "")
		fs.StringVar(&caFile, "ca-file", "", "")
		fs.StringVar(&tokenFile, "reviewer-token-file", "", "")
		fs.StringVar(&audience, "audience", "sm", "")
		fs.Var(&roles, "role", "")
	})
	if err != nil || len(rest) != 0 || host == "" || caFile == "" || tokenFile == "" || len(roles) == 0 {
		return errUsage
	}
	caPEM, err := os.ReadFile(caFile) // #nosec G304 -- operator-supplied path
	if err != nil {
		return err
	}
	tok, err := os.ReadFile(tokenFile) // #nosec G304 -- operator-supplied path
	if err != nil {
		return err
	}
	roleMap := map[string]string{}
	for _, r := range roles {
		sa, svc, ok := strings.Cut(r, "=")
		if !ok {
			return errUsage
		}
		roleMap[sa] = svc
	}
	var out map[string]any
	err = c.call("PUT", "/v1/sys/auth/kubernetes", map[string]any{"host": host, "ca_pem": string(caPEM),
		"reviewer_token": strings.TrimSpace(string(tok)), "audience": audience, "roles": roleMap}, &out)
	if err != nil {
		return err
	}
	return c.printJSON(out)
}

// ---- rotation ----

func (c *cli) rotationSet(args []string) error {
	var interval, plugin string
	var params multi
	rest, err := flags(args, func(fs *flag.FlagSet) {
		fs.StringVar(&interval, "interval", "", "")
		fs.StringVar(&plugin, "plugin", "", "")
		fs.Var(&params, "param", "")
	})
	if err != nil || interval == "" || plugin == "" {
		return errUsage
	}
	p, err := onePath(rest)
	if err != nil {
		return err
	}
	pm := map[string]string{}
	for _, kv := range params {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return errUsage
		}
		pm[k] = v
	}
	var out map[string]any
	if err := c.call("PUT", "/v1/sys/rotation/"+p, map[string]any{"interval": interval, "plugin": plugin, "params": pm}, &out); err != nil {
		return err
	}
	return c.printJSON(out)
}

func (c *cli) rotationSimple(args []string, method, query string) error {
	rest, err := flags(args, nil)
	if err != nil {
		return err
	}
	p, err := onePath(rest)
	if err != nil {
		return err
	}
	var out map[string]any
	if err := c.call(method, "/v1/sys/rotation/"+p+query, nil, &out); err != nil {
		return err
	}
	if out != nil {
		return c.printJSON(out)
	}
	return nil
}

func (c *cli) rotationGet(args []string) error    { return c.rotationSimple(args, "GET", "") }
func (c *cli) rotationNow(args []string) error    { return c.rotationSimple(args, "POST", "?op=rotate") }
func (c *cli) rotationDelete(args []string) error { return c.rotationSimple(args, "DELETE", "") }

// ---- revocation and root admin ----

func (c *cli) certRevoke(args []string) error {
	var serial, certFile, identity, reason string
	rest, err := flags(args, func(fs *flag.FlagSet) {
		fs.StringVar(&serial, "serial", "", "")
		fs.StringVar(&certFile, "cert", "", "")
		fs.StringVar(&identity, "identity", "", "")
		fs.StringVar(&reason, "reason", "", "")
	})
	if err != nil || len(rest) != 0 || btoi(serial != "")+btoi(certFile != "")+btoi(identity != "") != 1 {
		return errUsage
	}
	body := map[string]any{"reason": reason}
	switch {
	case certFile != "":
		pemBytes, err := os.ReadFile(certFile) // #nosec G304 -- operator-supplied path
		if err != nil {
			return err
		}
		cert, err := pki.ParseCert(pemBytes)
		if err != nil {
			return err
		}
		id, err := pki.IdentityFromCert(cert)
		if err != nil {
			return err
		}
		// The serial, and the lineage: every renewal of this certificate,
		// including any the holder (or a thief) already made.
		body["serial"], body["until"] = cert.SerialNumber.Text(16), cert.NotAfter
		body["identity"], body["login"] = id.String(), pki.LoginTime(cert)
	case serial != "":
		body["serial"] = serial
	default:
		body["identity"] = identity
	}
	var out map[string]any
	if err := c.call("POST", "/v1/sys/revocations", body, &out); err != nil {
		return err
	}
	return c.printJSON(out)
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (c *cli) certUnrevoke(args []string) error {
	var serial, identity, lineage string
	rest, err := flags(args, func(fs *flag.FlagSet) {
		fs.StringVar(&serial, "serial", "", "")
		fs.StringVar(&identity, "identity", "", "")
		fs.StringVar(&lineage, "lineage", "", "")
	})
	if err != nil || len(rest) != 0 || btoi(serial != "")+btoi(identity != "")+btoi(lineage != "") != 1 {
		return errUsage
	}
	q := "?serial=" + url.QueryEscape(serial)
	if identity != "" {
		q = "?identity=" + url.QueryEscape(identity)
	}
	if lineage != "" {
		q = "?lineage=" + url.QueryEscape(lineage)
	}
	var out map[string]any
	if err := c.call("DELETE", "/v1/sys/revocations"+q, nil, &out); err != nil {
		return err
	}
	return c.printJSON(out)
}

func (c *cli) certRevocations(args []string) error {
	if rest, err := flags(args, nil); err != nil || len(rest) != 0 {
		return errUsage
	}
	var out map[string]any
	if err := c.call("GET", "/v1/sys/revocations", nil, &out); err != nil {
		return err
	}
	return c.printJSON(out)
}

// rootAdmin hands root to another admin. Like rekey, it needs a threshold of
// current shares: a stolen root-admin certificate alone can't do it.
func (c *cli) rootAdmin(args []string) error {
	var identity string
	var current int
	rest, err := flags(args, func(fs *flag.FlagSet) {
		fs.StringVar(&identity, "identity", "", "")
		fs.IntVar(&current, "current-threshold", 0, "")
	})
	if err != nil || len(rest) != 0 || identity == "" {
		return errUsage
	}
	if current == 0 {
		if _, err := c.httpClient(); err != nil {
			return err
		}
		t, _ := c.health(c.addrs[0])["threshold"].(float64)
		if current = int(t); current == 0 {
			return errors.New("could not read the current threshold; pass -current-threshold")
		}
	}
	var have []string
	for i := range current {
		s, err := c.readSecret(fmt.Sprintf("Current share %d of %d: ", i+1, current))
		if err != nil {
			return err
		}
		have = append(have, s)
	}
	var out map[string]any
	if err := c.call("POST", "/v1/sys/root-admin", map[string]any{"identity": identity, "shares": have}, &out); err != nil {
		return err
	}
	fmt.Fprintln(c.errw, "Root handed over. Revoke the previous root admin's certificate or identity if it may be compromised.")
	return c.printJSON(out)
}

// ---- cluster and snapshots ----

func (c *cli) members(args []string) error {
	if rest, err := flags(args, nil); err != nil || len(rest) != 0 {
		return errUsage
	}
	var out map[string]any
	if err := c.call("GET", "/v1/sys/cluster", nil, &out); err != nil {
		return err
	}
	return c.printJSON(out)
}

func (c *cli) removeNode(args []string) error {
	return c.oneArg(args, "DELETE", "/v1/sys/cluster/members/")
}

func (c *cli) stepDown(args []string) error {
	if rest, err := flags(args, nil); err != nil || len(rest) != 0 {
		return errUsage
	}
	var out map[string]any
	if err := c.call("POST", "/v1/sys/cluster/step-down", nil, &out); err != nil {
		return err
	}
	return c.printJSON(out)
}

func (c *cli) snapshotSave(args []string) error {
	var out string
	rest, err := flags(args, func(fs *flag.FlagSet) { fs.StringVar(&out, "out", "", "") })
	if err != nil || len(rest) != 0 || out == "" {
		return errUsage
	}
	var raw json.RawMessage
	if err := c.call("GET", "/v1/sys/snapshot", nil, &raw); err != nil {
		return err
	}
	f, err := snapshot.Read(bytes.NewReader(raw)) // check it before calling it a backup
	if err != nil {
		return err
	}
	if err := writeNew(out, raw, 0o600); err != nil {
		return err
	}
	fmt.Fprintf(c.out, "saved %d keys to %s (sha256 %s)\n", f.Keys, out, f.SHA256)
	return nil
}

func (c *cli) snapshotRestore(args []string) error {
	rest, err := flags(args, nil)
	if err != nil || len(rest) != 1 {
		return errUsage
	}
	data, err := os.ReadFile(rest[0])
	if err != nil {
		return err
	}
	if _, err := snapshot.Read(bytes.NewReader(data)); err != nil {
		return err
	}
	var out map[string]any
	if err := c.call("POST", "/v1/sys/snapshot/restore", data, &out); err != nil {
		return err
	}
	fmt.Fprintln(c.errw, "Restored. Now unseal every node with the shares that were current when the snapshot was taken.")
	return c.printJSON(out)
}

func (c *cli) snapshotVerify(args []string) error {
	rest, err := flags(args, nil)
	if err != nil || len(rest) != 1 {
		return errUsage
	}
	file, err := os.Open(rest[0])
	if err != nil {
		return err
	}
	defer file.Close()
	f, err := snapshot.Read(file)
	if err != nil {
		return err
	}
	fmt.Fprintf(c.out, "ok: %d keys, taken %s, sha256 %s\n", f.Keys, f.Created.Format(time.RFC3339), f.SHA256)
	return nil
}

// ---- database credentials and leases ----

// oneArg runs method on base+arg and prints the JSON result, if any.
func (c *cli) oneArg(args []string, method, base string) error {
	rest, err := flags(args, nil)
	if err != nil || len(rest) != 1 || rest[0] == "" {
		return errUsage
	}
	var out map[string]any
	if err := c.call(method, base+strings.Trim(rest[0], "/"), nil, &out); err != nil {
		return err
	}
	if out != nil {
		return c.printJSON(out)
	}
	return nil
}

func (c *cli) dbWriteRole(args []string) error {
	rest, err := flags(args, nil)
	if err != nil || len(rest) != 2 {
		return errUsage
	}
	body, err := os.ReadFile(rest[1])
	if err != nil {
		return err
	}
	return c.call("PUT", "/v1/sys/db-roles/"+rest[0], body, nil)
}

func (c *cli) dbReadRole(args []string) error   { return c.oneArg(args, "GET", "/v1/sys/db-roles/") }
func (c *cli) dbDeleteRole(args []string) error { return c.oneArg(args, "DELETE", "/v1/sys/db-roles/") }

func (c *cli) dbCreds(args []string) error {
	var ttl string
	rest, err := flags(args, func(fs *flag.FlagSet) { fs.StringVar(&ttl, "ttl", "", "") })
	if err != nil || len(rest) != 1 {
		return errUsage
	}
	var out map[string]any
	if err := c.call("POST", "/v1/db/creds/"+rest[0], map[string]string{"ttl": ttl}, &out); err != nil {
		return err
	}
	return c.printJSON(out)
}

func (c *cli) leaseList(args []string) error {
	rest, err := flags(args, nil)
	if err != nil || len(rest) > 1 {
		return errUsage
	}
	prefix := ""
	if len(rest) == 1 {
		prefix = strings.Trim(rest[0], "/")
	}
	var out map[string]any
	if err := c.call("GET", "/v1/sys/leases/"+prefix, nil, &out); err != nil {
		return err
	}
	return c.printJSON(out)
}

func (c *cli) leaseRevokePrefix(args []string) error {
	return c.oneArg(args, "POST", "/v1/sys/leases/revoke-prefix/")
}

// ---- audit ----

func (c *cli) auditVerify(args []string) error {
	var want string
	rest, err := flags(args, func(fs *flag.FlagSet) { fs.StringVar(&want, "head", "", "") })
	if err != nil || len(rest) != 1 {
		return errUsage
	}
	f, err := os.Open(rest[0])
	if err != nil {
		return err
	}
	defer f.Close()
	var head audit.Head
	if want != "" {
		seq, hash, ok := strings.Cut(want, ":")
		n, perr := strconv.ParseUint(seq, 10, 64)
		if !ok || perr != nil || len(hash) != 64 {
			return errUsage
		}
		head, err = audit.VerifyThrough(f, audit.Head{Seq: n, Hash: hash})
	} else {
		head, err = audit.Verify(f)
	}
	if err != nil {
		return fmt.Errorf("%s: %w (last good record: %d)", rest[0], err, head.Seq)
	}
	fmt.Fprintf(c.out, "ok: %d records, head %s\n", head.Seq, head.Hash)
	return nil
}
