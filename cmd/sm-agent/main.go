// Command sm-agent delivers a service's certificate and secrets as files.
//
//	sm-agent -addr sm-1:8200,sm-2:8200 -ca /etc/sm/ca.crt -out /run/secrets/sm \
//	         -auth kubernetes -secret prod/orders/api-key=api-key -db orders-rw=db.json [-once]
//
// -once (init container) logs in, writes the files and exits. Without it
// (sidecar or VM service) it keeps renewing the certificate and re-fetching
// secrets until SIGTERM. -db role=file writes per-pod database credentials
// ({"username","password","lease_id","expires","max_expires"}) and keeps
// their lease alive; use it in the sidecar, since an init container's lease
// isn't renewed. See deploy/k8s for a pod example.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/hamad-tariq/SecretsManager/internal/agent"
)

// secretFlags parses repeatable key=file flags.
type secretFlags map[string]string

func (s secretFlags) String() string { return fmt.Sprint(map[string]string(s)) }

func (s secretFlags) Set(v string) error {
	path, file, ok := strings.Cut(v, "=")
	if !ok || path == "" || file == "" {
		return errors.New("want path=file")
	}
	s[strings.Trim(path, "/")] = file
	return nil
}

// version is set at release build time (scripts/release.sh).
var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "sm-agent:", err)
		os.Exit(1)
	}
}

func run() error {
	secrets, dbs := secretFlags{}, secretFlags{}
	var (
		addr    = flag.String("addr", os.Getenv("SM_ADDR"), "node API address(es), comma-separated")
		caFile  = flag.String("ca", os.Getenv("SM_CA"), "root CA PEM")
		out     = flag.String("out", "/run/secrets/sm", "output directory (use tmpfs)")
		auth    = flag.String("auth", "kubernetes", "token | kubernetes")
		tokFile = flag.String("token-file", "", "enrollment token file (auth=token)")
		jwtFile = flag.String("jwt-file", "/var/run/secrets/sm/token", "projected service-account token (auth=kubernetes)")
		refresh = flag.Duration("refresh", 5*time.Minute, "how often to re-fetch secrets")
		once    = flag.Bool("once", false, "log in, write files and exit (init container)")
	)
	flag.Var(secrets, "secret", "kv path=file name (repeatable)")
	flag.Var(dbs, "db", "database role=file name for dynamic credentials (repeatable)")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println("sm-agent", version)
		return nil
	}

	caPEM, err := os.ReadFile(*caFile) // #nosec G703 G304 -- operator-supplied path
	if err != nil {
		return err
	}
	a, err := agent.New(agent.Config{
		Addrs: strings.Split(*addr, ","), CAPEM: caPEM, OutDir: *out, Auth: *auth,
		TokenFile: *tokFile, JWTFile: *jwtFile, Secrets: secrets, DBCreds: dbs, Refresh: *refresh,
		Log: slog.New(slog.NewJSONHandler(os.Stderr, nil)),
	})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *once {
		if err := a.Login(ctx); err != nil {
			return err
		}
		return errors.Join(a.Sync(ctx), a.DBCreds(ctx))
	}
	return a.Run(ctx)
}
