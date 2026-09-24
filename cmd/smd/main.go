// Command smd runs one secrets-manager node: Raft storage, the barrier and
// the HTTPS API.
//
//	smd -id node-1 -data /var/lib/smd -bootstrap \
//	    -raft-addr 10.0.0.1:8201 -rpc-addr 10.0.0.1:8202 -api-addr 10.0.0.1:8200 \
//	    -cert node-1.pem -key node-1.key -ca root.pem
//
// Further nodes use -join <any member's rpc-addr> instead of -bootstrap.
// The node certificate must be a pki node identity (spiffe://sm/node/<id>)
// valid for the hosts in the addresses; -cert may include the intermediate.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/hamad-tariq/SecretsManager/internal/api"
	"github.com/hamad-tariq/SecretsManager/internal/audit"
	"github.com/hamad-tariq/SecretsManager/internal/barrier"
	"github.com/hamad-tariq/SecretsManager/internal/cluster"
	"github.com/hamad-tariq/SecretsManager/internal/lease"
	"github.com/hamad-tariq/SecretsManager/internal/metrics"
	"github.com/hamad-tariq/SecretsManager/internal/pki"
	"github.com/hamad-tariq/SecretsManager/internal/rotation"
)

// version is set at release build time (scripts/release.sh).
var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "smd:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		id        = flag.String("id", "", "node ID (must match the certificate)")
		dataDir   = flag.String("data", "", "data directory")
		raftAddr  = flag.String("raft-addr", "", "host:port for Raft traffic")
		rpcAddr   = flag.String("rpc-addr", "", "host:port for cluster RPC (join, forwarding)")
		apiAddr   = flag.String("api-addr", "", "host:port for the HTTPS API")
		certFile  = flag.String("cert", "", "node certificate PEM (leaf, then intermediates)")
		keyFile   = flag.String("key", "", "node private key PEM")
		caFile    = flag.String("ca", "", "root CA certificate PEM")
		bootstrap = flag.Bool("bootstrap", false, "form a new cluster (first node only)")
		join      = flag.String("join", "", "rpc-addr of an existing member to join")
		fwdAddr   = flag.String("audit-forward", "", "host:port of a syslog-over-TLS collector for the audit log (recommended)")
		fwdCA     = flag.String("audit-forward-ca", "", "CA PEM for the collector's certificate (default: -ca)")
		fwdMaxLag = flag.Int64("audit-forward-max-lag", 64<<20, "bytes of unforwarded audit log after which requests fail")
		lineage   = flag.Duration("max-cert-lineage", 30*24*time.Hour, "how long a service certificate may keep renewing before its identity must log in again")
		rotCheck  = flag.Duration("rotation-check", 10*time.Second, "how often the leader looks for due rotations and expired leases")
	)
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println("smd", version)
		return nil
	}
	for name, v := range map[string]string{"id": *id, "data": *dataDir, "raft-addr": *raftAddr, "rpc-addr": *rpcAddr,
		"api-addr": *apiAddr, "cert": *certFile, "key": *keyFile, "ca": *caFile} {
		if v == "" {
			return fmt.Errorf("-%s is required", name)
		}
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	cert, roots, err := loadTLS(*certFile, *keyFile, *caFile)
	if err != nil {
		return err
	}
	rootPEM, _ := os.ReadFile(*caFile) // #nosec G304 G703 -- operator-supplied path, already read by loadTLS
	rootCert, err := pki.ParseCert(rootPEM)
	if err != nil {
		return err
	}

	node, err := cluster.Start(cluster.Config{ID: *id, RaftAddr: *raftAddr, RPCAddr: *rpcAddr, DataDir: *dataDir,
		Cert: cert, Roots: roots, Bootstrap: *bootstrap})
	if err != nil {
		return err
	}
	defer node.Shutdown()
	if *join != "" {
		if err := node.Join(*join); err != nil {
			return err
		}
	}

	seal := barrier.NewSeal(node)
	defer seal.Seal() // wipe keys on the way out
	auditPath := filepath.Join(*dataDir, "audit.log")
	al, err := audit.OpenFile(auditPath, nil)
	if err != nil {
		return err
	}
	defer al.Close()

	ctx, stopBackground := context.WithCancel(context.Background())
	defer stopBackground()
	reg := metrics.New()
	if *fwdAddr != "" {
		fwdRoots := roots
		if *fwdCA != "" {
			if fwdRoots, err = loadPool(*fwdCA); err != nil {
				return err
			}
		}
		fwd := &audit.Forwarder{Path: auditPath, Addr: *fwdAddr, TLS: pki.ClientTLS(cert, fwdRoots),
			Hostname: *id, MaxLag: *fwdMaxLag, Log: log}
		if err := fwd.Start(); err != nil {
			return err
		}
		al.SetGate(fwd.Check)
		go fwd.Run(ctx)
		reg.Gauge("sm_audit_forward_lag_bytes", "Audit log bytes not yet forwarded to the collector.", func() []metrics.Sample {
			return metrics.One(float64(fwd.Lag()))
		})
	} else {
		log.Warn("audit log is not forwarded off this node (-audit-forward); a compromised node could rewrite its own log")
	}
	reg.Gauge("sm_leader_changes", "Leadership changes seen by this node since it started.", func() []metrics.Sample {
		return metrics.One(float64(node.LeaderChanges()))
	})
	reg.Gauge("sm_node_cert_expiry_seconds", "Seconds until this node's certificates expire.", func() []metrics.Sample {
		return []metrics.Sample{
			{Labels: []string{"cert", "node"}, Value: time.Until(cert.Leaf.NotAfter).Seconds()},
			{Labels: []string{"cert", "root"}, Value: time.Until(rootCert.NotAfter).Seconds()},
		}
	})
	leases := lease.New(lease.Config{Backend: seal.Barrier, Sealed: seal.Sealed, Leader: node.IsLeader, Audit: al,
		Identity: pki.Identity{Kind: pki.Node, Name: *id}.String(), Tick: *rotCheck, Log: log})
	reg.Gauge("sm_leases", "Active database credential leases (reported by the leader).", func() []metrics.Sample {
		if seal.Sealed() || !node.IsLeader() {
			return nil
		}
		l, err := leases.List("")
		if err != nil {
			return nil
		}
		return metrics.One(float64(len(l)))
	})

	apiServer := api.New(api.Config{Seal: seal, Audit: al, Cluster: node, Metrics: reg, Roots: roots, MaxLineage: *lineage, Log: log})

	// Rotations and lease expiry run on whichever node is leader; the others idle.
	go rotation.New(rotation.Config{Backend: seal.Barrier, Sealed: seal.Sealed, Leader: node.IsLeader, Audit: al,
		Identity: pki.Identity{Kind: pki.Node, Name: *id}.String(), TLS: pki.ClientTLS(cert, roots), Tick: *rotCheck,
		Revoked: apiServer.CertRevoked, Log: log, Metrics: reg}).Run(ctx)
	go leases.Run(ctx)

	srv := &http.Server{
		Addr:              *apiAddr,
		Handler:           apiServer.Handler(),
		TLSConfig:         api.TLSConfig(cert, roots),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServeTLS("", "") }()
	log.Info("node started", "version", version, "id", *id, "api", *apiAddr, "raft", *raftAddr, "rpc", *rpcAddr)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case s := <-stop:
		log.Info("shutting down", "signal", s.String())
	}
	stopBackground()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

func loadPool(caFile string) (*x509.CertPool, error) {
	pemBytes, err := os.ReadFile(caFile) // #nosec G304 G703 -- operator-supplied path
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("%s: no certificates", caFile)
	}
	return pool, nil
}

func loadTLS(certFile, keyFile, caFile string) (tlsCert tls.Certificate, roots *x509.CertPool, err error) {
	read := func(p string) []byte {
		if err != nil {
			return nil
		}
		var b []byte
		b, err = os.ReadFile(p) // #nosec G304 -- operator-supplied paths
		return b
	}
	certPEM, keyPEM, caPEM := read(certFile), read(keyFile), read(caFile)
	if err != nil {
		return tlsCert, nil, err
	}
	chain, err := pki.ParseCerts(certPEM)
	if err != nil {
		return tlsCert, nil, fmt.Errorf("%s: %w", certFile, err)
	}
	key, err := pki.ParseKey(keyPEM)
	if err != nil {
		return tlsCert, nil, fmt.Errorf("%s: %w", keyFile, err)
	}
	root, err := pki.ParseCert(caPEM)
	if err != nil {
		return tlsCert, nil, fmt.Errorf("%s: %w", caFile, err)
	}
	roots = x509.NewCertPool()
	roots.AddCert(root)
	return pki.TLSCertificate(chain[0], key, chain[1:]...), roots, nil
}
