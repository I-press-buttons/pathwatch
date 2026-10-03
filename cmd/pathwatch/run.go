package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"sync/atomic"
	"syscall"

	"github.com/i-press-buttons/pathwatch/internal/alert"
	"github.com/i-press-buttons/pathwatch/internal/analyze"
	"github.com/i-press-buttons/pathwatch/internal/config"
	"github.com/i-press-buttons/pathwatch/internal/enrich"
	"github.com/i-press-buttons/pathwatch/internal/probe"
	"github.com/i-press-buttons/pathwatch/internal/scheduler"
	"github.com/i-press-buttons/pathwatch/internal/store"
	"github.com/i-press-buttons/pathwatch/internal/web"
	webui "github.com/i-press-buttons/pathwatch/web"
	"io/fs"
)

// fanout delivers scheduler events to the SSE hub and the alert engine seam.
type fanout struct {
	hub *web.Hub
	an  *atomic.Pointer[analyze.Analyzer]
}

func (f fanout) Round(e scheduler.RoundEvent) { f.hub.Round(e) }
func (f fanout) Probe(e scheduler.ProbeEvent) {
	f.hub.Probe(e)
	if a := f.an.Load(); a != nil {
		a.HandleProbe(e.Sample)
	}
}
func (f fanout) TargetsChanged() { f.hub.TargetsChanged() }

// enrichPersist stores hop enrichment in the ip_info table.
type enrichPersist struct{ st *store.Store }

func (p enrichPersist) Load() (map[netip.Addr]enrich.Info, error) {
	rows, err := p.st.LoadIPInfo()
	if err != nil {
		return nil, err
	}
	m := make(map[netip.Addr]enrich.Info, len(rows))
	for _, r := range rows {
		if a, err := netip.ParseAddr(r.Address); err == nil {
			m[a] = enrich.Info{Hostname: r.Hostname, ASN: r.ASN, ASName: r.ASName, UpdatedAt: r.UpdatedAt}
		}
	}
	return m, nil
}

func (p enrichPersist) Put(a netip.Addr, i enrich.Info) {
	p.st.PutIPInfo(store.IPInfo{Address: a.String(), Hostname: i.Hostname, ASN: i.ASN, ASName: i.ASName, UpdatedAt: i.UpdatedAt})
}

func runCmd(args []string) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	cfgFlag := fs.String("config", "", "path to the config file (default $PATHWATCH_CONFIG or pathwatch.yaml)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	path := configPath(*cfgFlag)
	cfg, err := config.Load(path, config.LoadOptions{CreateIfMissing: true})
	if err != nil {
		fmt.Fprintf(os.Stderr, "pathwatch: %v\n", err)
		return 1
	}
	log, closer := newLogger(cfg.Log)
	defer closer.Close()
	if err := run(cfg, log); err != nil {
		log.Error("pathwatch stopped with an error", "err", err)
		return 1
	}
	return 0
}

func run(cfg *config.Config, log *slog.Logger) error {
	if cfg.Created {
		log.Info("config file did not exist; wrote a starter config", "path", cfg.Path)
	}
	log.Info("pathwatch starting", "version", version, "config", cfg.Path, "database", cfg.Storage.Path, "listen", cfg.Listen)

	auth, err := cfg.ResolveAuth(nil)
	if err != nil {
		return fmt.Errorf("resolve credentials: %w", err)
	}
	switch {
	case auth.Generated:
		log.Warn("================================================================")
		log.Warn("No password was configured, so one was generated for the web UI.")
		log.Warn("  user:     " + auth.User)
		log.Warn("  password: " + auth.Password)
		log.Warn("  stored in " + auth.FilePath + " (set PATHWATCH_PASSWORD to choose your own)")
		log.Warn("================================================================")
	case auth.Enabled && auth.FilePath != "":
		log.Info("using the generated web UI password", "user", auth.User, "file", auth.FilePath)
	case auth.Enabled:
		log.Info("web UI authentication enabled", "user", auth.User)
	default:
		log.Info("web UI authentication is off (loopback only); set PATHWATCH_PASSWORD to enable it")
	}

	if err := os.MkdirAll(filepath.Dir(cfg.Storage.Path), 0o755); err != nil {
		return fmt.Errorf("create data directory: %w", err)
	}
	st, err := store.Open(cfg.Storage.Path, store.Options{
		RawRetention:      cfg.Storage.RawRetention.D(),
		Rollup1mRetention: cfg.Storage.Rollup1mRetention.D(),
		Rollup1hRetention: cfg.Storage.Rollup1hRetention.D(),
		Logger:            log,
	})
	if err != nil {
		return err
	}
	defer st.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := st.Backfill(ctx); err != nil {
		log.Warn("rollup backfill failed", "err", err)
	}

	prober, mode, perr := probe.NewICMPProber(cfg.Probing.ICMPMode)
	if perr != nil {
		log.Warn("ICMP probing is unavailable; hop traces are disabled (HTTP, TCP and DNS probes still run)", "icmp_mode", probe.ModeUnavailable, "err", perr)
		prober = nil
	} else {
		log.Info("ICMP prober ready", "icmp_mode", mode)
		defer prober.Close()
	}

	en := enrich.New(enrich.Options{ReverseDNS: cfg.ReverseDNSEnabled(), ASNDBPath: cfg.Enrich.ASNDB, Persist: enrichPersist{st}, Logger: log})
	defer en.Close()

	hub := web.NewHub()
	var anPtr atomic.Pointer[analyze.Analyzer]
	var sp probe.Prober
	if prober != nil {
		sp = prober
	}
	sched := scheduler.New(scheduler.Options{
		Store: st, Prober: sp, Observer: fanout{hub: hub, an: &anPtr}, Logger: log,
		Defaults: cfg.Defaults, Version: version,
	})
	var engine alert.Engine = alert.Nop{} // TODO(next phase): the alert rule engine plugs in here
	defer engine.Close()
	an := analyze.New(st, sched, engine, log)
	anPtr.Store(an)
	an.Start()

	sched.Start(ctx)
	if err := sched.SyncConfig(cfg.ResolveTargets(), cfg.ResolveDNSProbes()); err != nil {
		return fmt.Errorf("start targets: %w", err)
	}
	if err := sched.LoadUITargets(); err != nil {
		log.Warn("loading UI targets failed", "err", err)
	}
	log.Info("monitoring started", "targets", len(sched.States()))

	var static fs.FS
	if sub, err := fs.Sub(webui.Static, "static"); err == nil {
		static = sub
	}
	srv := web.New(web.Deps{
		Store: st, Sched: sched, Analyzer: an, Enrich: en, Hub: hub, Config: cfg, Auth: auth,
		Version: version, Logger: log, Static: static,
	})
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.Listen, err)
	}
	scheme := "http"
	if cfg.TLS.CertFile != "" {
		scheme = "https"
	}
	log.Info("web UI listening", "url", scheme+"://"+ln.Addr().String()+"/")

	go watchReload(ctx, cfg.Path, sched, log)

	err = srv.ListenAndServe(ctx, ln)
	log.Info("shutting down")
	stop()
	sched.Close()
	an.Close()
	if err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

// watchReload re-reads the config on SIGHUP and applies targets and DNS probes.
func watchReload(ctx context.Context, path string, sched *scheduler.Scheduler, log *slog.Logger) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	defer signal.Stop(ch)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ch:
		}
		cfg, err := config.Load(path, config.LoadOptions{})
		if err != nil {
			log.Error("config reload failed; keeping the running configuration", "err", err)
			continue
		}
		if err := sched.SyncConfig(cfg.ResolveTargets(), cfg.ResolveDNSProbes()); err != nil {
			log.Error("applying reloaded config failed", "err", err)
			continue
		}
		log.Info("config reloaded", "targets", len(cfg.Targets), "dns_probes", len(cfg.DNSProbes))
	}
}
