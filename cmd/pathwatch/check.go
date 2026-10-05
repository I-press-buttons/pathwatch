package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/i-press-buttons/pathwatch/internal/config"
)

func configPath(flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	if v := os.Getenv(config.EnvConfig); v != "" {
		return v
	}
	return config.DefaultConfig
}

func checkConfigCmd(args []string) int {
	fs := flag.NewFlagSet("check-config", flag.ContinueOnError)
	cfgFlag := fs.String("config", "", "path to the config file (default $PATHWATCH_CONFIG or pathwatch.yaml)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	path := configPath(*cfgFlag)
	cfg, err := config.Load(path, config.LoadOptions{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		return 1
	}
	targets := cfg.ResolveTargets()
	dns := cfg.ResolveDNSProbes()
	fmt.Printf("%s: OK\n", path)
	fmt.Printf("  listen:   %s (auth %s)\n", cfg.Listen, authSummary(cfg))
	fmt.Printf("  database: %s\n", cfg.Storage.Path)
	fmt.Printf("  targets:  %d, dns probes: %d, alert rules: %d\n", len(targets), len(dns), len(cfg.Alerts.Rules))
	for _, t := range targets {
		kinds := ""
		if t.ICMP != nil {
			kinds += fmt.Sprintf(" icmp-trace/%v", t.ICMP.Interval)
		}
		for _, p := range t.Probes {
			kinds += fmt.Sprintf(" %s/%v", p.Type, p.Interval)
		}
		fmt.Printf("    - %s (%s):%s\n", t.Name, t.Host, kinds)
	}
	if !config.IsLoopbackListen(cfg.Listen) && os.Getenv(config.EnvPassword) == "" {
		fmt.Println("  note: listening beyond loopback without PATHWATCH_PASSWORD; a password is generated on first start")
	}
	// Resolving auth here would create the password file, so look at the user-set password only.
	if pw := userPassword(cfg); pw != "" && weakPassword(pw) {
		fmt.Printf("  warning: %s\n", weakPasswordMsg)
	}
	return 0
}

// minPasswordLen is the length below which a user-chosen password draws a warning.
const minPasswordLen = 12

const weakPasswordMsg = "the web UI password is shorter than 12 characters; use a longer one, or unset PATHWATCH_PASSWORD on a non-loopback listen address to get a generated one"

func weakPassword(pw string) bool { return len(pw) < minPasswordLen }

// userPassword is the password the operator set through the environment (not a generated one).
func userPassword(cfg *config.Config) string {
	name := cfg.Auth.BasicPasswordEnv
	if name == "" {
		name = config.EnvPassword
	}
	if pw := os.Getenv(name); pw != "" {
		return pw
	}
	return os.Getenv(config.EnvPassword)
}

func authSummary(cfg *config.Config) string {
	switch {
	case !config.IsLoopbackListen(cfg.Listen):
		return "required"
	case os.Getenv(config.EnvPassword) != "":
		return "on"
	}
	return "off on loopback"
}
