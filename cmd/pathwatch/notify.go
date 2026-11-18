package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/i-press-buttons/pathwatch/internal/alert"
	"github.com/i-press-buttons/pathwatch/internal/config"
)

// notifyTestCmd sends a test notification over every configured channel (or the one named by
// --channel) and reports each outcome. It reads the same config file and environment as run, so
// in Docker it is run inside the container: docker exec pathwatch pathwatch notify-test.
func notifyTestCmd(args []string) int {
	fs := flag.NewFlagSet("notify-test", flag.ContinueOnError)
	cfgFlag := fs.String("config", "", "path to the config file (default $PATHWATCH_CONFIG or pathwatch.yaml)")
	only := fs.String("channel", "", "test only this channel: webhook or email")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *only != "" && *only != alert.ChannelWebhook && *only != alert.ChannelEmail {
		fmt.Fprintf(os.Stderr, "unknown channel %q (webhook or email)\n", *only)
		return 2
	}
	path := configPath(*cfgFlag)
	cfg, err := config.Load(path, config.LoadOptions{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		return 1
	}
	// Configure logs a rejected channel configuration; show it on stderr.
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	return notifyTest(cfg, *only, os.Stdout, log)
}

func notifyTest(cfg *config.Config, only string, out io.Writer, log *slog.Logger) int {
	s := alert.NewSender(nil, nil, log, nil)
	s.Configure(cfg)
	channels := s.Channels()
	if only != "" {
		channels = nil
		for _, c := range s.Channels() {
			if c == only {
				channels = append(channels, c)
			}
		}
		if len(channels) == 0 {
			fmt.Fprintf(out, "%s: not configured (alerts.notify.%s in the config file)\n", only, only)
			return 1
		}
	}
	if len(channels) == 0 {
		fmt.Fprintln(out, "no notification channels are configured (alerts.notify.webhook / alerts.notify.email)")
		return 1
	}
	code := 0
	for _, c := range channels {
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		start := time.Now()
		err := s.SendTest(ctx, c)
		cancel()
		took := time.Since(start).Round(time.Millisecond)
		if err != nil {
			fmt.Fprintf(out, "%s: FAILED after %v: %v\n", c, took, err)
			code = 1
			continue
		}
		fmt.Fprintf(out, "%s: sent in %v\n", c, took)
	}
	return code
}
