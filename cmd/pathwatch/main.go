// Command pathwatch is a self-hosted network path monitor.
package main

import (
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	_ "time/tzdata" // maintenance windows use IANA time zones; minimal containers lack tzdata
)

// version is set at build time: -ldflags "-X main.version=v1.2.3".
var version = "0.1.0"

const usage = `pathwatch - self-hosted network path monitor

Usage:
  pathwatch [run] [--config pathwatch.yaml]   run the monitor and web UI (default)
  pathwatch check-config [--config FILE]      validate the configuration and exit
  pathwatch notify-test [--config FILE] [--channel webhook|email]
                                              send a test notification over the alert channels
  pathwatch trace [options] <host>            one-shot mtr-style trace to stdout
  pathwatch version                           print the version

Environment: PATHWATCH_CONFIG, PATHWATCH_DB, PATHWATCH_LISTEN, PATHWATCH_USER, PATHWATCH_PASSWORD
`

func main() {
	args := os.Args[1:]
	cmd := "run"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	var code int
	switch cmd {
	case "run":
		code = runCmd(args)
	case "check-config":
		code = checkConfigCmd(args)
	case "notify-test":
		code = notifyTestCmd(args)
	case "trace":
		code = traceCmd(args)
	case "version", "--version":
		fmt.Println(versionString())
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "pathwatch: unknown command %q\n\n%s", cmd, usage)
		code = 2
	}
	os.Exit(code)
}

func versionString() string {
	s := fmt.Sprintf("pathwatch %s (%s, %s/%s)", version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, kv := range bi.Settings {
			if kv.Key == "vcs.revision" && len(kv.Value) >= 7 {
				s += " commit " + kv.Value[:7]
			}
		}
	}
	return s
}
