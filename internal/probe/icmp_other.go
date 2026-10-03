//go:build !linux && !windows

package probe

import (
	"errors"
	"runtime"
)

// NewICMPProber is not implemented on this platform.
func NewICMPProber(mode string) (Prober, string, error) {
	return nil, ModeUnavailable, errors.New("ICMP probing is not implemented on " + runtime.GOOS)
}
