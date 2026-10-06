package probe

import (
	"context"
	"errors"
)

// dualProber dispatches probes by destination address family to an IPv4 and an IPv6 prober.
// Either may be nil when that family is unavailable on this host.
type dualProber struct {
	v4, v6 Prober
}

func (d *dualProber) Probe(ctx context.Context, req Request) Result {
	a := req.Dst.Unmap()
	p, fam := d.v6, "IPv6"
	if a.Is4() {
		p, fam = d.v4, "IPv4"
	}
	if p == nil {
		return Result{Err: errors.New("ICMP probing for " + fam + " is unavailable on this host")}
	}
	req.Dst = a
	return p.Probe(ctx, req)
}

// Mode reports the IPv4 prober's mode (the IPv6 one is normally identical); when only IPv6 is
// available, that one's.
func (d *dualProber) Mode() string {
	if d.v4 != nil {
		return d.v4.Mode()
	}
	return d.v6.Mode()
}

func (d *dualProber) ReleaseFlow(flow uint16) {
	for _, p := range []Prober{d.v4, d.v6} {
		if fr, ok := p.(FlowReleaser); ok {
			fr.ReleaseFlow(flow)
		}
	}
}

func (d *dualProber) Close() error {
	var err error
	for _, p := range []Prober{d.v4, d.v6} {
		if p != nil {
			err = errors.Join(err, p.Close())
		}
	}
	return err
}
