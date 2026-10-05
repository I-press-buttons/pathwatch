# pathwatch

A self-hosted network analysis tool that continuously monitors the path to the destinations you care about. It records per-hop latency and loss alongside real HTTP/HTTPS, TCP and DNS timing, so you can tell "a router is rate-limiting my pings" from "my connection is actually broken". Its feature set is comparable to commercial path-analysis and network-monitoring products, but it ships as a single static binary with an embedded web dashboard, plus a multi-arch Docker image for servers and NAS devices such as Synology.

## Goal

Give home labs, small networks and anyone troubleshooting flaky connectivity a free, always-on way to see where on the path a problem occurs, how long it has been happening, and whether it affects real traffic.

## Features

- **Hop-by-hop path analysis**: sent/lost, loss %, min/avg/max/current/p95 and jitter for every hop, with inline latency bars and hostname/ASN enrichment.
- **Path timeline**: a per-hop heatmap over time with route changes and monitor gaps marked, updated live.
- **End-to-end probes**: HTTP/HTTPS (DNS, connect, TLS, TTFB, transfer), TCP connect and DNS, correlated on the same time axis as the hops.
- **Rate-limit-aware alerting**: end-to-end probes decide; loss on an intermediate router alone never pages you. Hysteresis, cooldowns, silences, maintenance windows, and queued retries. Webhook (Discord, Slack, ntfy, generic) and email channels.
- **MOS score** per target from latency, jitter and loss.
- **Long-term history** in SQLite with automatic rollups and retention.
- **Configurable from the UI or YAML**: manage targets (hostname, IPv4, IPv6), intervals, thresholds and alert rules in the browser, or keep everything in a version-controlled file.
- **Themes**: nine built-in, including Dark, Nord, Solarized and a green/yellow/red Classic scale.
- **Pure Go, no CGO**: Linux (amd64, arm64, armv7) and Windows.

## Screenshots

Screenshots use demo data.

| Target page (Classic theme) | Overview (Dark theme) |
|---|---|
| ![Target page](docs/screenshots/target-classic.png) | ![Overview](docs/screenshots/overview-dark.png) |

## Quick start (Docker)

```sh
docker run -d --name pathwatch \
  --network host \
  --cap-drop ALL --cap-add NET_RAW \
  --security-opt no-new-privileges:true \
  --read-only --tmpfs /tmp \
  --restart unless-stopped \
  -e TZ=Europe/London \
  -e PATHWATCH_PASSWORD='choose-a-long-password' \
  -v pathwatch-data:/data \
  ghcr.io/i-press-buttons/pathwatch:latest
```

Open <http://localhost:8095> and log in as `admin`. `--network host` makes probes follow your real traffic path, and `--cap-add NET_RAW` allows raw ICMP for hop tracing. The container runs as root but drops every other capability, cannot gain privileges, and has a read-only root filesystem; only `/data` is writable (see [Container hardening](#container-hardening)). If `PATHWATCH_PASSWORD` is omitted, a random one is saved to `/data/.pathwatch-password` and logged.

To build from source (Go 1.26+, no C toolchain): `go build ./cmd/pathwatch && ./pathwatch run --config pathwatch.yaml`. A one-shot trace is available with `pathwatch trace <host>`.

### Container hardening

The image runs as root (raw ICMP sockets work most reliably that way on Synology kernels), so the examples confine that process: `--cap-drop ALL --cap-add NET_RAW` keeps the only capability pathwatch uses, `no-new-privileges` blocks privilege gain, and `--read-only` with a `/tmp` tmpfs leaves `/data` as the only writable path. The compose file and Portainer stack in `deploy/` use the same settings. To check: `docker exec pathwatch grep -E 'CapEff|NoNewPrivs' /proc/1/status` should show `0000000000002000` and `1`, and the log should contain `icmp_mode=raw`.

- **Data folder ownership.** Without `DAC_OVERRIDE`, root can only write to `/data` if the host folder is owned by root or is world-writable. A folder owned by another user (typical on Synology, where File Station creates folders owned by your DSM user) fails at startup with `write starter config: open /data/pathwatch.yaml: permission denied`. Fix it with `sudo chown root:root <data folder>`, or add `--cap-add DAC_OVERRIDE`. Existing installs whose files are already root-owned are not affected.
- **Log file location.** With `--read-only`, a `log.file` outside `/data` cannot be opened. pathwatch prints a warning and keeps logging to stderr (`docker logs`). A relative `log.file` resolves next to the config file, so it lands in `/data`.
- **Non-root (advanced, not the default).** You can run with `user: "<uid>:<gid>"`, but the image has no file capability on the binary, so a non-root process gets no effective `NET_RAW` and raw ICMP fails; it only works with unprivileged datagram ICMP where the host's `net.ipv4.ping_group_range` allows it (often not enabled on Synology). The data folder must be owned by that uid. If you build your own image with `setcap cap_net_raw+ep` on the binary, do not combine that with `no-new-privileges` unless you have verified it on your runtime: file capabilities can be ignored under `no_new_privs` depending on the Docker/runc version, and with `+ep` a container started without `NET_RAW` in its bounding set will refuse to execute the binary at all.
- `NET_RAW` on the host network also allows raw packet sockets on all host interfaces. That is inherent to raw ICMP mode.

## Documentation

- [docs/SYNOLOGY.md](docs/SYNOLOGY.md): Synology + Portainer deployment
- [docs/SPEC.md](docs/SPEC.md): design and full configuration reference
- [docs/API.md](docs/API.md): JSON API used by the UI

pathwatch has no telemetry and only contacts the targets and notification endpoints you configure.

## License

[MIT](LICENSE)
