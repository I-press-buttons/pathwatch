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
  --cap-add NET_RAW \
  --restart unless-stopped \
  -e TZ=Europe/London \
  -e PATHWATCH_PASSWORD='choose-a-long-password' \
  -v pathwatch-data:/data \
  ghcr.io/i-press-buttons/pathwatch:latest
```

Open <http://localhost:8095> and log in as `admin`. `--network host` makes probes follow your real traffic path, and `--cap-add NET_RAW` allows raw ICMP for hop tracing. If `PATHWATCH_PASSWORD` is omitted, a random one is saved to `/data/.pathwatch-password` and logged.

To build from source (Go 1.26, latest patch release recommended; no C toolchain): `go build ./cmd/pathwatch && ./pathwatch run --config pathwatch.yaml`. A one-shot trace is available with `pathwatch trace <host>`.

### Verifying downloads

Release archives and the Docker image carry build provenance attestations. Verify them with the `gh` CLI:

```sh
gh attestation verify pathwatch_X.Y.Z_linux_amd64.tar.gz --repo I-press-buttons/pathwatch
gh attestation verify oci://ghcr.io/i-press-buttons/pathwatch:X.Y.Z --repo I-press-buttons/pathwatch
```

## Documentation

- [docs/SYNOLOGY.md](docs/SYNOLOGY.md): Synology + Portainer deployment
- [docs/SPEC.md](docs/SPEC.md): design and full configuration reference
- [docs/API.md](docs/API.md): JSON API used by the UI

pathwatch has no telemetry and only contacts the targets and notification endpoints you configure.

## License

[MIT](LICENSE)
