# Running pathwatch on a Synology NAS (Portainer)

This guide takes you from nothing to a working pathwatch dashboard on a Synology NAS, using Portainer. No command line is needed.

## What you need

- A Synology with **DSM 7.x**.
- **Container Manager** installed (Package Center -> Container Manager). On DSM 7.0 and 7.1 it is called "Docker".
- **Portainer** already running. If you do not have it yet, follow Portainer's own Synology install guide first.
- A supported CPU: **64-bit Intel/AMD (amd64)** or **64-bit ARM (arm64)**. See [Which Synology models work](#which-synology-models-work).

## 1. Create the data folder

pathwatch keeps everything (its config file, its database, and the generated password) in one folder.

1. Open **File Station**.
2. Go to the shared folder named `docker` (create it in Control Panel -> Shared Folder if it does not exist).
3. Inside it, create a folder named `pathwatch`.

The full path is now `/volume1/docker/pathwatch`. If your storage volume is not `volume1`, use your own volume name and adjust the path in step 3.

> The folder must be on one of the NAS's own volumes. Do not use a folder that is a mounted network share (NFS or SMB) from another machine. See [Troubleshooting](#the-database-must-live-on-a-local-volume).

## 2. Make sure the image can be downloaded

The image lives on GitHub's container registry: `ghcr.io/i-press-buttons/pathwatch`. GitHub packages are **private by default**, so one of these two things must be true. Choose **A** if you own the repository, or **B** if you do not.

### A. Make the package public (repository owner)

1. On GitHub, open your profile -> **Packages** -> **pathwatch**.
2. Click **Package settings**.
3. Scroll to the **Danger Zone** and click **Change visibility** -> **Public**.

The package only appears after the first successful run of the "Docker image" workflow. Once it is public, anyone can pull it without logging in.

### B. Add GitHub as a registry in Portainer (private package)

1. On GitHub, create a **personal access token (classic)** at Settings -> Developer settings -> Personal access tokens. Give it only the **`read:packages`** scope.
2. In Portainer, go to **Registries** -> **Add registry** -> **Custom registry**.
3. Fill in:
   - **Name:** `ghcr`
   - **Registry URL:** `ghcr.io`
   - **Authentication:** on
   - **Username:** your GitHub user name
   - **Password:** the token from step 1
4. Click **Add registry**.

## 3. Add the stack in Portainer

1. In Portainer, pick your NAS environment (usually "local").
2. Go to **Stacks** -> **Add stack**.
3. Name it `pathwatch`.
4. Choose **Web editor** and paste the contents of [`deploy/portainer-stack.yml`](../deploy/portainer-stack.yml).
5. Edit the file in the editor:
   - `TZ`: your time zone, for example `Europe/Berlin`.
   - `PATHWATCH_PASSWORD`: remove the `#` at the start of the line and choose a password. If you leave it commented out, pathwatch makes one up for you (see [Find your password](#4-find-your-password)).
   - `PATHWATCH_LISTEN`: leave it as `0.0.0.0:8095` unless that port is taken (see [Changing the port](#changing-the-port)).
   - The volume line `/volume1/docker/pathwatch:/data`: change `volume1` if your volume is named differently.
6. Click **Deploy the stack**.

The first start downloads the image, which takes a minute or two. When the stack shows as running, continue.

## 4. Find your password

If you set `PATHWATCH_PASSWORD` yourself, use it. The user name is `admin`.

If you did not, pathwatch generated a random password on its first start. To read it:

1. In Portainer, go to **Containers** -> **pathwatch** -> **Logs** (the small page icon).
2. Look near the top for the line announcing the generated password for the web UI.

The password is also saved in a file called `.pathwatch-password` inside your data folder (`/volume1/docker/pathwatch/.pathwatch-password`). In File Station, hidden files are shown with the **Settings** (three dots) -> **Show hidden files** option. Delete that file and set `PATHWATCH_PASSWORD` later if you would rather choose your own.

Recommended: set `PATHWATCH_PASSWORD` in the stack yourself (at least 12 characters) instead of relying on the generated one, because anyone who can open the container logs in Portainer can read the generated password.

## 5. Open the dashboard

Browse to:

```
http://<nas-ip>:8095
```

Replace `<nas-ip>` with your NAS's address, for example `http://192.168.1.20:8095`. Log in as `admin`.

pathwatch creates a starter configuration on first run with a few example targets (cloudflare.com with an HTTP check, 1.1.1.1 and 8.8.8.8), so you will see data within a minute or two. Add your own targets from the UI, or edit the config file (below).

## Securing access

pathwatch's web UI uses HTTP Basic auth. Over plain `http://` (the default) the password travels in clear text with every request, so anyone on the same network segment can capture it.

- **Keep pathwatch LAN-only.** Do not port-forward 8095 on your router. Use the DSM firewall rule described under [Troubleshooting](#i-can-reach-the-nas-but-not-the-dashboard-synology-firewall) to allow only your local network.
- **Set `PATHWATCH_PASSWORD`** in the stack (at least 12 characters; shorter passwords log a startup warning). Failed logins are rate-limited per client IP (HTTP 429) and logged as `authentication failed`.
- **For remote access, use a VPN** (for example Synology's VPN Server or Tailscale), or put DSM's reverse proxy in front with HTTPS: Control Panel -> Login Portal -> Advanced -> Reverse Proxy -> Create. Source: HTTPS, your hostname, port 443 (or another port); destination: HTTP, `localhost`, port `8095`. Then set `public_url` in `pathwatch.yaml` to the HTTPS address, so alert links and the cross-site request check match.
- With a reverse proxy on the NAS you can bind pathwatch to loopback only (`PATHWATCH_LISTEN: "127.0.0.1:8095"`). Authentication is then off unless `PATHWATCH_PASSWORD` is set, so keep the password set. While auth is off, requests whose `Host` header is not `localhost`, a loopback IP or the `public_url` host are rejected with HTTP 421, so `public_url` must contain the proxy's hostname.
- Built-in TLS (`tls.cert_file` / `tls.key_file`) works too, but the image's plain-HTTP healthcheck then fails and Portainer shows the container as unhealthy. Override `healthcheck:` in the stack, or use the DSM reverse proxy instead.

## Updating

New versions are published to the same image tag, so updating means pulling it again.

1. In Portainer, go to **Stacks** -> **pathwatch**.
2. Turn on **Re-pull image and redeploy** (it may be called "Pull and redeploy") and click **Update the stack**.

You can also go to **Containers**, tick `pathwatch`, and use **Recreate** with **Pull latest image** switched on. Your data folder is untouched either way, so history and settings stay.

## Changing the port

pathwatch uses host networking, so the port is opened directly on the NAS. If 8095 is already used by another app:

1. Edit the stack and change `PATHWATCH_LISTEN` to, for example, `0.0.0.0:8123`.
2. Click **Update the stack**.
3. Open `http://<nas-ip>:8123`.

The container health check follows this setting automatically. Do not add a `ports:` section; it has no effect with host networking.

## Editing the configuration

All settings live in `/volume1/docker/pathwatch/pathwatch.yaml`. The file starts out with comments explaining the options, and [docs/SPEC.md](SPEC.md) has a complete example.

1. Edit the file with a text editor. In File Station you can download it, edit it on your computer, and upload it again. (Use a plain text editor, not a word processor.)
2. In Portainer, go to **Containers** -> tick `pathwatch` -> **Restart**.
3. If pathwatch does not come back, open the container **Logs**. Typos in the file are reported there by name and line, because unknown settings are rejected on purpose.

Targets you add in the web UI are stored in the database and are not written into the YAML file.

## Troubleshooting

### Hops are missing, or the logs say `icmp_mode: unavailable`

pathwatch needs raw network access to trace the path. Check the stack for both of these lines:

```yaml
network_mode: host
cap_drop:
  - ALL
cap_add:
  - NET_RAW
```

Both must be present (`NET_RAW` must not be dropped), and the container must run as root (the default for this image, so do not add a `user:` line). The stack also sets `security_opt: [no-new-privileges:true]`, `read_only: true` and a `/tmp` tmpfs; those do not affect ICMP. After fixing the stack, click **Update the stack**. In the container logs, look for a line that states which ICMP mode was detected.

If you started the container some other way (for example from the Container Manager UI), make sure **Use the same network as Docker Host** is on and that `NET_RAW` is added under capabilities.

### The container stops with "permission denied" on /data/pathwatch.yaml

The stack drops all capabilities except `NET_RAW`, including `DAC_OVERRIDE`. Without it, root can only write to the data folder if the folder is owned by root or is writable by everyone. Folders created in File Station usually belong to your DSM user, so the first start fails with `write starter config: open /data/pathwatch.yaml: permission denied`. Pick one fix:

- Over SSH: `sudo chown root:root /volume1/docker/pathwatch` (preferred; keeps the capability set minimal), or
- In the stack, remove the `#` in front of `# - DAC_OVERRIDE` under `cap_add`.

Existing installs whose files are already owned by root are not affected.

### A log file outside /data is ignored

The container's root filesystem is read-only, so a `log.file` outside `/data` cannot be opened. pathwatch prints `cannot open log file ...` and keeps logging to stderr, which Portainer shows under the container **Logs**. Use a path under `/data` (a relative path resolves next to `pathwatch.yaml`).

### "Port already in use" or the container keeps restarting

Another program on the NAS is using port 8095. Pick another port, see [Changing the port](#changing-the-port). The container log will contain an "address already in use" message in this case.

### The database must live on a local volume

pathwatch stores its history in SQLite, which does not work reliably over network file systems. The folder you map to `/data` has to be on the NAS's own volume (for example `/volume1/docker/pathwatch`). Do not point it at an NFS or SMB share from another computer. Symptoms of getting this wrong are "database is locked" errors or a corrupted database.

### I can reach the NAS but not the dashboard (Synology firewall)

If you use the DSM firewall (Control Panel -> Security -> Firewall), add an allow rule for the TCP port (8095 by default) from your local network (for example `192.168.1.0/24`) and place it above any deny-all rule. With host networking, DSM's firewall applies directly to pathwatch.

### Which image tag to use

| Tag | What it is |
|---|---|
| `latest` | The newest build of the main branch. The default, and the right choice for most people. |
| `edge` | The newest build from any other branch. For testing unreleased changes; may break. |
| `1.2.3`, `1.2` | A specific release. Use these if you want to update only when you decide to. |
| `sha-abc1234` | One exact commit. Handy when reporting a bug. |

Change the tag in the `image:` line of the stack and update the stack.

> **Before the first release:** `latest` appears once the code is merged into the `main` branch. Until then, only `edge` exists. If Portainer reports `manifest unknown` for `latest`, change the image line to `ghcr.io/i-press-buttons/pathwatch:edge`.

### Which Synology models work

The image is published for **linux/amd64** (Intel and AMD CPU models) and **linux/arm64** (64-bit ARM CPU models).

**32-bit ARM models (armv7, found in some older, low-end units) are not supported by the Docker image**, and neither are PowerPC models. Many of these cannot run Container Manager at all. To find out which one you have, look up your model's CPU on Synology's "What kind of CPU does my Synology NAS have" article, or run `uname -m` over SSH: `x86_64` (amd64) and `aarch64` (arm64) work; `armv7l` does not.

Release binaries for armv7 Linux are published on the GitHub releases page for people who want to run pathwatch without Docker.

### Still stuck

Open the container logs in Portainer first; most problems (bad config, taken port, missing permission) are stated there in plain words. Then open an issue at <https://github.com/i-press-buttons/pathwatch/issues> and include the log and your Synology model.
