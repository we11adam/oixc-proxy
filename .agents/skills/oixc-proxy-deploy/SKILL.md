---
name: oixc-proxy-deploy
description: Install, update, release, or verify oixc-proxy on macOS, Linux, and OpenWrt hosts. Use for GitHub Release publishing, local or SSH deployment, service setup, upgrades, health checks, and rollbacks in this Rust repository; do not modify the Go compatibility repository.
---

# Deploy oixc-proxy

Use the Rust implementation in this repository. Treat `../oixc-go` only as a
compatibility reference unless the user explicitly includes it.

## Preserve deployment boundaries

- Mutate only hosts the user explicitly names or authorizes. Read-only probes
  may determine OS, architecture, login user, existing config, service manager,
  listener addresses, and health.
- Never print tokens or copy a config to a new host unless the user authorizes
  that host to receive it. Preserve existing configs, listeners, service files,
  and node-filter choices during an update unless asked to change them.
- Use an existing installation's service manager. Do not rerun
  `install-launch-agent` or `install-systemd` over an existing service file.

## Select the artifact

Prefer `install.sh` and a published release when the user requests a released
version. Private repository downloads require an authenticated `gh` CLI or a
read-only `GH_TOKEN`/`GITHUB_TOKEN` supplied to `gh`; never echo that
credential. If OpenWrt lacks `gh`, download on an authenticated control host,
verify there, and transfer the artifact with legacy `scp -O`. For unreleased
repository changes, build a release binary with the same target mapping used
by `.github/workflows/release.yml`:

| Host | Target |
| --- | --- |
| Intel macOS | `x86_64-apple-darwin` |
| Apple Silicon macOS | `aarch64-apple-darwin` |
| x86-64 Linux | `x86_64-unknown-linux-musl` |
| aarch64 Linux/OpenWrt | `aarch64-unknown-linux-musl` |

Before replacing anything, verify the target architecture, SHA-256, executable
bit, and `oixc-proxy version` output.

## Update an existing installation

1. Probe the current binary path, config path, service manager, PID, listeners,
   health endpoint, and provider endpoint without exposing the token.
2. Upload the new binary beside the installed one as `oixc-proxy.new`. Keep the
   old binary as `oixc-proxy.previous`, then atomically rename the new file.
3. Restart with the existing mechanism: LaunchAgent on macOS, systemd user unit
   on ordinary Linux, or procd init script on OpenWrt.
4. Verify the installed hash and version, a new running PID, unchanged listener
   addresses, HTTP 204 from `/healthz`, and HTTP 200 from a provider endpoint.
5. If the new process does not become healthy, restore `oixc-proxy.previous`,
   restart once, verify the rollback, and report the failed target separately.

For a first installation, `install.sh` installs only the binary. Obtain explicit
authorization before creating a config or service, then follow
[DEPLOY.md](../../../DEPLOY.md). The config must remain mode `0600` or stricter.

## Publish a release

The tag must be `v` followed by the exact `Cargo.toml` package version. Pushing
that tag runs `.github/workflows/release.yml`, which builds four release
archives, publishes `SHA256SUMS` and `install.sh`, and creates or updates the
GitHub Release. Do not publish a tag until tests pass and the worktree is clean.
