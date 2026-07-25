# Platform support

`secreq` is a **Unix tool at its core.** It leans on peer-credential
lookup over unix-domain sockets (`SO_PEERCRED` / `LOCAL_PEERPID`),
process-tree walking, PATH shims, and `execvp` — none of which have a
first-class Windows equivalent. The support matrix below is what you can
expect before you invest in setting it up.

There are **no prebuilt binaries.** You build from source with
`cargo install --path packages/secreq` (or `cargo build --release`), so "supported"
here means "the crate builds and runs on that host," not "a package
exists."

## Matrix

| Platform | Status | Login service | Consent-window prerequisite |
|---|---|---|---|
| **macOS** | ✅ First-class | launchd `LaunchAgent` (`~/Library/LaunchAgents/com.secreq.daemon.plist`) | WindowServer is always present — nothing to set up. |
| **Linux** | ✅ First-class | systemd `--user` unit (`~/.config/systemd/user/secreq.service`) | A graphical session: `$DISPLAY` (X11) or `$WAYLAND_DISPLAY` (Wayland). |
| **\*BSD** (FreeBSD, OpenBSD, NetBSD) | ⚠️ Best-effort, unsupported | None wired up — treated as "systemd-adjacent" but no unit is generated for a non-systemd init | Same as Linux (`$DISPLAY` / `$WAYLAND_DISPLAY`). **Known compile gap — see below.** |
| **Windows** | ❌ Not supported | — | — |

### Architectures

Currently **host-build only** — you build on the machine you run on;
there is no cross-compilation or release pipeline yet (that is a
separate, future task).

| Arch | Status |
|---|---|
| **x86_64** | ✅ Supported (macOS Intel, Linux) |
| **aarch64** | ✅ Supported (macOS Apple Silicon, Linux arm64) |

Both architectures are supported wherever the OS is supported; the
gating is the OS, not the CPU. There are no arch-specific `cfg` paths in
the tree.

## macOS — first-class

Everything works out of the box:

- **App Nap is disabled** for the consent window and the pending-badge
  overlay (`NSProcessInfo.beginActivity`, via the macOS-only
  `objc2-foundation` / `winit` dependencies gated in `Cargo.toml`), so a
  backgrounded window still repaints when the daemon has something to ask.
- **launchd** runs the daemon as a `LaunchAgent`. `secreq daemon install`
  writes the plist; launchd keeps it alive (relaunching on the ~10s
  throttle if the singleton lock is already held).
- The **WindowServer** is always available in a login session, so the
  consent prompt has somewhere to draw with no extra configuration.

Peer credentials come from `getsockopt(LOCAL_PEERPID)`.

## Linux — first-class

- The daemon runs as a **systemd `--user` unit**
  (`secreq.service`), installed by `secreq daemon install`. It inherits
  your user-session environment (so `op` and the other provider CLIs are
  on `PATH`) and journals to `journalctl --user -u secreq`.
- Sockets live under **`$XDG_RUNTIME_DIR`** when it is set (the correct,
  tmpfs-backed, per-user location); `secreq` falls back to its own root
  only when it is unset.
- The consent window needs a **graphical session** — `$DISPLAY` (X11) or
  `$WAYLAND_DISPLAY` (Wayland). `eframe` is built with both the `x11` and
  `wayland` backends. On a headless box with neither, use per-invocation
  auto-approval instead of the window (see [Headless](#headless-use) below).

Peer credentials come from `getsockopt(SO_PEERCRED)`.

## \*BSD — best-effort, currently unsupported

The BSDs are Unix-family and most of `secreq` is portable to them in
principle (unix sockets, PATH shims, `execvp`, the provider CLIs). Two
things stop them from being first-class today:

1. **Compile gap.** The SSH-agent peer-credential lookup
   (`src/daemon/peercred.rs::peer_pid`) has implementations only for
   `target_os = "linux"` and `target_os = "macos"`, and it is called
   unconditionally on the SSH-agent path. A `*-unknown-freebsd` (or other
   BSD) build therefore **fails to compile** until an equivalent
   (`getpeereid` / `LOCAL_PEERCRED`) branch is added.
2. **No login service.** Autostart only knows launchd (macOS) and systemd
   (everything else). A BSD host has neither a systemd `--user` manager
   nor a plist, so `daemon install` does not produce a working unit; you
   would run `secreq daemon --fg` under your own supervisor.

Treat BSD as "patches welcome," not "supported."

## Windows — not supported

`secreq` **does not run on Windows,** and this is by design, not an
oversight to be filed. The model depends on:

- **Peer credentials over unix sockets** to attribute a request to a
  process (`SO_PEERCRED` / `LOCAL_PEERPID`) — there is no equivalent used.
- **`execvp` PATH shims** to interpose on every `gh` / `aws` / … call,
  including the ones `npm` / `make` / your IDE spawn.
- **Process-tree provenance** walked with Unix pid semantics.

You may notice a `windows` arm in the consent UI's theme flavor and a
stray Windows screenshot fixture in the dev-docs. **Those do not imply
Windows support** — they exist only so the theming code and the
screenshot harness stay total; there is no working Windows build, login
service, or socket path.

## Headless use

The consent window is the only piece that needs a display. When there is
no graphical session (a CI box, an SSH session with no forwarding, a
container), approve per-invocation instead of interactively:

- `secreq x <bin>` / the wrap shims: pass **`--sq-yes`**.
- `secreq run … -- <cmd>`: pass **`--yes`**.

Everything else — the daemon, provider resolution, masking, the audit
log — works headless.
