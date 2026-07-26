# Platform support

`secreq` is a **Unix tool at its core.** It leans on peer-credential lookup
over unix-domain sockets (`SO_PEERCRED` / `LOCAL_PEERPID`), process-tree
walking, PATH shims and `execvp` — none of which have a first-class Windows
equivalent.

| Platform                             | Status                      | Login service                                                      | Consent window needs                              |
| ------------------------------------ | --------------------------- | -------------------------------------------------------------------- | --------------------------------------------------- |
| **macOS**                            | ✅ First-class              | launchd LaunchAgent (`~/Library/LaunchAgents/com.secreq.daemon.plist`) | Nothing — the WindowServer is always present.     |
| **Linux**                            | ✅ First-class              | systemd `--user` unit (`~/.config/systemd/user/secreq.service`)     | `$DISPLAY` (X11) or `$WAYLAND_DISPLAY` (Wayland). |
| **\*BSD** (FreeBSD, OpenBSD, NetBSD) | ⚠️ Best-effort, unsupported | None — no systemd `--user` manager and no plist.                     | Same as Linux. **Known compile gap, below.**      |
| **Windows**                          | ❌ Not supported            | —                                                                     | —                                                 |

**x86_64 and aarch64 are both supported wherever the OS is.** The gating is
the OS, not the CPU; there are no arch-specific code paths.

Prebuilt binaries ship for the four first-class targets
(`{x86_64,aarch64}-{unknown-linux-gnu,apple-darwin}`). Anywhere else,
[`cargo install`](./install.md#cargo-install) builds from source.

## macOS

Everything works out of the box.

- **App Nap is disabled** for the consent window and the pending badge, so a
  backgrounded window still repaints when the daemon has something to ask.
- **launchd** runs the daemon as a LaunchAgent, written by
  `secreq daemon install` and kept alive across logins.
- Peer credentials come from `getsockopt(LOCAL_PEERPID)`.

## Linux

- The daemon runs as a **systemd `--user` unit**, installed by
  `secreq daemon install`. It inherits your user-session environment, so
  `op` and other provider CLIs are on `PATH`, and journals to
  `journalctl --user -u secreq`.
- Sockets live under **`$XDG_RUNTIME_DIR`** when set (the correct
  tmpfs-backed per-user location); secreq falls back to its own root only
  when it is unset.
- The consent window needs a **graphical session**. `eframe` is built with
  both the X11 and Wayland backends.
- Peer credentials come from `getsockopt(SO_PEERCRED)`.

## \*BSD

Most of secreq is portable to the BSDs in principle — unix sockets, PATH
shims, `execvp`, the provider CLIs. Two things stop them being first-class:

1. **A compile gap.** The SSH-agent peer-credential lookup
   (`daemon/peercred.rs::peer_pid`) has implementations only for Linux and
   macOS and is called unconditionally on the SSH path, so a BSD build
   **fails to compile** until a `getpeereid` / `LOCAL_PEERCRED` branch is
   added.
2. **No login service.** Autostart knows launchd and systemd only, so
   `daemon install` produces nothing usable; you'd run `secreq daemon --fg`
   under your own supervisor.

Treat BSD as "patches welcome," not "supported."

## Windows

`secreq` **does not run on Windows,** by design rather than by omission. The
model depends on peer credentials over unix sockets to attribute a request
to a process, `execvp` PATH shims to interpose on every call including the
ones `npm` and your IDE spawn, and process-tree provenance walked with Unix
pid semantics.

You may notice a `windows` arm in the consent UI's theme flavors and Windows
screenshots in the docs. **Those do not imply Windows support** — they exist
so the theming code and the screenshot harness stay total, and so the docs
can show a reader chrome they recognize. There is no working Windows build,
login service, or socket path.

## Headless use

The consent window is the only piece that needs a display. Where there's no
graphical session (CI, an SSH session without forwarding, a container),
approve per-invocation instead:

- `secreq x <bin>` and the wrap shims: **`--sq-yes`**.
- `secreq run … -- <cmd>`: **`--yes`**.

Everything else works headless: the daemon, provider resolution, masking,
and the audit log.
