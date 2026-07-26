# Platform support

`secreq` runs on macOS and Linux today. Everything it does is written against
Unix interfaces, so a Windows port is a real piece of work rather than a
recompile, but it is wanted and nothing about the design rules it out.

| Platform                         | Status        |
| -------------------------------- | ------------- |
| macOS                            | Supported     |
| Linux                            | Supported     |
| \*BSD (FreeBSD, OpenBSD, NetBSD) | Not supported |
| Windows                          | Not supported |

The gating is the OS, not the CPU: x86_64 and aarch64 both work wherever the
OS does. Prebuilt binaries ship for all four supported combinations
(`{x86_64,aarch64}-{unknown-linux-gnu,apple-darwin}`); anywhere else,
[`cargo install`](./install.md#cargo-install) builds from source.

## macOS

Everything works out of the box. `secreq daemon install` writes a launchd
LaunchAgent, which keeps the daemon running across logins. A backgrounded
consent window still repaints when the daemon has something to ask, so a
prompt never arrives frozen.

## Linux

`secreq daemon install` writes a systemd `--user` unit. It inherits your
user-session environment, so `op` and the other provider CLIs are on `PATH`,
and it journals to `journalctl --user -u secreq`.

The consent window needs a graphical session; both X11 and Wayland work.
Without one, see [headless use](#headless-use) below.

Sockets live under `$XDG_RUNTIME_DIR` when it is set, which is the
tmpfs-backed per-user directory that gets cleaned up when you log out. If it
is unset, secreq falls back to its own root at `~/.secreq/run`.

## \*BSD

Unix sockets, PATH shims, `execvp` and the provider CLIs all port to the
BSDs. Two things are missing:

1. It does not compile yet. The SSH agent reads the peer process id through
   code written for Linux and macOS only, so a BSD build fails at compile
   time. The missing piece is a `getpeereid` / `LOCAL_PEERCRED` branch in
   `daemon/peercred.rs`.
2. There is no login service. Autostart knows launchd and systemd, so
   `secreq daemon install` produces nothing usable. Run `secreq daemon --fg`
   under your own supervisor instead.

Patches welcome. BSD is not supported today.

## Windows

Not yet. There is no Windows build, and nobody is running one.

It is not blocked on anything conceptual: each interface secreq relies on has
a Windows counterpart, and porting means writing against them rather than
finding a substitute for something missing.

| What secreq uses on Unix                         | The Windows counterpart                                                     |
| ------------------------------------------------ | --------------------------------------------------------------------------- |
| `SO_PEERCRED` / `LOCAL_PEERPID` on a unix socket | A named pipe, whose client pid comes from `GetNamedPipeClientProcessId`     |
| Walking `/proc` or `sysctl` for the caller chain | `CreateToolhelp32Snapshot`, which reports each process's parent             |
| Process start time, to defeat pid recycling      | `GetProcessTimes`                                                           |
| A PATH shim that `execvp`s the real binary       | A shim executable on `PATH`, the mechanism scoop and chocolatey already use |
| launchd and systemd `--user`                     | Task Scheduler, or a Run key                                                |

Two of those are more than renaming a call. Windows has `AF_UNIX` but carries
no peer credentials over it, so the daemon's socket layer would become named
pipes rather than gaining a `#[cfg]` arm. And nothing on Windows replaces a
process in place the way `execvp` does: the shim either exits and leaves the
binary running under a new pid, or stays alive as its parent and forwards the
exit code. Either way the caller chain the consent prompt shows you gains a
frame that isn't there on Unix.

The screenshots in these docs are rendered in a Windows theme as well as
macOS and GNOME, so you may see one that looks native. That is the docs
showing you chrome you recognise, not a working port.

## Headless use

The consent window is the only piece that needs a display. Where there's no
graphical session (CI, an SSH session without forwarding, a container),
approve per-invocation instead:

- `secreq x <bin>` and the wrap shims: **`--sq-yes`**.
- `secreq run … -- <cmd>`: **`--yes`**.

Everything else works headless: the daemon, provider resolution, masking,
and the audit log.
