//! Login auto-start service for the consent daemon (`secreq daemon install`).
//!
//! The SSH agent socket only exists while the daemon runs. Wraps auto-spawn
//! the daemon on demand, but nothing spawns it for an *incoming* SSH
//! connection — so `SSH_AUTH_SOCK` points at a dead socket unless a daemon
//! already happens to be up. A per-user login service fixes that: the OS
//! starts `secreq daemon --fg` at login and keeps it alive.
//!
//! Mirrors [`crate::path_setup`] / [`crate::ssh_setup`]'s design: pure
//! `plan()`/`apply()`/`remove()` over a `home`-injectable service-file path,
//! with the side-effecting service-manager calls (`launchctl` / `systemctl`)
//! split into separate [`load_service`] / [`unload_service`] functions so the
//! unit tests render + write + remove without ever touching the real loader.
//!
//! - **macOS** → a launchd LaunchAgent plist at
//!   `~/Library/LaunchAgents/com.secreq.daemon.plist`. launchd spawns
//!   processes with a minimal environment, so the plist pins a sane `PATH`
//!   (`EnvironmentVariables`) — otherwise the daemon can't find `op` and the
//!   other provider binaries when it resolves secrets.
//! - **Linux** → a systemd `--user` unit at
//!   `~/.config/systemd/user/secreq.service`. systemd `--user` inherits the
//!   user-session environment, so no explicit `PATH` is needed (but `op` must
//!   be on the login PATH).

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

/// launchd job label / systemd-adjacent identity for our service.
pub const LAUNCHD_LABEL: &str = "com.secreq.daemon";
/// systemd `--user` unit name.
pub const SYSTEMD_UNIT: &str = "secreq.service";

/// A sane fallback `PATH` for the launchd-spawned daemon. launchd gives a job
/// a near-empty environment, so without this the daemon can't find `op` (which
/// homebrew installs under `/opt/homebrew/bin` on Apple Silicon or
/// `/usr/local/bin` on Intel) or other provider binaries.
const LAUNCHD_PATH: &str = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin";

/// Which login-service mechanism this host uses. macOS → launchd LaunchAgent;
/// everything else we treat as systemd `--user` for the purposes of this
/// command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Macos,
    Linux,
}

/// Detect the platform via `cfg!`. macOS → [`Platform::Macos`]; everything
/// else → [`Platform::Linux`] (the systemd `--user` path).
pub fn current_platform() -> Platform {
    if cfg!(target_os = "macos") {
        Platform::Macos
    } else {
        Platform::Linux
    }
}

/// Path of the service definition file for `platform`, under `home`.
/// `home`-injectable so tests can use a temp dir.
pub fn service_file_path(home: &Path, platform: Platform) -> PathBuf {
    match platform {
        Platform::Macos => home
            .join("Library/LaunchAgents")
            .join(format!("{LAUNCHD_LABEL}.plist")),
        Platform::Linux => home.join(".config/systemd/user").join(SYSTEMD_UNIT),
    }
}

/// Render a launchd LaunchAgent plist that runs `secreq daemon --fg`.
///
/// - `Label = com.secreq.daemon`
/// - `ProgramArguments = [<exe>, "daemon", "--fg"]`
/// - `RunAtLoad = true`, `KeepAlive = true` (start at login, restart on exit)
/// - `StandardOutPath` / `StandardErrorPath = <log_path>` (the same log
///   `secreq daemon log-path` prints, so users have one place to look)
/// - `EnvironmentVariables.PATH` pinned (launchd's env is minimal)
///
/// The exe and log paths are XML-escaped.
pub fn render_launchd_plist(exe: &Path, log_path: &Path) -> String {
    let exe = xml_escape(&exe.display().to_string());
    let log = xml_escape(&log_path.display().to_string());
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{LAUNCHD_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exe}</string>
        <string>daemon</string>
        <string>--fg</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{log}</string>
    <key>StandardErrorPath</key>
    <string>{log}</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>{LAUNCHD_PATH}</string>
    </dict>
</dict>
</plist>
"#
    )
}

/// Render a systemd `--user` unit that runs `secreq daemon --fg`.
///
/// systemd `--user` inherits the user-session environment, so we don't pin a
/// `PATH` here — but the daemon still needs `op` (and friends) reachable on
/// that login PATH to resolve secrets. `log_path` is referenced in a comment;
/// systemd journals stdout/stderr itself (`journalctl --user -u secreq`), so
/// there's no need to redirect to a file the way launchd does.
pub fn render_systemd_unit(exe: &Path, log_path: &Path) -> String {
    let exe = exe.display();
    let log = log_path.display();
    format!(
        "[Unit]\n\
         Description=secreq consent daemon (SSH agent + wrap consent)\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={exe} daemon --fg\n\
         Restart=on-failure\n\
         # systemd journals stdout/stderr: journalctl --user -u {SYSTEMD_UNIT}\n\
         # (the file daemon log still lives at {log})\n\
         # PATH is inherited from your user systemd environment — `op` and other\n\
         # provider binaries must be reachable there.\n\
         \n\
         [Install]\n\
         WantedBy=default.target\n"
    )
}

/// What [`apply`] will do — handed to the caller to show before any file is
/// touched. Mirrors [`crate::ssh_setup::SshSetupPlan`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallPlan {
    /// Which platform's service this plan targets.
    pub platform: Platform,
    /// Path of the service file we'll write (created with parents if absent).
    pub service_file: PathBuf,
    /// Rendered service definition. Show this to the user.
    pub contents: String,
    /// True if a service file already exists at [`Self::service_file`]. We
    /// still rewrite it (the exe path may have moved), but the handler can use
    /// this to phrase its messaging.
    pub already_installed: bool,
}

/// Build the install plan: the service-file path and its rendered contents.
/// Pure — no filesystem writes. Use [`apply`] to actually write.
///
/// `home` lets tests stand in a temp dir for `$HOME`; `exe` is the
/// `secreq` binary the service should exec; `log_path` is the daemon log file.
pub fn plan(home: &Path, platform: Platform, exe: &Path, log_path: &Path) -> Result<InstallPlan> {
    let service_file = service_file_path(home, platform);
    let contents = match platform {
        Platform::Macos => render_launchd_plist(exe, log_path),
        Platform::Linux => render_systemd_unit(exe, log_path),
    };
    let already_installed = service_file.exists();
    Ok(InstallPlan {
        platform,
        service_file,
        contents,
        already_installed,
    })
}

/// Apply the plan: create parent dirs and write the service file (mode 0644).
///
/// Unlike the PATH/SSH managed-block writers, this **always rewrites** rather
/// than no-op'ing when already installed — the exe path baked into the service
/// definition may have changed (a new install location, a moved binary), and a
/// stale path would silently break auto-start. Returns `Ok(true)` if the file
/// was newly created or its contents changed, `Ok(false)` if the on-disk
/// contents were already byte-identical (so the caller can say "nothing
/// changed").
pub fn apply(plan: &InstallPlan) -> Result<bool> {
    if let Some(parent) = plan.service_file.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("could not create {}", parent.display()))?;
    }
    let unchanged = std::fs::read_to_string(&plan.service_file)
        .map(|existing| existing == plan.contents)
        .unwrap_or(false);
    if unchanged {
        return Ok(false);
    }
    std::fs::write(&plan.service_file, &plan.contents)
        .with_context(|| format!("could not write {}", plan.service_file.display()))?;
    set_mode_0644(&plan.service_file)?;
    Ok(true)
}

/// Remove the service file for `platform` under `home`. Returns `Ok(false)` if
/// the file was already absent. Does **not** touch the service manager — call
/// [`unload_service`] first to stop/disable the running job.
pub fn remove(home: &Path, platform: Platform) -> Result<bool> {
    let service_file = service_file_path(home, platform);
    match std::fs::remove_file(&service_file) {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => {
            Err(err).with_context(|| format!("could not remove {}", service_file.display()))
        }
    }
}

// ── Side-effecting service-manager calls (kept OUT of the pure path) ──────────
//
// These shell out to `launchctl` / `systemctl`. Tests never call them, so the
// pure plan/apply/remove path stays hermetic.

/// Load (and enable) the freshly-written service so it's running now and
/// starts at the next login.
///
/// - **macOS:** `launchctl bootstrap gui/<uid> <file>`, falling back to the
///   older `launchctl load -w <file>` if bootstrap fails (e.g. the job is
///   already bootstrapped, or on an OS where bootstrap behaves differently).
/// - **Linux:** `systemctl --user daemon-reload`, then
///   `systemctl --user enable --now secreq.service`.
pub fn load_service(platform: Platform, service_file: &Path) -> Result<()> {
    match platform {
        Platform::Macos => {
            let target = format!("gui/{}", current_uid());
            // Try the modern bootstrap first; fall back to load -w.
            match run_capture(
                "launchctl",
                &["bootstrap", &target, &path_str(service_file)],
            ) {
                Ok(()) => Ok(()),
                Err(bootstrap_err) => {
                    run_capture("launchctl", &["load", "-w", &path_str(service_file)]).with_context(
                        || format!("launchctl bootstrap also failed: {bootstrap_err:#}"),
                    )
                }
            }
        }
        Platform::Linux => {
            run_capture("systemctl", &["--user", "daemon-reload"])?;
            run_capture("systemctl", &["--user", "enable", "--now", SYSTEMD_UNIT])
        }
    }
}

/// Unload (and disable) the service: stop the running job and clear its
/// start-at-login registration. Best-effort reverse of [`load_service`].
///
/// - **macOS:** `launchctl bootout gui/<uid>/com.secreq.daemon`, falling back
///   to `launchctl unload <file>`.
/// - **Linux:** `systemctl --user disable --now secreq.service`.
pub fn unload_service(platform: Platform, service_file: &Path) -> Result<()> {
    match platform {
        Platform::Macos => {
            let target = format!("gui/{}/{LAUNCHD_LABEL}", current_uid());
            match run_capture("launchctl", &["bootout", &target]) {
                Ok(()) => Ok(()),
                Err(bootout_err) => run_capture("launchctl", &["unload", &path_str(service_file)])
                    .with_context(|| format!("launchctl bootout also failed: {bootout_err:#}")),
            }
        }
        Platform::Linux => run_capture("systemctl", &["--user", "disable", "--now", SYSTEMD_UNIT]),
    }
}

/// Current real user id, for the `gui/<uid>` launchd domain target.
fn current_uid() -> u32 {
    // SAFETY: `getuid` is always-succeeds and has no preconditions — it reads
    // the calling process's real uid and can't fail or touch memory we own.
    unsafe { libc::getuid() }
}

/// Run a command, returning a helpful error (including captured stderr) on a
/// non-zero exit or a spawn failure.
fn run_capture(program: &str, args: &[&str]) -> Result<()> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("could not run `{program} {}`", args.join(" ")))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    bail!(
        "`{program} {}` failed ({}): {}",
        args.join(" "),
        output.status,
        stderr.trim()
    );
}

fn path_str(path: &Path) -> String {
    path.display().to_string()
}

fn set_mode_0644(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let mut perms = std::fs::metadata(path)
        .with_context(|| format!("could not stat {}", path.display()))?
        .permissions();
    perms.set_mode(0o644);
    std::fs::set_permissions(path, perms)
        .with_context(|| format!("could not set mode 0644 on {}", path.display()))
}

/// Escape the five XML special characters so a path with `&`, `<`, etc. can't
/// break the plist.
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launchd_plist_has_program_args_runatload_keepalive_and_path() {
        let exe = Path::new("/usr/local/bin/secreq");
        let log = Path::new("/Users/me/.local/state/secreq/daemon.log");
        let plist = render_launchd_plist(exe, log);

        assert!(plist.contains("<string>/usr/local/bin/secreq</string>"));
        assert!(plist.contains("<string>daemon</string>"));
        assert!(plist.contains("<string>--fg</string>"));
        assert!(plist.contains("<key>RunAtLoad</key>"));
        assert!(plist.contains("<key>KeepAlive</key>"));
        assert!(plist.contains("<string>com.secreq.daemon</string>"));
        // The pinned PATH so launchd's minimal env can still find `op`.
        assert!(plist.contains(LAUNCHD_PATH));
        // Log path wired to both stdout and stderr.
        assert!(plist.contains("<key>StandardOutPath</key>"));
        assert!(plist.contains(&log.display().to_string()));
    }

    #[test]
    fn launchd_plist_xml_escapes_paths() {
        let exe = Path::new("/opt/A&B/secreq");
        let log = Path::new("/tmp/daemon.log");
        let plist = render_launchd_plist(exe, log);
        assert!(plist.contains("/opt/A&amp;B/secreq"));
        assert!(!plist.contains("/opt/A&B/secreq"));
    }

    #[test]
    fn systemd_unit_has_execstart_and_wantedby() {
        let exe = Path::new("/home/me/.local/bin/secreq");
        let log = Path::new("/home/me/.local/state/secreq/daemon.log");
        let unit = render_systemd_unit(exe, log);

        assert!(unit.contains("ExecStart=/home/me/.local/bin/secreq daemon --fg"));
        assert!(unit.contains("Restart=on-failure"));
        assert!(unit.contains("WantedBy=default.target"));
        assert!(unit.contains("Type=simple"));
        assert!(unit.contains("Description=secreq consent daemon (SSH agent + wrap consent)"));
    }

    #[test]
    fn apply_writes_service_file_and_remove_deletes_it() {
        let home = tempfile::tempdir().unwrap();
        let platform = current_platform();
        let exe = Path::new("/usr/local/bin/secreq");
        let log = Path::new("/tmp/secreq-daemon.log");

        let p = plan(home.path(), platform, exe, log).unwrap();
        assert!(!p.already_installed);
        assert_eq!(p.service_file, service_file_path(home.path(), platform));

        // First apply creates the file with the rendered contents.
        assert!(apply(&p).unwrap(), "first apply should write");
        let on_disk = std::fs::read_to_string(&p.service_file).unwrap();
        assert_eq!(on_disk, p.contents);

        // Re-applying identical contents reports "unchanged" (Ok(false)).
        let p_again = plan(home.path(), platform, exe, log).unwrap();
        assert!(p_again.already_installed);
        assert!(
            !apply(&p_again).unwrap(),
            "identical re-apply must report unchanged"
        );

        // Changing the exe path rewrites and reports changed.
        let p_moved = plan(home.path(), platform, Path::new("/opt/secreq/secreq"), log).unwrap();
        assert!(apply(&p_moved).unwrap(), "moved exe must rewrite");
        let moved_on_disk = std::fs::read_to_string(&p.service_file).unwrap();
        assert_eq!(moved_on_disk, p_moved.contents);

        // remove deletes it once, then reports absent.
        assert!(
            remove(home.path(), platform).unwrap(),
            "remove should delete"
        );
        assert!(!p.service_file.exists());
        assert!(
            !remove(home.path(), platform).unwrap(),
            "second remove must report false"
        );
    }

    #[test]
    fn plan_reports_already_installed_when_file_exists() {
        let home = tempfile::tempdir().unwrap();
        let platform = current_platform();
        let exe = Path::new("/usr/local/bin/secreq");
        let log = Path::new("/tmp/secreq-daemon.log");

        let service_file = service_file_path(home.path(), platform);
        std::fs::create_dir_all(service_file.parent().unwrap()).unwrap();
        std::fs::write(&service_file, "stale contents").unwrap();

        let p = plan(home.path(), platform, exe, log).unwrap();
        assert!(p.already_installed);
    }
}
