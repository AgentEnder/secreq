//! Structured, persistent logging for the consent daemon.
//!
//! Every log event fans out to **two persistent files plus interactive
//! stderr**, all under `$XDG_STATE_HOME/secreq` (the dir that holds
//! `audit.log`):
//!
//! - **`daemon.jsonl`** — one JSON object per line, append-only. The record
//!   you `jq`/grep when debugging a past session or monitoring the daemon's
//!   footprint over time.
//! - **`daemon.log`** — the same events in the historical human format
//!   (`[secreq +12.345s tag] msg`). This is what `secreq daemon log-path`
//!   prints and what bare `secreq daemon` tails.
//! - **stderr**, but only when it's a TTY — so a developer running
//!   `secreq daemon --fg` in a terminal sees the state machine tick live.
//!   Under the login service (stderr redirected to a file) this is
//!   suppressed, because the two files above already capture everything.
//!
//! The two files are written directly by this module — each line in a
//! single `write_all`, so `O_APPEND` keeps whole lines atomic even when
//! several daemons or a `consent-window` child append at once (the `pid`
//! field disambiguates). They are **deliberately separate files**: they
//! used to be one (`daemon.log`), with the JSON writer and a launcher's
//! stderr redirect both appending through *different* fds — which tore
//! each other's lines. Splitting them removes the shared target.
//!
//! Each record carries:
//!
//! - `ts_unix`  — wall-clock seconds since the epoch, to correlate a
//!   daemon line with an `audit.log` row.
//! - `t_mono_s` — monotonic seconds since this process started. Survives
//!   wall-clock skew, which matters when chasing a hang between socket
//!   events and egui repaints.
//! - `pid`, `level`, `tag`, `msg`, plus any flattened metric fields
//!   (the resource sampler adds `cpu_pct` / `rss_bytes` / `uptime_s`).
//!
//! Human stderr line:
//!
//! ```text
//! [secreq +12.345s state] show_window: window_visible=true (was false)
//! ```
//!
//! JSON-lines file line:
//!
//! ```json
//! {"ts_unix":1717000000,"t_mono_s":12.345,"pid":4242,"level":"info","tag":"state","msg":"show_window: ..."}
//! ```
//!
//! Logging is **best-effort**: if the persistent file can't be opened
//! (no `$HOME`, unwritable state dir, …) we silently fall back to
//! stderr only. A logging failure must never take down the daemon.

use std::fmt::Arguments;
use std::fs::{File, OpenOptions};
use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value};
use sysinfo::{Process, ProcessRefreshKind, ProcessesToUpdate, System};

static START: OnceLock<Instant> = OnceLock::new();

fn start() -> Instant {
    *START.get_or_init(Instant::now)
}

/// Severity / kind of a log record. Kept deliberately small — the
/// daemon's debug surface is narrow. `Metric` tags the periodic
/// resource samples so monitoring tooling can filter them in or out
/// (`jq 'select(.level=="metric")'`).
#[derive(Clone, Copy)]
enum Level {
    Info,
    Warn,
    Metric,
}

impl Level {
    fn as_str(self) -> &'static str {
        match self {
            Level::Info => "info",
            Level::Warn => "warn",
            Level::Metric => "metric",
        }
    }
}

/// Lazily-opened append handles to the two persistent logs, each guarded by
/// a mutex so this process's threads (main loop, socket accept, consent
/// child reader) append whole lines without interleaving. Cross-process the
/// files are `O_APPEND`, so a single `write_all` per line stays atomic even
/// when several daemons append at once. `None` if a file couldn't be opened
/// — that sink degrades silently (the other sinks still carry the line).
static JSONL_FILE: OnceLock<Option<Mutex<File>>> = OnceLock::new();
static LOG_FILE: OnceLock<Option<Mutex<File>>> = OnceLock::new();

fn jsonl_sink() -> Option<&'static Mutex<File>> {
    JSONL_FILE
        .get_or_init(|| jsonl_path().ok().and_then(open_append).map(Mutex::new))
        .as_ref()
}

fn log_sink() -> Option<&'static Mutex<File>> {
    LOG_FILE
        .get_or_init(|| log_path().ok().and_then(open_append).map(Mutex::new))
        .as_ref()
}

/// Whether interactive stderr echo is on — true only when stderr is a TTY
/// (a developer running `daemon --fg`). Cached once: under the login
/// service stderr is a file, so we skip the echo and rely on the two files.
fn stderr_is_tty() -> bool {
    static TTY: OnceLock<bool> = OnceLock::new();
    *TTY.get_or_init(|| std::io::stderr().is_terminal())
}

/// Absolute path to the human-readable daemon log, `<state_dir>/daemon.log`
/// (honours `$XDG_STATE_HOME`, same dir as `audit.log`). The accessor
/// behind `secreq daemon log-path` and the `daemon` tail follower.
pub fn log_path() -> anyhow::Result<PathBuf> {
    crate::paths::daemon_log_path()
}

/// Absolute path to the structured JSON-lines daemon log,
/// `<state_dir>/daemon.jsonl` — one JSON object per line for `jq`/monitoring.
pub fn jsonl_path() -> anyhow::Result<PathBuf> {
    crate::paths::daemon_jsonl_path()
}

/// Open (creating if needed) a persistent log sink in append mode. Returns
/// `None` on any failure — logging degrades rather than erroring.
fn open_append(path: PathBuf) -> Option<File> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok()?;
    }
    OpenOptions::new().create(true).append(true).open(path).ok()
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Render one record as a single-line JSON string (no trailing
/// newline). Pure — the unit tests assert on its output directly. The
/// `fields` map is flattened into the top-level object so monitoring
/// queries read `.cpu_pct` rather than `.fields.cpu_pct`.
fn render_json(
    ts_unix: u64,
    t_mono_s: f64,
    pid: u32,
    level: Level,
    tag: &str,
    msg: &str,
    fields: &Map<String, Value>,
) -> String {
    let mut obj = Map::new();
    obj.insert("ts_unix".into(), Value::from(ts_unix));
    // Two-decimal monotonic clock — millisecond precision is more than
    // enough and keeps the line compact.
    obj.insert(
        "t_mono_s".into(),
        Value::from((t_mono_s * 1000.0).round() / 1000.0),
    );
    obj.insert("pid".into(), Value::from(pid));
    obj.insert("level".into(), Value::from(level.as_str()));
    obj.insert("tag".into(), Value::from(tag));
    obj.insert("msg".into(), Value::from(msg));
    for (k, v) in fields {
        obj.insert(k.clone(), v.clone());
    }
    Value::Object(obj).to_string()
}

/// The one place every log line is born. Renders all sinks from the same
/// captured timestamp so they never disagree. Each file line is a single
/// `write_all` (newline included) so a `tail`-style follower never observes
/// a half-written, possibly mid-multibyte line.
fn emit(level: Level, tag: &str, msg: &str, fields: &Map<String, Value>) {
    let t_mono_s = start().elapsed().as_secs_f64();
    let ts_unix = now_unix();
    let pid = std::process::id();

    // Structured JSON sink → daemon.jsonl (best-effort).
    if let Some(file) = jsonl_sink() {
        let mut line = render_json(ts_unix, t_mono_s, pid, level, tag, msg, fields);
        line.push('\n');
        if let Ok(mut guard) = file.lock() {
            // Ignore write errors — a full/unwritable disk must not crash
            // the daemon; the other sinks still carry the line.
            let _ = guard.write_all(line.as_bytes());
        }
    }

    // Human sink → daemon.log (best-effort), same atomic-per-line discipline.
    let human = render_human(t_mono_s, tag, msg);
    if let Some(file) = log_sink() {
        let mut line = human.clone();
        line.push('\n');
        if let Ok(mut guard) = file.lock() {
            let _ = guard.write_all(line.as_bytes());
        }
    }

    // Interactive echo — only when stderr is a terminal. Under the login
    // service stderr is redirected to a file, and echoing there would both
    // duplicate daemon.log and re-introduce the two-fd tearing this split
    // exists to fix.
    if stderr_is_tty() {
        eprintln!("{human}");
    }
}

/// Render the human-readable form of a log line. Pure, so the unit test
/// can assert the exact on-screen/on-disk shape.
fn render_human(t_mono_s: f64, tag: &str, msg: &str) -> String {
    format!("[secreq +{t_mono_s:>7.3}s {tag}] {msg}")
}

/// Write one debug line. Use [`log_at`] when you have a stable
/// subsystem tag (`state`, `server`, `ui`).
pub fn log(args: Arguments<'_>) {
    log_at("daemon", args);
}

/// Write one tagged debug line.
pub fn log_at(tag: &str, args: Arguments<'_>) {
    emit(Level::Info, tag, &args.to_string(), &Map::new());
}

/// Sample this process's CPU and memory and emit one `resource`
/// record. Caller owns the [`System`] so the cpu-usage delta is
/// computed against the *previous* sample (sysinfo derives CPU% from
/// the gap between two refreshes of the same process); see
/// [`prime_resource_sampler`].
pub fn sample_resources(sys: &mut System) {
    let Some(pid) = sysinfo::get_current_pid().ok() else {
        return;
    };
    sys.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[pid]),
        true,
        ProcessRefreshKind::nothing().with_cpu().with_memory(),
    );
    let Some(proc) = sys.process(pid) else {
        emit(
            Level::Warn,
            "resource",
            "resource sample skipped: own process not visible to sysinfo",
            &Map::new(),
        );
        return;
    };
    let (fields, human) = resource_summary(proc);
    emit(Level::Metric, "resource", &human, &fields);
}

/// Prime the resource sampler: take an initial CPU/memory reading so the
/// *first* real [`sample_resources`] call has a baseline to diff against
/// (without this the first reported `cpu_pct` is always 0.0). Returns a
/// `System` configured for cheap, self-only refreshes.
pub fn prime_resource_sampler() -> System {
    let mut sys = System::new();
    if let Ok(pid) = sysinfo::get_current_pid() {
        sys.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[pid]),
            true,
            ProcessRefreshKind::nothing().with_cpu().with_memory(),
        );
    }
    sys
}

/// Build the structured fields + human summary for one process sample.
/// Pure (modulo reading `proc`), so the unit test can drive it against
/// the test process itself.
fn resource_summary(proc: &Process) -> (Map<String, Value>, String) {
    let cpu_pct = proc.cpu_usage();
    let rss_bytes = proc.memory();
    let uptime_s = proc.run_time();

    let mut fields = Map::new();
    // Round CPU to two decimals — sub-percent noise isn't actionable.
    fields.insert(
        "cpu_pct".into(),
        Value::from((cpu_pct as f64 * 100.0).round() / 100.0),
    );
    fields.insert("rss_bytes".into(), Value::from(rss_bytes));
    fields.insert("uptime_s".into(), Value::from(uptime_s));

    let rss_mib = rss_bytes as f64 / (1024.0 * 1024.0);
    let human = format!("cpu={cpu_pct:.1}% rss={rss_mib:.1}MiB uptime={uptime_s}s");
    (fields, human)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_json_emits_expected_envelope() {
        let line = render_json(
            1_717_000_000,
            12.3456,
            4242,
            Level::Info,
            "state",
            "show_window: visible=true",
            &Map::new(),
        );
        let v: Value = serde_json::from_str(&line).expect("valid JSON line");
        assert_eq!(v["ts_unix"], 1_717_000_000u64);
        // Monotonic clock rounded to millisecond precision.
        assert_eq!(v["t_mono_s"], 12.346);
        assert_eq!(v["pid"], 4242);
        assert_eq!(v["level"], "info");
        assert_eq!(v["tag"], "state");
        assert_eq!(v["msg"], "show_window: visible=true");
        // No metric fields present on a plain log line.
        assert!(v.get("cpu_pct").is_none());
    }

    #[test]
    fn render_human_matches_historical_format() {
        // The human line format is load-bearing: the `daemon` tail follower
        // and users' eyes both expect `[secreq +<mono>s <tag>] <msg>`.
        let line = render_human(12.3456, "state", "show_window: visible=true");
        assert_eq!(line, "[secreq + 12.346s state] show_window: visible=true");
    }

    #[test]
    fn render_json_flattens_metric_fields_to_top_level() {
        let mut fields = Map::new();
        fields.insert("cpu_pct".into(), Value::from(0.5));
        fields.insert("rss_bytes".into(), Value::from(12_582_912u64));
        let line = render_json(1, 0.0, 1, Level::Metric, "resource", "cpu=0.5%", &fields);
        let v: Value = serde_json::from_str(&line).expect("valid JSON line");
        assert_eq!(v["level"], "metric");
        // Flattened — queryable as `.cpu_pct`, not `.fields.cpu_pct`.
        assert_eq!(v["cpu_pct"], 0.5);
        assert_eq!(v["rss_bytes"], 12_582_912u64);
    }

    #[test]
    fn resource_summary_reports_live_self_metrics() {
        // Drive the summary against our own test process: RSS must be
        // non-zero and uptime fields must be present and well-typed.
        let mut sys = System::new();
        let pid = sysinfo::get_current_pid().expect("current pid");
        sys.refresh_processes_specifics(
            ProcessesToUpdate::Some(&[pid]),
            true,
            ProcessRefreshKind::nothing().with_cpu().with_memory(),
        );
        let proc = sys.process(pid).expect("own process visible");
        let (fields, human) = resource_summary(proc);

        assert!(
            fields["rss_bytes"].as_u64().expect("rss is u64") > 0,
            "a running process must report non-zero RSS"
        );
        assert!(fields["cpu_pct"].as_f64().expect("cpu is f64") >= 0.0);
        assert!(fields.contains_key("uptime_s"));
        assert!(human.contains("rss="), "human summary: {human}");
    }
}
