//! Structured, persistent logging for the consent daemon.
//!
//! Every log event fans out to **two sinks**:
//!
//! - A **persistent JSON-lines file** at `<state_dir>/daemon.log` — the
//!   same `$XDG_STATE_HOME/secreq` directory that holds `audit.log`. One
//!   JSON object per line, append-only, survives daemon restarts. This
//!   is the record you `jq`/grep when debugging a past session or
//!   monitoring the daemon's footprint over time. Both the daemon and
//!   the short-lived `consent-window` child append here; the `pid` field
//!   disambiguates them.
//! - **Human-readable stderr**, in the historical format, so a developer
//!   running the daemon in the foreground still sees the consent-flow
//!   state machine tick in real time.
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
use std::io::Write;
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

/// Lazily-opened append handle to `<state_dir>/daemon.log`, guarded by a
/// mutex so the daemon main loop, the socket accept thread, and the
/// consent-window child's reader thread can all append without
/// interleaving partial lines. `None` if the file couldn't be opened —
/// in which case we log to stderr only.
static FILE: OnceLock<Option<Mutex<File>>> = OnceLock::new();

fn log_file() -> Option<&'static Mutex<File>> {
    FILE.get_or_init(|| open_log_file().map(Mutex::new))
        .as_ref()
}

/// Absolute path to the persistent daemon log, `<state_dir>/daemon.log`
/// (honours `$XDG_STATE_HOME`, same dir as `audit.log`). The public
/// accessor behind `secreq daemon log-path` and the `daemon` tail
/// follower.
pub fn log_path() -> anyhow::Result<PathBuf> {
    Ok(crate::audit::state_dir()?.join("daemon.log"))
}

/// Open (creating if needed) the persistent JSON-lines log. Returns
/// `None` on any failure — logging degrades to stderr rather than
/// erroring.
fn open_log_file() -> Option<File> {
    let path = log_path().ok()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok()?;
    }
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .ok()
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

/// The one place every log line is born. Renders both sinks from the
/// same captured timestamp so the file and stderr never disagree.
fn emit(level: Level, tag: &str, msg: &str, fields: &Map<String, Value>) {
    let t_mono_s = start().elapsed().as_secs_f64();
    let ts_unix = now_unix();
    let pid = std::process::id();

    // Persistent structured sink (best-effort). The whole line —
    // newline included — is written with a single `write_all` so the
    // append is atomic: the daemon and the consent-window child both
    // append here, and `tail`-style followers must never observe a
    // half-written (and possibly mid-multibyte) line.
    if let Some(file) = log_file() {
        let mut line = render_json(ts_unix, t_mono_s, pid, level, tag, msg, fields);
        line.push('\n');
        if let Ok(mut guard) = file.lock() {
            // Ignore write errors — a full/unwritable disk must not
            // crash the daemon. stderr below still carries the line.
            let _ = guard.write_all(line.as_bytes());
        }
    }

    // Human-readable foreground sink.
    eprintln!("[secreq +{t_mono_s:>7.3}s {tag}] {msg}");
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
