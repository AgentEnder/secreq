//! End-to-end check of the daemon's persistent structured log.
//!
//! The unit tests in `daemon::log` cover the pure rendering and the
//! resource-summary math. This integration test exercises the part they
//! can't: that `sample_resources` actually drives the global file sink,
//! writing a parseable JSON line to the structured `<state_dir>/daemon.jsonl`
//! (the human-format sibling is `daemon.log`).
//!
//! It runs in its own process (one test binary per file) and pins the
//! environment via `common::Sandbox::enter`, so the log location is fully
//! isolated — and it never spawns a real daemon, so it can't collide with
//! the singleton pidfile lock or disturb a developer's running daemon.

mod common;

use std::io::BufRead;

use secreq::daemon::log;

#[test]
fn sample_resources_writes_a_structured_resource_line() {
    let sb = common::Sandbox::new();
    let _env = sb.enter();

    let mut sys = log::prime_resource_sampler();
    log::sample_resources(&mut sys);

    // The structured JSON sink is `daemon.jsonl` (the human `daemon.log` is
    // its sibling); the resource envelope is asserted against the JSON.
    let jsonl_path = sb.root().join("daemon.jsonl");
    let file = std::fs::File::open(&jsonl_path)
        .unwrap_or_else(|e| panic!("daemon.jsonl should exist at {}: {e}", jsonl_path.display()));

    // Find the resource record and validate its structured envelope.
    let resource_line = std::io::BufReader::new(file)
        .lines()
        .map_while(Result::ok)
        .map(|l| serde_json::from_str::<serde_json::Value>(&l).expect("each line is valid JSON"))
        .find(|v| v["tag"] == "resource")
        .expect("a resource sample line should have been written");

    assert_eq!(resource_line["level"], "metric");
    assert_eq!(resource_line["pid"], std::process::id());
    assert!(
        resource_line["rss_bytes"]
            .as_u64()
            .expect("rss_bytes is u64")
            > 0,
        "a live process must report non-zero RSS: {resource_line}"
    );
    assert!(resource_line["cpu_pct"].as_f64().expect("cpu_pct is f64") >= 0.0);
    assert!(resource_line.get("uptime_s").is_some());
    assert!(resource_line.get("ts_unix").is_some());
    assert!(resource_line.get("t_mono_s").is_some());
}
