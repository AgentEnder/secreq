//! PTY-driven regression test for the interactive prompt flows.
//!
//! Arrow keys must move cliclack selects even when the terminal was left in
//! DECCKM "application cursor keys" mode (a crashed vim, a stray `smkx`),
//! where arrows arrive as SS3 `ESC O B` instead of CSI `ESC [ B`. The
//! `console` crate parses only CSI, so without a defense the selection
//! freezes while Enter and Escape keep working — the wrap picker becomes
//! "first item or nothing".
//!
//! secreq's defense is emitting the DECCKM reset (`ESC [ ? 1 l`) before
//! prompting. [`common::pty::PtyRun`] plays the part of a DECCKM-honoring
//! terminal that *starts* in application mode: it sends SS3 arrows until it
//! has seen the reset, CSI arrows after — so the test fails exactly when a
//! real stuck terminal would.
#![cfg(unix)]

mod common;

use std::time::Duration;

use common::pty::{twoway, PtyRun};
use common::Sandbox;

/// `secreq wrap <bin>` in a terminal stuck in application cursor-key mode:
/// one arrow-down must reach the second item ("Gate only"), producing a
/// gate-only wrap. Before the DECCKM reset existed, the arrow degraded to
/// an `UnknownEscSeq` the select ignored, Enter took "Inject secrets", and
/// the flow wandered into the provider picker instead.
#[test]
fn wrap_select_arrows_survive_application_cursor_mode() {
    let sb = Sandbox::new();
    sb.write_config(&format!(
        r#"
            shim_dir = "{shim}"

            [providers.fake]
            retrieve = ["printf", "%s", "{{locator}}"]
        "#,
        shim = sb.path().join("shims").display(),
    ));

    let mut run = PtyRun::spawn(&sb, &["wrap", "testbin"]);
    run.wait_for("What should this wrap do?", Duration::from_secs(20));
    run.press_arrow_down();
    std::thread::sleep(Duration::from_millis(150));
    run.press_enter();

    // Gate-only path goes straight to the reason prompt. Landing in the
    // provider picker means the arrow key was swallowed.
    let out = run.wait_for("Reason (shown in consent prompt)", Duration::from_secs(10));
    assert!(
        !twoway(&out, b"Provider for the next env var"),
        "arrow-down was ignored: select stayed on the first item"
    );
    run.press_enter(); // no reason

    let status = run.wait_exit(Duration::from_secs(10));
    assert!(status.success(), "wrap exited with {status:?}");

    let config = std::fs::read_to_string(sb.config_path()).expect("config written");
    assert!(
        config.contains("testbin"),
        "wrap missing from config:\n{config}"
    );
    assert!(
        !config.contains("secret://"),
        "gate-only wrap must inject nothing:\n{config}"
    );
}
