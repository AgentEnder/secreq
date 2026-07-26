//! Keeps `docs/cli-reference.md` in step with the clap tree in `src/cli.rs`.
//!
//! The failure this exists to prevent is not a typo — it is a command that
//! ships with no documentation at all. `secreq read`, `daemon status`,
//! `migrate restore`, `agent open` and `run --prompt-unresolved` all existed,
//! all worked, and none of them appeared in the hand-written CLI reference,
//! because nothing ever checked. Documentation coverage was a thing a person
//! had to remember; now it is a thing the build knows.
//!
//! Regenerate after any change to the CLI surface:
//!
//! ```sh
//! cargo run --example gen-cli-reference > docs/cli-reference.md
//! ```

use std::process::Command;

const REFERENCE: &str = "../../docs/cli-reference.md";
const REGEN: &str = "cargo run --example gen-cli-reference > docs/cli-reference.md";

/// Run the generator the same way a contributor would, so the test cannot
/// pass against a code path the documented command does not take.
///
/// Calling the generator's functions directly would be faster and would test
/// something else: the drift that matters is between the *committed file* and
/// *what the command emits*, and only one of those is a function call.
fn generated() -> String {
    let output = Command::new(env!("CARGO"))
        .args(["run", "--quiet", "--example", "gen-cli-reference"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("gen-cli-reference example must run");

    assert!(
        output.status.success(),
        "gen-cli-reference failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8(output.stdout).expect("generated reference must be UTF-8")
}

#[test]
fn committed_cli_reference_matches_the_clap_tree() {
    let on_disk = std::fs::read_to_string(REFERENCE)
        .unwrap_or_else(|_| panic!("docs/cli-reference.md must exist; generate it:\n  {REGEN}"));

    assert_eq!(
        generated().trim_end(),
        on_disk.trim_end(),
        "docs/cli-reference.md is stale — the CLI surface changed.\nRegenerate it:\n  {REGEN}"
    );
}

/// Every visible command reaches the page.
///
/// The equality test above already implies this, but it fails as a wall of
/// diff. This one names the command that went missing, which is the sentence
/// someone actually needs when a rename quietly drops a heading.
#[test]
fn every_visible_command_has_a_heading() {
    let page = std::fs::read_to_string(REFERENCE)
        .unwrap_or_else(|_| panic!("docs/cli-reference.md must exist; generate it:\n  {REGEN}"));

    let mut missing = Vec::new();
    walk(&secreq::cli::command(), &["secreq"], &mut |invocation| {
        if !page.contains(&format!("`{invocation}`")) {
            missing.push(invocation.to_string());
        }
    });

    assert!(
        missing.is_empty(),
        "undocumented command(s): {}\nRegenerate the reference:\n  {REGEN}",
        missing.join(", ")
    );
}

/// The internals stay out.
///
/// `consent-window`, `manager-window` and `pending-badge` are spawned by the
/// daemon and are `#[command(hide = true)]` for the same reason they are
/// absent from `secreq --help`: publishing them invites someone to run one
/// and file a bug when it can't reach a daemon.
#[test]
fn hidden_commands_stay_unpublished() {
    let page = std::fs::read_to_string(REFERENCE)
        .unwrap_or_else(|_| panic!("docs/cli-reference.md must exist; generate it:\n  {REGEN}"));

    for hidden in secreq::cli::command()
        .get_subcommands()
        .filter(|c| c.is_hide_set())
    {
        let heading = format!("## `secreq {}`", hidden.get_name());
        assert!(
            !page.contains(&heading),
            "`secreq {}` is hidden but has a heading in docs/cli-reference.md",
            hidden.get_name()
        );
    }
}

fn walk(cmd: &clap::Command, path: &[&str], visit: &mut impl FnMut(&str)) {
    for sub in cmd.get_subcommands() {
        if sub.is_hide_set() || sub.get_name() == "help" {
            continue;
        }
        let mut full: Vec<&str> = path.to_vec();
        full.push(sub.get_name());
        visit(&full.join(" "));
        walk(sub, &full, visit);
    }
}
