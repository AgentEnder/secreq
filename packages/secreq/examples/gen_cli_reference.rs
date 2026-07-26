//! Emit `docs/cli-reference.md` — every command secreq has, derived from
//! the clap tree rather than transcribed into prose.
//!
//! Regenerate the committed file with:
//!
//! ```sh
//! cargo run --example gen-cli-reference > docs/cli-reference.md
//! ```
//!
//! A drift test (`tests/cli_drift.rs`) fails CI when the committed file and
//! this output disagree, so a new subcommand or flag reaches the docs by
//! existing. The guide at `docs/cli.md` is the hand-written half — the argv
//! contract, `x` versus `run`, the trust model — and deliberately carries no
//! flag tables, because those are these.
//!
//! ## What it deliberately does not emit
//!
//! **Hidden commands and hidden args.** `secreq consent-window`,
//! `manager-window` and `pending-badge` are `#[command(hide = true)]`: the
//! daemon spawns them, a user never types them, and `secreq --help` already
//! declines to list them. The filter is clap's own `is_hide_set`, so a
//! command's visibility in the docs and its visibility in `--help` are the
//! same fact rather than two lists to keep in step.
//!
//! **`x`'s `--sq-` options.** They are parsed by hand in `cli::run_x`, never
//! by clap, precisely so that `<wrap> --help` reaches the wrapped binary.
//! Nothing here can see them, and inventing a table for them would be the
//! transcription this file exists to remove — so `secreq x`'s own long help
//! points at `secreq x --sq-help`, and the contract is explained in the
//! guide.

use clap::{Arg, Command};

/// Auto-generated args every command carries. Listing `--help` under all
/// twenty-odd commands is noise that pushes the real flags off the screen.
const UNIVERSAL: [&str; 2] = ["help", "version"];

fn main() {
    let mut out = String::new();
    let root = secreq::cli::command();

    out.push_str(&preamble());

    let globals: Vec<&Arg> = root
        .get_arguments()
        .filter(|a| a.is_global_set() && !a.is_hide_set() && !is_universal(a))
        .collect();
    if !globals.is_empty() {
        out.push_str("## Global options\n\n");
        out.push_str(
            "These reach the admin verbs and `run`. They do **not** apply to \
             `x`, whose argv belongs to the wrapped binary. See the \
             [argv contract](./cli.md#the-argv-contract) for its `--sq-` \
             equivalents.\n\n",
        );
        out.push_str(&arg_table(&globals));
        out.push_str("`-h`/`--help` and `-V`/`--version` work everywhere.\n\n");
    }

    for sub in visible_subcommands(&root) {
        emit(&mut out, sub, &["secreq"], 2);
    }

    print!("{out}");
}

fn preamble() -> String {
    // The banner is addressed to whoever opened the file in the repo and is
    // about to fix a typo in it. On the site it reads as provenance.
    "<!-- GENERATED FILE. DO NOT EDIT.\n     \
     Source: packages/secreq/src/cli.rs (the clap tree).\n     \
     Regenerate: cargo run --example gen-cli-reference > docs/cli-reference.md\n     \
     Guarded by: packages/secreq/tests/cli_drift.rs -->\n\n\
     # All commands\n\n\
     Every command, subcommand, and flag `secreq` accepts, generated from the \
     CLI definition itself.\n\n\
     This is the exhaustive list. For what the commands are *for* (the two \
     run verbs, why `x` forwards every flag it is given, how approval is \
     scoped) read the [CLI guide](./cli.md).\n\n"
        .to_string()
}

fn is_universal(arg: &Arg) -> bool {
    UNIVERSAL.contains(&arg.get_id().as_str())
}

/// Subcommands worth publishing, in declaration order.
///
/// `help` is clap's own generated subcommand and documents nothing secreq
/// does.
fn visible_subcommands(cmd: &Command) -> Vec<&Command> {
    cmd.get_subcommands()
        .filter(|c| !c.is_hide_set() && c.get_name() != "help")
        .collect()
}

/// One command, then its children one level deeper.
fn emit(out: &mut String, cmd: &Command, path: &[&str], depth: usize) {
    let name = cmd.get_name();
    let mut full: Vec<&str> = path.to_vec();
    full.push(name);
    let invocation = full.join(" ");

    out.push_str(&format!(
        "{} `{}`\n\n",
        "#".repeat(depth.min(6)),
        invocation
    ));

    out.push_str("```\n");
    out.push_str(&usage(cmd, &invocation));
    out.push_str("\n```\n\n");

    // `secreq ui` is a real spelling of `secreq view`, and a reader who was
    // told one of them by a colleague needs to find the other.
    let aliases: Vec<String> = cmd
        .get_visible_aliases()
        .map(|a| format!("`{} {a}`", path.join(" ")))
        .collect();
    if !aliases.is_empty() {
        out.push_str(&format!("Also spelled {}.\n\n", aliases.join(", ")));
    }

    if let Some(text) = describe(cmd) {
        out.push_str(&text);
        out.push_str("\n\n");
    }

    let positionals: Vec<&Arg> = cmd
        .get_arguments()
        .filter(|a| a.is_positional() && !a.is_hide_set())
        .collect();
    if !positionals.is_empty() {
        out.push_str("| Argument | Meaning |\n| --- | --- |\n");
        for arg in &positionals {
            out.push_str(&format!(
                "| `{}` | {} |\n",
                value_slot(arg),
                cell(help_of(arg).as_deref().unwrap_or("—"))
            ));
        }
        out.push('\n');
    }

    let flags: Vec<&Arg> = cmd
        .get_arguments()
        .filter(|a| {
            !a.is_positional() && !a.is_hide_set() && !a.is_global_set() && !is_universal(a)
        })
        .collect();
    if !flags.is_empty() {
        out.push_str(&arg_table(&flags));
    }

    for child in visible_subcommands(cmd) {
        emit(out, child, &full, depth + 1);
    }
}

/// The command's prose, preferring the long doc comment.
///
/// clap derive puts a doc comment's first line in `about` and the whole
/// thing in `long_about`. A reference page wants the whole thing — the
/// second paragraph of `daemon status` is where the exit codes are.
fn describe(cmd: &Command) -> Option<String> {
    let text = cmd
        .get_long_about()
        .or_else(|| cmd.get_about())
        .map(ToString::to_string)?;
    Some(reflow(&text))
}

fn help_of(arg: &Arg) -> Option<String> {
    arg.get_long_help()
        .or_else(|| arg.get_help())
        .map(ToString::to_string)
}

fn arg_table(args: &[&Arg]) -> String {
    let mut table = String::from("| Flag | Meaning |\n| --- | --- |\n");
    for arg in args {
        table.push_str(&format!(
            "| `{}` | {} |\n",
            flag_spelling(arg),
            cell(help_of(arg).as_deref().unwrap_or("—"))
        ));
    }
    table.push('\n');
    table
}

/// `-y`, `--yes`, `--env-file <PATH>` — every spelling the user may type.
fn flag_spelling(arg: &Arg) -> String {
    let mut parts = Vec::new();
    if let Some(short) = arg.get_short() {
        parts.push(format!("-{short}"));
    }
    if let Some(long) = arg.get_long() {
        parts.push(format!("--{long}"));
    }
    if parts.is_empty() {
        parts.push(arg.get_id().to_string());
    }
    let mut spelled = parts.join(", ");
    if arg.get_action().takes_values() {
        spelled.push(' ');
        spelled.push_str(&value_slot(arg));
    }
    spelled
}

/// `<PATH>`, `<REF>…` — the placeholder, with an ellipsis when repeatable.
fn value_slot(arg: &Arg) -> String {
    let name = arg
        .get_value_names()
        .and_then(|names| names.first())
        .map_or_else(
            || arg.get_id().to_string().to_uppercase(),
            ToString::to_string,
        );
    let repeats = matches!(arg.get_action(), clap::ArgAction::Append)
        || arg.get_num_args().is_some_and(|r| r.max_values() > 1);
    if repeats {
        format!("<{name}>…")
    } else {
        format!("<{name}>")
    }
}

/// `secreq ssh add <NAME> [OPTIONS]` — built here rather than taken from
/// clap's `render_usage`, which needs a `&mut Command` and prints a
/// terminal-shaped block rather than one line.
fn usage(cmd: &Command, invocation: &str) -> String {
    // `x` is the one command whose real argv clap never sees — its args are
    // hidden so `secreq --help` stays readable, which would otherwise leave
    // the usage line here reading `secreq x` and taking no arguments. The
    // override is declared beside the variant in `cli.rs`, so the correction
    // lives with the thing being corrected; `get_override_usage` is private,
    // but `render_usage` honours it, and a rendered usage that already names
    // this command is one clap authored deliberately.
    let rendered = flatten(&cmd.clone().render_usage().to_string());
    if let Some(stripped) = rendered.strip_prefix("Usage: ") {
        if stripped.starts_with("secreq ") {
            return stripped.to_string();
        }
    }

    let mut line = String::from(invocation);

    if cmd
        .get_arguments()
        .any(|a| !a.is_positional() && !a.is_hide_set() && !is_universal(a))
    {
        line.push_str(" [OPTIONS]");
    }

    for arg in cmd.get_arguments().filter(|a| a.is_positional()) {
        if arg.is_hide_set() {
            continue;
        }
        let slot = value_slot(arg);
        line.push(' ');
        if arg.is_required_set() {
            line.push_str(&slot);
        } else {
            line.push_str(&format!("[{slot}]"));
        }
    }

    if !visible_subcommands(cmd).is_empty() {
        line.push_str(" <SUBCOMMAND>");
    }

    line
}

/// Collapse a doc comment into markdown paragraphs.
///
/// Doc comments wrap at the source's column limit, which is not the
/// reader's, so single newlines are soft and join. A blank line is a real
/// paragraph break and survives.
///
/// An **indented** paragraph is the exception, and it has to be: several
/// commands illustrate themselves with a shell line in their doc comment
/// (`agent open`'s `ssh -R` forward, `resolve`'s command substitution).
/// Rewrapping those joins the continuation of a `\`-continued line onto its
/// head and publishes a command that does not run — which is the same
/// hand-copied-and-rotted failure this generator exists to prevent, just
/// arriving by a different route.
fn reflow(text: &str) -> String {
    let mut paragraphs: Vec<String> = Vec::new();

    for para in text.split("\n\n") {
        let lines: Vec<&str> = para.lines().filter(|l| !l.trim().is_empty()).collect();
        if lines.is_empty() {
            continue;
        }
        if lines.iter().all(|l| l.starts_with("  ")) {
            // The *common* indent, not each line's own: a `\`-continued
            // argument is indented further than the command it continues,
            // and flattening that reads as two commands rather than one.
            let common = lines
                .iter()
                .map(|l| l.len() - l.trim_start().len())
                .min()
                .unwrap_or(0);
            let body: Vec<&str> = lines.iter().map(|l| &l[common..]).collect();
            paragraphs.push(format!("```sh\n{}\n```", body.join("\n")));
        } else {
            paragraphs.push(flatten(para));
        }
    }

    paragraphs.join("\n\n")
}

/// All whitespace — including the paragraph breaks — down to single spaces.
fn flatten(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// A table cell: one line, and no pipe that would end the row early.
fn cell(text: &str) -> String {
    flatten(text).replace('|', "\\|")
}
