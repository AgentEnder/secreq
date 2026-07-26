//! Guards that the committed UI screenshot fixtures stay in step with the UI
//! that produces them.
//!
//! The fixtures in `dev-docs/ui-screenshots/` are **published assets** — the
//! docs site serves every one of them and switches between chrome variants on
//! the reader's OS and theme — so a stale PNG isn't a stale test artifact, it's
//! wrong documentation on secreq.dev. Rendering one needs a GPU, so CI cannot
//! catch drift by re-rendering.
//!
//! **This is a bookkeeping guard, not a pixel guard.** It deliberately does not
//! re-render and compare images: a wgpu render is not byte-reproducible across
//! GPUs and drivers, so a Linux runner's output would never match the macOS
//! renders in git no matter how correct both are. Comparing bytes would mean
//! choosing between "committed and reviewable" and "verified in CI".
//!
//! What it therefore checks, all without a GPU:
//!
//! 1. **Snapshots** — every fixture folder carries the `layout.json` that
//!    guards it, and that names its cells.
//! 2. **Completeness** — every cell that `layout.json` names is on disk.
//! 3. **No strays** — a fixture's folder holds its `layout.json` and its named
//!    renders and nothing else, so a renamed fixture or a narrowed chrome
//!    matrix doesn't leave a dead PNG the docs site keeps shipping.
//! 4. **Documentation** — every fixture has a row in the README table, which
//!    `CLAUDE.md` requires and which is otherwise trivial to forget.
//! 5. **Numbering** — no two fixtures claim the same `NN-` prefix, which is
//!    how a fixture is cited everywhere except its own folder name.
//!
//! A fixture *is* a directory here — there is no separate list of them to fall
//! out of step with the tree, which is why (1) can be a real check rather than
//! a tautology: the folder proves the fixture exists, and `layout.json` is what
//! it must carry.
//!
//! Catching "the UI moved but nobody re-rendered" is the job of those layout
//! snapshots themselves, and it happens in `tests/ui_screenshots.rs`: each
//! fixture lays its window out on the CPU and compares. This target owns only
//! the structural half — a fixture whose snapshot file never got written would
//! otherwise have nothing to compare against and would pass by saying nothing.
//!
//! Every failure here has the same fix, so each message says it:
//!
//! ```sh
//! SECREQ_BLESS_SHOTS=1 cargo test --test ui_screenshots -- --nocapture --test-threads=1
//! ```

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const REGEN: &str =
    "SECREQ_BLESS_SHOTS=1 cargo test --test ui_screenshots -- --nocapture --test-threads=1";

/// Basename of the file every fixture folder carries — see
/// `tests/ui_layout/mod.rs`, which writes it.
const LAYOUT_FILE: &str = "layout.json";

/// Every fixture in the screenshot tree, by id.
///
/// A directory here *is* a fixture: the harness writes one folder per fixture
/// and nothing else creates one, so the tree is the register of what exists.
/// Loose files (this directory's README) are not fixtures and are skipped.
fn fixture_ids() -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    for entry in std::fs::read_dir(common::SCREENSHOT_DIR).expect("screenshot dir must exist") {
        let Ok(entry) = entry else { continue };
        if entry.path().is_dir() {
            found.insert(entry.file_name().to_string_lossy().into_owned());
        }
    }
    found
}

/// One fixture's committed record, or `None` if it has no `layout.json`.
///
/// Missing is a legitimate answer here rather than a panic: it is exactly what
/// [`every_fixture_has_a_layout_snapshot`] exists to report, and the other
/// checks have nothing to say about a fixture that has already failed that one.
fn layout_of(id: &str) -> Option<serde_json::Value> {
    let path = Path::new(common::SCREENSHOT_DIR).join(id).join(LAYOUT_FILE);
    let raw = std::fs::read_to_string(&path).ok()?;
    Some(
        serde_json::from_str(&raw)
            .unwrap_or_else(|e| panic!("{} is not valid JSON ({e})", path.display())),
    )
}

/// The `<os>-<appearance>` cells a fixture's `layout.json` names.
///
/// The snapshot is the promise: it holds one entry per cell the fixture laid
/// out, so it says which renders must exist without anyone maintaining a
/// second list of them.
fn promised_variants(layout: &serde_json::Value) -> BTreeSet<String> {
    layout
        .get("variants")
        .and_then(serde_json::Value::as_object)
        .map(|variants| variants.keys().cloned().collect())
        .unwrap_or_default()
}

/// What is actually inside a fixture's folder, filenames only.
fn files_in(id: &str) -> BTreeSet<String> {
    let dir = Path::new(common::SCREENSHOT_DIR).join(id);
    let Ok(entries) = std::fs::read_dir(dir) else {
        return BTreeSet::new();
    };
    entries
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect()
}

/// The number a fixture id claims: the token before its first `-`, when that
/// token starts with a digit.
///
/// Ids read `NN-what-it-shows`, and the `NN` is a single sequence shared by
/// every window kind. A deliberate second take on one shot carries a letter
/// suffix (`01b-empty-all-clear-viewer`) and claims a number of its own; a few
/// fixtures are named rather than numbered (`run-consent`) and claim none.
fn claimed_number(id: &str) -> Option<&str> {
    let head = id.split('-').next().unwrap_or(id);
    head.starts_with(|c: char| c.is_ascii_digit())
        .then_some(head)
}

/// Every published fixture carries the layout snapshot that guards it.
///
/// The staleness check itself lives with the fixtures in
/// `tests/ui_screenshots.rs`: each one lays its window out on the CPU and
/// compares the result against its own `layout.json`, which is what makes
/// "the UI moved but the PNGs didn't" a CI failure on a runner with no GPU.
/// This is the structural half — a fixture whose snapshot file never got
/// written would otherwise have nothing to compare against and would pass
/// by saying nothing.
#[test]
fn every_fixture_has_a_layout_snapshot() {
    let missing: Vec<_> = fixture_ids()
        .into_iter()
        .filter(|id| layout_of(id).is_none())
        .collect();

    assert!(
        missing.is_empty(),
        "\nThese fixtures have no {LAYOUT_FILE}, so nothing is guarding their \
         renders and the docs site has no caption for them:\n  {}\n\n\
         Regenerate them (and commit the result):\n  {REGEN}\n",
        missing.join("\n  "),
    );
}

#[test]
fn every_promised_render_exists() {
    let mut missing = Vec::new();
    for id in fixture_ids() {
        let Some(layout) = layout_of(&id) else {
            continue;
        };
        let present = files_in(&id);
        for variant in promised_variants(&layout) {
            let file = format!("{variant}.png");
            if !present.contains(&file) {
                missing.push(format!("{id}/{file}"));
            }
        }
    }

    assert!(
        missing.is_empty(),
        "\n{} render(s) named by a fixture's {LAYOUT_FILE} are not on disk:\n  {}\n\n\
         The docs site 404s on each. Regenerate:\n  {REGEN}\n",
        missing.len(),
        missing.join("\n  "),
    );
}

/// A fixture's folder holds its snapshot and its renders — nothing else.
///
/// Everything published about a screenshot is derived from this tree: the docs
/// site copies each `<id>/<os>-<appearance>.png` out and publishes it. So a
/// file the fixture no longer accounts for is not inert, it is a screenshot
/// still on secreq.dev showing a window that no longer exists — the usual way
/// being a rename, or a chrome matrix that narrowed and left its old cells
/// behind.
#[test]
fn no_orphaned_renders() {
    let mut orphans = Vec::new();
    for id in fixture_ids() {
        let Some(layout) = layout_of(&id) else {
            continue;
        };
        let expected: BTreeSet<String> = promised_variants(&layout)
            .iter()
            .map(|variant| format!("{variant}.png"))
            .chain([LAYOUT_FILE.to_owned()])
            .collect();
        for file in files_in(&id) {
            if !expected.contains(&file) {
                orphans.push(format!("{id}/{file}"));
            }
        }
    }

    assert!(
        orphans.is_empty(),
        "\n{} file(s) in {} are not accounted for by their fixture's {LAYOUT_FILE}:\n  {}\n\n\
         Nothing reads them and they cost git weight forever — delete them, then \
         regenerate:\n  {REGEN}\n",
        orphans.len(),
        common::SCREENSHOT_DIR,
        orphans.join("\n  "),
    );
}

/// `CLAUDE.md` makes the README row mandatory for a new fixture; without a
/// check it is the step that gets skipped, and a reviewer is left opening a
/// PNG to guess what it demonstrates.
///
/// Scoped to fixtures that carry a **caption**, which is the repo's own marker
/// for "this one is published documentation". A `Shot::exercise_only()` fixture
/// (the `99-resize-*` sweep, say) exists to drive a code path, ships without a
/// caption, and has nothing to tell a reader — demanding prose for it would
/// only invite filler.
#[test]
fn every_documented_fixture_has_a_readme_row() {
    let readme = std::fs::read_to_string(Path::new(common::SCREENSHOT_DIR).join("README.md"))
        .expect("dev-docs/ui-screenshots/README.md must exist");

    let undocumented: Vec<_> = fixture_ids()
        .into_iter()
        .filter(|id| layout_of(id).is_some_and(|layout| layout.get("caption").is_some()))
        .filter(|id| !readme.contains(&format!("| `{id}` |")))
        .collect();

    assert!(
        undocumented.is_empty(),
        "\n{} fixture(s) have no row in dev-docs/ui-screenshots/README.md:\n  {}\n\n\
         Add one per fixture — `| `<id>` | <test fn> | <what it exercises> |` — \
         so a reviewer can tell from the diff what the new PNG shows.\n",
        undocumented.len(),
        undocumented.join("\n  "),
    );
}

/// Two fixtures must not claim the same number.
///
/// Nothing else here notices: the ids differ, so the folders differ, and both
/// halves of a collision satisfy every other check. What breaks is the human
/// side — the number is how a fixture is referred to in review and in the
/// README table, and the tree is also what the next contributor scans to pick
/// a free one, so a duplicate quietly invites a third. It has happened, and it
/// was caught by eye rather than by anything running.
///
/// The sequence is **global across window kinds**: a consent-window fixture
/// and a session-card fixture draw from the same numbers, which is exactly why
/// picking one by looking at neighbouring fixtures goes wrong.
#[test]
fn no_two_fixtures_claim_the_same_number() {
    let mut by_number: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    let ids = fixture_ids();
    for id in &ids {
        if let Some(number) = claimed_number(id) {
            by_number.entry(number).or_default().push(id.clone());
        }
    }

    let collisions: Vec<String> = by_number
        .iter()
        .filter(|(_, ids)| ids.len() > 1)
        .map(|(number, ids)| format!("{number}: {}", ids.join(", ")))
        .collect();

    let highest = by_number
        .keys()
        .filter_map(|number| {
            number
                .chars()
                .take_while(char::is_ascii_digit)
                .collect::<String>()
                .parse::<u32>()
                .ok()
        })
        .max()
        .unwrap_or(0);

    assert!(
        collisions.is_empty(),
        "\n{} fixture number(s) are claimed twice:\n  {}\n\n\
         The number is how a fixture is cited, so a duplicate makes the README \
         table ambiguous and the next free number impossible to read off the \
         tree. Renumber the newer one to {:02} (the highest in use is {highest}, \
         and numbers are never reused): rename its `Shot::new(\"…\")` id in \
         tests/ui_screenshots.rs and its README row, delete the old folder, \
         then regenerate:\n  {REGEN}\n\n\
         A second take on one shot is the exception — give it a letter suffix \
         (`01b-…`), which reads as a variant rather than a new slot.\n",
        collisions.len(),
        collisions.join("\n  "),
        highest + 1,
    );
}
