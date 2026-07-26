//! Laying the consent windows out as **data**, so "the UI moved but nobody
//! re-rendered" is a CI failure on a machine with no GPU.
//!
//! The screenshot harness renders through wgpu, which needs a GPU and is not
//! byte-reproducible across drivers — so CI can neither re-render the PNGs nor
//! compare them. Layout is different: it is pure CPU work in `egui`, it happens
//! before a single triangle is submitted, and it is exactly the half of a
//! screenshot that a UI change moves. So every fixture also lays its window out
//! through a plain [`egui::Context`] and pins the resulting shape stream into
//! `dev-docs/ui-screenshots/<id>/layout.json`. Change a padding constant, a
//! colour token or a string and the committed snapshot stops matching; nothing
//! about the guard needs a display.
//!
//! That file is also where a fixture's two **authored** facts live — the window
//! kind it drives and the caption the docs site publishes under it — because a
//! fixture's folder should hold everything about that fixture and nothing
//! should have to be said about it twice. They sit outside `variants`, and no
//! digest covers them: a caption is prose, and re-wording prose must never
//! report that the UI moved.
//!
//! Three findings shape the capture, each of which cost a debugging session:
//!
//! - **Capture in points; never set a pixel scale during the layout pass.**
//!   The PNGs rasterise at 2x, but `pixels_per_point` is a *rasterisation*
//!   knob applied to a logical window: setting it to 2.0 here halves the
//!   logical window (a 500x510 prompt becomes 250x255), which doesn't merely shrink the
//!   capture — the evidence well narrows past its eliding width, the locator
//!   comes back as `op://Personal…`, and whole rows fall out. The snapshot
//!   would record truncated text and call it stable.
//! - **Text is captured per layout *section*, not per row.** A row spans
//!   several sections, and the section is where colour, font size and the
//!   mnemonic underline (the line under Approve's `A`) live. Flattening a row
//!   to one run silently drops all three. `Glyph::section_index` is private in
//!   egui 0.34, so [`text_rows`] recovers sections by walking a byte counter
//!   over the job's text, stepping past the newline each row break consumes.
//! - **Two passes before capturing.** egui settles some layout on the frame
//!   after first sight (galley sizes feeding container sizes), and
//!   `egui_kittest`'s `run()` does the same. A one-shot capture records the
//!   unsettled frame.
//!
//! The whole prompt window is ~37 shapes of four kinds — `Rect`, `Circle`,
//! `LineSegment`, `Text`. No meshes, textures, images, paths or béziers, which
//! is why a faithful record is small enough to read in a diff. `Shape::Vec`
//! nests, so the walk is recursive and carries each `ClippedShape`'s clip rect
//! down to the leaves.
//!
//! Lives here rather than in `tests/common/` because that module is linked
//! into all ten integration test binaries, and this one drags in egui plus the
//! entire daemon UI for the benefit of exactly one of them.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use egui::{Color32, Pos2, Rect, Shape, Stroke, Vec2};
use serde_json::{json, Map, Value};

/// Basename of a fixture's record, inside that fixture's own folder.
pub const LAYOUT_FILE: &str = "layout.json";

/// One window laid out once: its logical size and the flattened shape stream.
pub struct Capture {
    size: Vec2,
    shapes: Vec<Value>,
}

impl Capture {
    /// The snapshot record for one variant: the size the window was laid out
    /// at, a digest of the shapes, then the shapes themselves.
    ///
    /// The digest is redundant with the list — it exists so a reader (and the
    /// failure message) has one short thing to compare instead of scrolling a
    /// thousand-line array to find out whether anything moved at all.
    fn to_json(&self) -> Value {
        let shapes = Value::Array(self.shapes.clone());
        let mut entry = Map::new();
        entry.insert("size".into(), json!([num(self.size.x), num(self.size.y)]));
        entry.insert("digest".into(), digest(&shapes).into());
        entry.insert("shapes".into(), shapes);
        Value::Object(entry)
    }
}

/// Lay `draw` out at `size` on the CPU and flatten what it painted.
///
/// `draw` is the *same* closure body the wgpu harness hands
/// `egui_kittest`, which is the point: a capture that ran different UI code
/// than the render would guard nothing. `Context::run_ui` hands back the root
/// `Ui` straight out of the viewport — the same `Ui` eframe gives `App::ui` in
/// production, and the reason the fixtures re-widen `max_rect` under kittest,
/// which interposes a `CentralPanel` of its own.
pub fn capture<S>(
    size: Vec2,
    mut state: S,
    mut draw: impl FnMut(&mut egui::Ui, &mut S),
) -> Capture {
    let ctx = egui::Context::default();
    let input = egui::RawInput {
        screen_rect: Some(Rect::from_min_size(Pos2::ZERO, size)),
        ..Default::default()
    };

    // Deliberately the *same* input twice: `RawInput::time` stays `None`, so
    // egui's time-based animations (hover fades, scroll-bar reveal) never
    // advance and the second pass differs from the first only by what settling
    // resolved. An advancing clock would make the capture depend on how long
    // the pass took to run.
    let mut output = None;
    for _ in 0..2 {
        output = Some(ctx.run_ui(input.clone(), |ui| draw(ui, &mut state)));
    }
    let output = output.expect("two layout passes ran");

    let mut shapes = Vec::new();
    for clipped in &output.shapes {
        walk(&clipped.shape, clipped.clip_rect, &mut shapes);
    }
    Capture { size, shapes }
}

/// One fixture's whole on-disk record: what it is, what it says, and how it
/// laid out across the chrome matrix.
///
/// There is no second file describing a screenshot. The window kind and the
/// caption are authored on the fixture in Rust and land here; everything else
/// a consumer needs — which renders exist, how big they are — is derivable
/// from the folder and the PNGs themselves, and derived facts are not worth
/// storing twice.
pub struct Fixture {
    id: String,
    /// `prompt` | `manager` | `badge` — which secreq window this fixture
    /// drives, so a consumer can label a render without pattern-matching on
    /// its filename.
    window: &'static str,
    /// The figcaption secreq.dev publishes under this fixture's renders, or
    /// `None` for a fixture that exercises the UI rather than documenting it.
    caption: Option<&'static str>,
    variants: BTreeMap<String, Value>,
}

impl Fixture {
    pub fn new(id: &str, window: &'static str, caption: Option<&'static str>) -> Self {
        Self {
            id: id.to_owned(),
            window,
            caption,
            variants: BTreeMap::new(),
        }
    }

    pub fn record(&mut self, variant: &str, capture: &Capture) {
        self.variants.insert(variant.to_owned(), capture.to_json());
    }

    /// Rewrite this fixture's `layout.json` from what was just captured.
    ///
    /// Whole-file, and it can be: the file belongs to exactly one fixture, and
    /// a fixture always blesses its whole matrix at once. A stale variant left
    /// behind by a narrowing matrix would otherwise be guarded forever against
    /// a cell nothing renders.
    pub fn write(&self, dir: &Path) {
        let path = self.path(dir);
        std::fs::create_dir_all(path.parent().expect("layout path has a parent"))
            .expect("mkdir fixture dir");

        // Authored fields first, geometry last — written in this order rather
        // than through a `serde_json::Map`, whose sorted keys would bury
        // `window` under a hundred kilobytes of shapes. The two lines a human
        // reads (or edits, after re-wording a caption in the harness) are the
        // two at the top of the file.
        let mut fields: Vec<(&str, Value)> = vec![("window", self.window.into())];
        if let Some(caption) = self.caption {
            fields.push(("caption", caption.into()));
        }
        // `serde_json::Map` is a `BTreeMap`, so variant keys serialise sorted
        // and the file diffs cleanly between runs.
        fields.push((
            "variants",
            Value::Object(self.variants.clone().into_iter().collect()),
        ));

        let mut body = String::from("{\n");
        for (i, (key, value)) in fields.iter().enumerate() {
            if i > 0 {
                body.push_str(",\n");
            }
            body.push_str("  ");
            body.push_str(&serde_json::to_string(key).expect("serialize key"));
            body.push_str(": ");
            write_pretty(value, 1, &mut body);
        }
        body.push_str("\n}");

        std::fs::write(&path, format!("{body}\n")).expect("write layout.json");
        eprintln!(
            "wrote {} ({} variants)",
            path.display(),
            self.variants.len()
        );
    }

    /// Compare what was just laid out against the committed snapshot, and
    /// panic with something a reader can act on if they disagree.
    ///
    /// Only `variants` is compared. The caption is deliberately outside the
    /// comparison: it is documentation prose, and a check that failed on a
    /// re-worded sentence would be telling the author the UI moved when
    /// nothing about it did.
    pub fn check(&self, dir: &Path, regen: &str) {
        let path = self.path(dir);
        let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!(
                "\n{} has no layout snapshot at {} ({e}).\n\n\
                 Every fixture carries one — it is what makes a UI change that \
                 never got a regen a CI failure.\n\nBless it:\n  {regen}\n",
                self.id,
                path.display(),
            )
        });
        let doc: Value = serde_json::from_str(&raw)
            .unwrap_or_else(|e| panic!("{} is not valid JSON ({e})", path.display()));
        let committed = doc
            .get("variants")
            .and_then(Value::as_object)
            .unwrap_or_else(|| {
                panic!(
                    "\n{} holds no `variants` object, so nothing is guarding {}'s \
                     renders.\n\nBless it:\n  {regen}\n",
                    path.display(),
                    self.id,
                )
            });

        let mut failures = Vec::new();
        for (variant, fresh) in &self.variants {
            match committed.get(variant) {
                None => failures.push(format!("  {variant}: not in the committed snapshot")),
                Some(old) if old == fresh => {}
                Some(old) => failures.push(format!("  {variant}: {}", describe_drift(old, fresh))),
            }
        }
        for variant in committed.keys() {
            if !self.variants.contains_key(variant) {
                failures.push(format!(
                    "  {variant}: committed, but this run laid out no such variant"
                ));
            }
        }

        assert!(
            failures.is_empty(),
            "\nThe UI moved but `{}`'s screenshots did not:\n{}\n\n\
             The committed PNGs now show a window that no longer exists. Re-render \
             them, eyeball the result, and commit both the PNGs and the refreshed \
             {}:\n  {regen}\n",
            self.id,
            failures.join("\n"),
            LAYOUT_FILE,
        );
    }

    fn path(&self, dir: &Path) -> PathBuf {
        dir.join(&self.id).join(LAYOUT_FILE)
    }
}

/// Say *what* moved, in one line, for a variant that drifted.
///
/// A whole-array diff of a thousand shapes is unreadable in a test failure, so
/// this reports the shape count if that changed and otherwise the first index
/// that differs — enough to tell "the window got a new row" from "a colour
/// token changed" without opening anything.
fn describe_drift(old: &Value, fresh: &Value) -> String {
    let (Some(Value::Array(old_shapes)), Some(Value::Array(new_shapes))) =
        (old.get("shapes"), fresh.get("shapes"))
    else {
        return "committed entry is malformed".to_owned();
    };
    if old.get("size") != fresh.get("size") {
        return format!(
            "window size changed, {} → {}",
            render(old.get("size")),
            render(fresh.get("size")),
        );
    }
    if old_shapes.len() != new_shapes.len() {
        return format!("{} shapes, was {}", new_shapes.len(), old_shapes.len());
    }
    match old_shapes.iter().zip(new_shapes).position(|(a, b)| a != b) {
        Some(i) => format!(
            "{} shapes, first change at #{i}:\n      was {}\n      now {}",
            new_shapes.len(),
            render(old_shapes.get(i)),
            render(new_shapes.get(i)),
        ),
        None => "digest changed but no shape did".to_owned(),
    }
}

/// One shape as a single line, clipped so a wide text run can't bury the
/// message it is trying to deliver.
fn render(value: Option<&Value>) -> String {
    let mut text = value.map(ToString::to_string).unwrap_or_default();
    if text.chars().count() > 220 {
        text = text.chars().take(217).collect::<String>() + "…";
    }
    text
}

/// Pretty-print, except that any value holding no nested object stays on one
/// line.
///
/// `serde_json::to_string_pretty` gives every element of every array a line of
/// its own, which spreads a single rect — four clip coordinates, four of its
/// own, a fill, a stroke, four corner radii — over thirty lines, and this
/// corpus over six megabytes. Collapsing leaf records instead makes the file
/// both smaller and *legible as a diff*: one line per painted shape and one per
/// text run, so a widget that moved shows up as one changed line rather than a
/// thirty-line hunk that has to be read to find the four numbers in it.
fn write_pretty(value: &Value, depth: usize, out: &mut String) {
    if is_leaf_record(value) {
        out.push_str(&serde_json::to_string(value).expect("serialize leaf"));
        return;
    }
    let pad = "  ".repeat(depth + 1);
    let close = "  ".repeat(depth);
    match value {
        Value::Object(map) => {
            out.push_str("{\n");
            for (i, (key, child)) in map.iter().enumerate() {
                if i > 0 {
                    out.push_str(",\n");
                }
                out.push_str(&pad);
                out.push_str(&serde_json::to_string(key).expect("serialize key"));
                out.push_str(": ");
                write_pretty(child, depth + 1, out);
            }
            out.push('\n');
            out.push_str(&close);
            out.push('}');
        }
        Value::Array(items) => {
            out.push_str("[\n");
            for (i, child) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(",\n");
                }
                out.push_str(&pad);
                write_pretty(child, depth + 1, out);
            }
            out.push('\n');
            out.push_str(&close);
            out.push(']');
        }
        // Unreachable: a scalar is always a leaf record and left above.
        scalar => out.push_str(&serde_json::to_string(scalar).expect("serialize scalar")),
    }
}

/// Whether `value` holds no object *below* it — a painted shape, a text run, a
/// coordinate pair. These go on one line; anything that nests a record inside
/// another record (a text shape's rows, the shape stream itself) expands.
fn is_leaf_record(value: &Value) -> bool {
    match value {
        Value::Object(map) => map.values().all(holds_no_object),
        Value::Array(items) => items.iter().all(holds_no_object),
        _ => true,
    }
}

fn holds_no_object(value: &Value) -> bool {
    match value {
        Value::Object(_) => false,
        Value::Array(items) => items.iter().all(holds_no_object),
        _ => true,
    }
}

/// blake3 of the canonical (compact, key-sorted) shape stream.
fn digest(shapes: &Value) -> String {
    let canonical = serde_json::to_string(shapes).expect("serialize shapes");
    blake3::hash(canonical.as_bytes()).to_hex().to_string()
}

// ── Shape flattening ──────────────────────────────────────────────────────

/// Flatten the shape tree, recording each leaf with the clip rect it
/// inherited. `Shape::Vec` nests, and the clip rect is the thing a consumer
/// would turn into an `overflow: hidden` wrapper — it is also how a fixture
/// notices that a scroll viewport changed size.
fn walk(shape: &Shape, clip: Rect, out: &mut Vec<Value>) {
    match shape {
        Shape::Noop => {}
        Shape::Vec(shapes) => {
            for shape in shapes {
                walk(shape, clip, out);
            }
        }
        Shape::Rect(r) => out.push(json!({
            "k": "rect",
            "clip": rect(clip),
            "rect": rect(r.rect),
            "fill": rgba(r.fill),
            "stroke": stroke(r.stroke),
            // Where the stroke sits relative to the rect, and how far a shadow
            // bleeds past it: both are visible geometry that a fill/stroke
            // pair alone would not record.
            "stroke_kind": format!("{:?}", r.stroke_kind),
            "blur": num(r.blur_width),
            "radius": json!([
                r.corner_radius.nw,
                r.corner_radius.ne,
                r.corner_radius.se,
                r.corner_radius.sw,
            ]),
        })),
        Shape::Circle(c) => out.push(json!({
            "k": "circle",
            "clip": rect(clip),
            "center": pos(c.center),
            "radius": num(c.radius),
            "fill": rgba(c.fill),
            "stroke": stroke(c.stroke),
        })),
        Shape::LineSegment { points, stroke: s } => out.push(json!({
            "k": "line",
            "clip": rect(clip),
            "a": pos(points[0]),
            "b": pos(points[1]),
            "stroke": stroke(*s),
        })),
        Shape::Text(t) => out.push(json!({
            "k": "text",
            "clip": rect(clip),
            "pos": pos(t.pos),
            "underline": stroke(t.underline),
            "rows": text_rows(t),
        })),
        // Nothing in these windows paints one of these today. Recording the
        // kind rather than panicking keeps the first fixture that introduces
        // (say) a mesh from failing as "unsupported" when what it actually
        // needs is a reviewer deciding what about that mesh is worth pinning.
        other => out.push(json!({
            "k": match other {
                Shape::Path(_) => "path",
                Shape::Mesh(_) => "mesh",
                Shape::Ellipse(_) => "ellipse",
                Shape::QuadraticBezier(_) => "quadratic",
                Shape::CubicBezier(_) => "cubic",
                Shape::Callback(_) => "callback",
                _ => "other",
            },
            "clip": rect(clip),
        })),
    }
}

/// A laid-out galley as rows of per-section runs.
///
/// Sections are recovered by byte offset: `Glyph::section_index` is private in
/// egui 0.34, so the walk carries its own counter over the job's text and steps
/// past the newline a row break consumes.
fn text_rows(t: &egui::epaint::TextShape) -> Value {
    let job = &t.galley.job;
    let mut byte = 0usize;
    let mut rows = Vec::new();

    for row in t.galley.rows.iter() {
        let mut runs: Vec<Value> = Vec::new();
        // (section, text, x0, x1, baseline within the row)
        let mut cur: Option<(usize, String, f32, f32, f32)> = None;
        for glyph in row.glyphs.iter() {
            let section = job
                .sections
                .iter()
                .position(|sec| sec.byte_range.contains(&byte))
                .unwrap_or(0);
            byte += glyph.chr.len_utf8();
            let x1 = glyph.pos.x + glyph.advance_width;
            match &mut cur {
                Some((sec, text, _, end, _)) if *sec == section => {
                    text.push(glyph.chr);
                    *end = x1;
                }
                _ => {
                    if let Some((sec, text, x0, x1, base)) = cur.take() {
                        runs.push(run(t, sec, &text, x0, x1, base));
                    }
                    // `Glyph::pos` is the *baseline*, relative to the row — the
                    // one coordinate that lets a consumer stand the text up the
                    // way egui did instead of guessing from a line box.
                    cur = Some((section, glyph.chr.to_string(), glyph.pos.x, x1, glyph.pos.y));
                }
            }
        }
        if let Some((sec, text, x0, x1, base)) = cur.take() {
            runs.push(run(t, sec, &text, x0, x1, base));
        }
        if job.text.as_bytes().get(byte) == Some(&b'\n') {
            byte += 1;
        }
        rows.push(json!({ "rect": rect(row.rect()), "runs": runs }));
    }

    Value::Array(rows)
}

/// One run of glyphs sharing a layout section, with that section's format.
///
/// Colour is *resolved*, not copied: a galley records `Color32::PLACEHOLDER`
/// wherever the widget layer meant "whatever the style says", and the shape's
/// `fallback_color` supplies the real one at paint time. Recording the
/// placeholder would make every themed label the same colour in the snapshot,
/// so a theme-token regression would sail straight through the guard.
///
/// `underline` is a stroke rather than a flag: egui carries width and colour,
/// and the buttons' mnemonics are the only thing using it here.
fn run(
    t: &egui::epaint::TextShape,
    section: usize,
    text: &str,
    x0: f32,
    x1: f32,
    baseline: f32,
) -> Value {
    let Some(format) = t.galley.job.sections.get(section).map(|s| &s.format) else {
        return json!({ "text": text, "x": [num(x0), num(x1)], "baseline": num(baseline) });
    };
    let color = t
        .override_text_color
        .unwrap_or_else(|| resolve(format.color, t.fallback_color));
    json!({
        "text": text,
        "x": [num(x0), num(x1)],
        "baseline": num(baseline),
        "size": num(format.font_id.size),
        "family": match &format.font_id.family {
            egui::FontFamily::Monospace => "monospace".to_owned(),
            egui::FontFamily::Proportional => "proportional".to_owned(),
            egui::FontFamily::Name(name) => name.to_string(),
        },
        "color": rgba(color),
        "underline": stroke(Stroke::new(
            format.underline.width,
            resolve(format.underline.color, t.fallback_color),
        )),
    })
}

/// Substitute the shape's fallback for the galley's "ask the style" sentinel.
fn resolve(color: Color32, fallback: Color32) -> Color32 {
    if color == Color32::PLACEHOLDER {
        fallback
    } else {
        color
    }
}

// ── Scalar encodings ──────────────────────────────────────────────────────

/// Floats land in the file rounded to two decimals.
///
/// Layout arithmetic is float arithmetic, and the sub-hundredth digits are
/// where an irrelevant reassociation shows up — pinning them would make the
/// snapshot churn on changes that move nothing a reader could see. Two
/// decimals is well under a device pixel at 2x and still catches any real
/// move.
fn num(v: f32) -> Value {
    // egui uses infinite rects for "unclipped", which JSON has no number for.
    if !v.is_finite() {
        return Value::String(if v.is_nan() {
            "nan".to_owned()
        } else if v > 0.0 {
            "inf".to_owned()
        } else {
            "-inf".to_owned()
        });
    }
    // `+ 0.0` folds -0.0 to 0.0: the two are equal as floats but serialise
    // differently, so a sign that no pixel can show would otherwise diff.
    let rounded = (f64::from(v) * 100.0).round() / 100.0 + 0.0;
    Value::Number(serde_json::Number::from_f64(rounded).expect("finite"))
}

fn pos(p: Pos2) -> Value {
    json!([num(p.x), num(p.y)])
}

fn rect(r: Rect) -> Value {
    json!([num(r.min.x), num(r.min.y), num(r.max.x), num(r.max.y)])
}

fn stroke(s: Stroke) -> Value {
    json!([num(s.width), rgba(s.color)])
}

fn rgba(c: Color32) -> String {
    format!("#{:02x}{:02x}{:02x}{:02x}", c.r(), c.g(), c.b(), c.a())
}
