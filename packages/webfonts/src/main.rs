//! Generate the docs site's webfonts from the fonts egui embeds.
//!
//! The site re-renders captured consent windows as DOM
//! (`dev-docs/ui-screenshots/<id>/layout.json` holds the geometry), placing
//! every text run at the position egui measured. Those positions were measured
//! with *these* faces, so the browser has to lay the same glyphs out with the
//! same metrics or the text drifts out of the boxes drawn around it. A
//! different cut of the same typeface — Google Fonts' Ubuntu, say — has
//! different advance widths and does not qualify.
//!
//! ## Why nothing here is committed
//!
//! The output is a pure function of a pinned crate, so committing it would be
//! committing a build artifact — and one that can silently fall behind an egui
//! bump. The docs-site build depends on this target instead, which makes the
//! fonts unable to disagree with the app by construction: there is no stored
//! copy to drift.
//!
//! The licences are written out for the same reason. Redistribution requires
//! shipping them, and generating them beside the fonts is what guarantees the
//! licence on disk covers the exact bytes next to it.
//!
//! Emoji faces are deliberately skipped. epaint bundles two, but the consent
//! UI avoids emoji entirely, so no fixture can reference a glyph from them and
//! shipping ~700 KB to prove it would be silly.
//!
//! Run: `cargo run -p secreq-webfonts` (or let `nx build docs-site` do it).

use std::path::PathBuf;

use ttf2woff2::BrotliQuality;

/// Where the docs site serves fonts from, relative to the workspace root.
const OUT_DIR: &str = "docs-site/public/fonts";

/// Brotli effort, pinned rather than left to the crate's default.
///
/// 11 is the maximum. This runs once per build and is cached by nx, while
/// every byte it saves is downloaded by every reader — an easy trade. Pinning
/// it also keeps the output reproducible, so a cached run and a fresh one
/// produce the same file.
const BROTLI_QUALITY: u8 = 11;

/// The faces `daemon::ui::install_style` actually selects: the default
/// proportional family, and Hack for monospace. Each ships with the licence
/// its redistribution requires.
const FACES: &[Face] = &[
    Face {
        name: "Ubuntu-Light",
        ttf: epaint_default_fonts::UBUNTU_LIGHT,
        licence_file: "UFL.txt",
        licence: include_str!("../licences/UFL.txt"),
    },
    Face {
        name: "Hack-Regular",
        ttf: epaint_default_fonts::HACK_REGULAR,
        licence_file: "Hack-Regular.txt",
        licence: include_str!("../licences/Hack-Regular.txt"),
    },
];

struct Face {
    name: &'static str,
    ttf: &'static [u8],
    licence_file: &'static str,
    licence: &'static str,
}

fn main() {
    // Run from the workspace root regardless of where cargo was invoked, so
    // the nx target and a hand-run `cargo run -p secreq-webfonts` land in the
    // same place.
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("crate sits two levels under the workspace root")
        .to_path_buf();
    let out_dir = root.join(OUT_DIR);
    std::fs::create_dir_all(&out_dir).expect("create font output dir");

    for face in FACES {
        let woff2 = ttf2woff2::encode(face.ttf, BrotliQuality::from(BROTLI_QUALITY))
            .unwrap_or_else(|e| panic!("compress {} to woff2: {e}", face.name));

        let font_path = out_dir.join(format!("{}.woff2", face.name));
        std::fs::write(&font_path, &woff2)
            .unwrap_or_else(|e| panic!("write {}: {e}", font_path.display()));

        let licence_path = out_dir.join(face.licence_file);
        std::fs::write(&licence_path, face.licence)
            .unwrap_or_else(|e| panic!("write {}: {e}", licence_path.display()));

        println!(
            "{:<14} {:>7} B ttf -> {:>7} B woff2  ({:.0}% smaller)",
            face.name,
            face.ttf.len(),
            woff2.len(),
            100.0 - (woff2.len() as f64 / face.ttf.len() as f64) * 100.0,
        );
    }
    println!("wrote {}", out_dir.display());
}
