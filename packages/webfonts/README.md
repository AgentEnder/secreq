# secreq-webfonts

Generates the two webfonts the docs site serves, from the fonts egui
embeds. Output goes to `docs-site/public/fonts/` and is **not committed**.

| generated file       | egui family                | drawn by                      |
| -------------------- | -------------------------- | ----------------------------- |
| `Ubuntu-Light.woff2` | `FontFamily::Proportional` | body text, labels, buttons    |
| `Hack-Regular.woff2` | `FontFamily::Monospace`    | secret names, commands, paths |

## Why the docs site needs the app's fonts at all

The site re-renders captured consent windows as DOM: the geometry comes
from `dev-docs/ui-screenshots/<id>/layout.json`, and every text run is
placed at the position egui measured. Those positions were measured with
_these_ faces. A different cut of the same typeface — Google Fonts'
Ubuntu, say — has different advance widths, so the text would drift out of
the boxes drawn around it. The site also serves under a CSP that blocks
external hosts, so a CDN was never an option either.

`daemon/ui.rs::install_style` starts from `FontDefinitions::default()` and
appends `Hack` to the proportional fallbacks, so every glyph in a consent
window comes from one of these two faces. Nothing loads a system font,
which is also what makes the CPU layout pass reproducible on any machine.

## Why nothing is committed

The output is a pure function of a pinned crate. A stored copy could only
ever fall _behind_ that crate — silently, on the next egui bump, with the
symptom being text drifting out of geometry on a published page.

So the docs-site build depends on this instead:

```jsonc
// docs-site/package.json
"build":   { "dependsOn": ["^build", "gen-webfonts"] },
"dev":     { "dependsOn": ["gen-webfonts"] },
"preview": { "dependsOn": ["gen-webfonts"] }
```

The target is cached on this crate's sources and `Cargo.lock`, so it runs
once and then costs nothing until egui moves. `docs-site/.gitignore`
ignores the whole output directory, the same way it already ignores
`/public/ui` and `/public/schemas`.

Run it by hand with:

```sh
cargo run -p secreq-webfonts
```

**Bumping egui is the case to watch.** New font bytes mean new metrics,
which move every text run the layout snapshots record — so the fixtures
need re-blessing in the same change
(`SECREQ_BLESS_SHOTS=layout cargo test --test ui_screenshots`).

## Why a standalone crate

An `examples/` binary in `secreq` would have been the obvious home, but an
example links its parent library: compressing two fonts would have pulled
egui, wgpu and the daemon through a compile. That cost lands on every docs
deploy, on a runner that otherwise has no reason to touch Rust. This crate
depends on `epaint_default_fonts` and `ttf2woff2` and nothing else.

## Licences

Redistribution requires shipping them, so they are written out beside the
fonts rather than committed separately — that way the licence on disk
always covers the exact bytes next to it:

- `UFL.txt` — Ubuntu Font Licence, covering `Ubuntu-Light.woff2`
- `Hack-Regular.txt` — the Hack licence, covering `Hack-Regular.woff2`

The emoji faces epaint also bundles (`NotoEmoji-Regular`,
`emoji-icon-font`) are deliberately skipped: the consent UI avoids emoji,
so no fixture can reference a glyph from them.

## Size

237 KB for the pair, down from 671 KB as TrueType. Brotli quality is
pinned at 11 — the maximum — because this runs once per build and is
cached, while every byte it saves is downloaded by every reader. Pinning
also keeps the output reproducible rather than dependent on the encoder's
default for a given release.

Subsetting would cut far more, and is deliberately not done: the ancestry
tree draws `└`, box-drawing characters are exactly what a careless subset
drops, and a missing glyph would not fail a test — it would ship a consent
window with a hole in it.
