//! Terminal rendering for the in-person pairing QR.

use anyhow::{bail, Context, Result};
use qrcode::render::unicode::Dense1x2;
use qrcode::types::EcLevel;
use qrcode::QrCode;

/// Width used by the CLI transcript harness's pseudo-terminal.
pub const TRANSCRIPT_PTY_WIDTH: usize = 80;

const DARK_ON_LIGHT: &str = "\x1b[30;107m";
const RESET_COLORS: &str = "\x1b[0m";

/// Render QR data as black-on-white Unicode half blocks.
///
/// The explicit foreground and background are load-bearing: inheriting the
/// terminal theme would invert the code on a dark terminal. Spaces represent
/// light modules on the forced white background, while `▀`, `▄`, and `█` paint
/// dark modules with the forced black foreground.
pub fn render(data: &str) -> Result<String> {
    // Low correction keeps the in-transcript QR compact. Terminal cells are a
    // crisp source rather than a damaged printed label, and fitting the pty is
    // an invariant checked below rather than an assumption left to the CLI.
    let code = QrCode::with_error_correction_level(data.as_bytes(), EcLevel::L)
        .context("encode pairing QR")?;
    let dense = code.render::<Dense1x2>().module_dimensions(1, 1).build();
    let mut lines = dense.lines();
    let Some(first) = lines.next() else {
        bail!("pairing QR renderer produced no rows");
    };
    let width = first.chars().count();
    if width > TRANSCRIPT_PTY_WIDTH {
        bail!(
            "pairing QR is {width} columns wide, exceeding the {TRANSCRIPT_PTY_WIDTH}-column transcript pty"
        );
    }

    if !lines.all(|line| line.chars().count() == width) {
        bail!("pairing QR renderer produced uneven rows");
    }

    let mut rendered = String::with_capacity(dense.len() + dense.lines().count() * 13);
    for line in dense.lines() {
        rendered.push_str(DARK_ON_LIGHT);
        rendered.push_str(line);
        rendered.push_str(RESET_COLORS);
        rendered.push('\n');
    }
    Ok(rendered)
}

#[cfg(test)]
mod tests {
    use qrcode::render::unicode::Dense1x2;

    use super::*;

    #[test]
    fn pairing_qr_is_rectangular_non_empty_and_fits_the_transcript_pty() {
        let url = format!(
            "http://192.168.100.200:49152/pair#{}",
            "0123456789abcdef".repeat(4)
        );
        let rendered = render(&url).expect("render pairing QR");
        let plain = console::strip_ansi_codes(&rendered);
        let lines: Vec<_> = plain.lines().collect();

        assert!(!lines.is_empty());
        assert!(lines
            .iter()
            .any(|line| line.chars().any(|cell| matches!(cell, '▀' | '▄' | '█'))));
        let width = lines[0].chars().count();
        assert!(width > 0);
        assert!(
            lines.iter().all(|line| line.chars().count() == width),
            "every QR line must have the same display width"
        );
        assert!(
            width <= TRANSCRIPT_PTY_WIDTH,
            "QR is {width} columns wide, but transcripts are {TRANSCRIPT_PTY_WIDTH}"
        );
        assert!(
            plain
                .chars()
                .all(|cell| matches!(cell, ' ' | '▀' | '▄' | '█' | '\n')),
            "QR output must contain terminal block characters only"
        );

        let expected = QrCode::with_error_correction_level(url.as_bytes(), EcLevel::L)
            .unwrap()
            .render::<Dense1x2>()
            .module_dimensions(1, 1)
            .build();
        assert_eq!(plain.trim_end_matches('\n'), expected);
        assert!(rendered
            .lines()
            .all(|line| { line.starts_with("\u{1b}[30;107m") && line.ends_with("\u{1b}[0m") }));
    }
}
