//! Terminal rendering for the in-person pairing QR.

use anyhow::{bail, Context, Result};
use qrcode::types::{Color, EcLevel};
use qrcode::QrCode;

/// Width used by the CLI transcript harness's pseudo-terminal.
pub const TRANSCRIPT_PTY_WIDTH: usize = 80;

const QUIET_ZONE: usize = 4;

/// Render QR data as text using one Unicode half-block cell per two modules.
pub fn render(data: &str) -> Result<String> {
    // Low correction keeps the in-transcript QR compact. Terminal cells are a
    // crisp source rather than a damaged printed label, and fitting the pty is
    // an invariant checked below rather than an assumption left to the CLI.
    let code = QrCode::with_error_correction_level(data.as_bytes(), EcLevel::L)
        .context("encode pairing QR")?;
    let code_width = code.width();
    let width = code_width + QUIET_ZONE * 2;
    if width > TRANSCRIPT_PTY_WIDTH {
        bail!(
            "pairing QR is {width} columns wide, exceeding the {TRANSCRIPT_PTY_WIDTH}-column transcript pty"
        );
    }

    let colors = code.into_colors();
    let height = width.next_multiple_of(2);
    let mut rendered = String::with_capacity((width + 1) * (height / 2));
    for top_y in (0..height).step_by(2) {
        for x in 0..width {
            let top = is_dark(&colors, code_width, x, top_y);
            let bottom = is_dark(&colors, code_width, x, top_y + 1);
            rendered.push(match (top, bottom) {
                (false, false) => ' ',
                (true, false) => '▀',
                (false, true) => '▄',
                (true, true) => '█',
            });
        }
        rendered.push('\n');
    }
    Ok(rendered)
}

fn is_dark(colors: &[Color], code_width: usize, x: usize, y: usize) -> bool {
    let Some(module_x) = x.checked_sub(QUIET_ZONE) else {
        return false;
    };
    let Some(module_y) = y.checked_sub(QUIET_ZONE) else {
        return false;
    };
    if module_x >= code_width || module_y >= code_width {
        return false;
    }
    colors
        .get(module_y * code_width + module_x)
        .is_some_and(|color| *color == Color::Dark)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairing_qr_is_rectangular_non_empty_and_fits_the_transcript_pty() {
        let url = format!(
            "http://192.168.100.200:49152/pair#{}",
            "0123456789abcdef".repeat(4)
        );
        let rendered = render(&url).expect("render pairing QR");
        let lines: Vec<_> = rendered.lines().collect();

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
            rendered
                .chars()
                .all(|cell| matches!(cell, ' ' | '▀' | '▄' | '█' | '\n')),
            "QR output must contain terminal block characters only"
        );
    }
}
