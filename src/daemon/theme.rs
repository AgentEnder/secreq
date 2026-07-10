//! Semantic design tokens for the consent surfaces.
//!
//! The visual identity is "Native Sentinel": secreq's windows read as
//! OS security surfaces, not as a web app. Each supported OS gets its
//! own token set (palette, radii, sizes) in both light and dark, ported
//! from the approved design drafts at
//! `dev-docs/design-drafts/consent-ui/shared/styles/{macos,windows,gnome}.css`.
//!
//! Appearance is not a user setting: the child windows set
//! [`egui::ThemePreference::System`] and [`Theme::of`] re-resolves from
//! `ctx.theme()` every frame, so an OS-level light/dark flip takes
//! effect immediately. The OS flavor defaults to the compile target but
//! is overridable through egui context data so the screenshot harness
//! can render the Windows and GNOME treatments on any host.

use egui::Color32;

/// Which OS idiom to render. Structural, not just palette: e.g. the
/// prompt's decision row is a right-aligned pair on macOS, an
/// equal-width footer strip on Windows, and a full-width response row
/// on GNOME.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsFlavor {
    MacOs,
    Windows,
    Gnome,
}

impl OsFlavor {
    /// The flavor for the OS this binary was built for.
    pub fn current() -> Self {
        if cfg!(target_os = "macos") {
            Self::MacOs
        } else if cfg!(target_os = "windows") {
            Self::Windows
        } else {
            Self::Gnome
        }
    }

    /// Context-data key for the fixture override.
    fn ctx_key() -> egui::Id {
        egui::Id::new("secreq.os_flavor")
    }

    /// Override the flavor for this egui context. Used by the
    /// screenshot harness to render non-host OS treatments; production
    /// code never calls this.
    pub fn install_override(ctx: &egui::Context, flavor: OsFlavor) {
        ctx.data_mut(|d| d.insert_temp(Self::ctx_key(), flavor));
    }

    fn resolve(ctx: &egui::Context) -> Self {
        ctx.data(|d| d.get_temp::<OsFlavor>(Self::ctx_key()))
            .unwrap_or_else(Self::current)
    }
}

/// Resolved semantic tokens for one (flavor, appearance) pair. Cheap to
/// build; renderers call [`Theme::of`] wherever they need it instead of
/// threading it through every signature.
#[derive(Debug, Clone, Copy)]
pub struct Theme {
    pub flavor: OsFlavor,
    pub dark: bool,

    // Surfaces
    /// Window fill.
    pub panel: Color32,
    /// Inset evidence well / grouped list fill.
    pub well: Color32,
    /// Border around wells and grouped lists.
    pub well_border: Color32,
    /// Hover / selected-row surface, one step off `panel`.
    pub raised: Color32,
    /// Header bar fill (GNOME headerbar; titlebar strips elsewhere).
    pub headerbar: Color32,
    /// Footer strip fill (Windows ContentDialog); equals `panel` elsewhere.
    pub footer: Color32,
    /// 1px hairline between structural regions.
    pub rule: Color32,
    /// Alternating table-row tint (macOS tables; transparent elsewhere).
    pub stripe: Color32,

    // Text
    pub fg: Color32,
    pub dim: Color32,
    pub faint: Color32,

    // Accent and status. Status colors are for indicator text — the
    // design never fills a surface green or red.
    pub accent: Color32,
    pub accent_fg: Color32,
    /// Accent used as text (links, suggested actions); differs from
    /// `accent` where a fill color is too dark/light to read as text.
    pub accent_text: Color32,
    pub ok: Color32,
    pub danger: Color32,

    // Buttons
    pub btn: Color32,
    pub btn_fg: Color32,
    pub btn_border: Color32,

    // Metrics
    pub well_radius: u8,
    pub btn_radius: u8,
    pub body_size: f32,
}

impl Theme {
    /// Resolve the theme for this frame: flavor from the context
    /// override (or compile target), appearance from egui's resolved
    /// theme (which follows the OS under `ThemePreference::System`).
    pub fn of(ctx: &egui::Context) -> Self {
        let dark = ctx.theme() == egui::Theme::Dark;
        Self::resolve(OsFlavor::resolve(ctx), dark)
    }

    pub fn resolve(flavor: OsFlavor, dark: bool) -> Self {
        match (flavor, dark) {
            (OsFlavor::MacOs, true) => MACOS_DARK,
            (OsFlavor::MacOs, false) => MACOS_LIGHT,
            (OsFlavor::Windows, true) => WINDOWS_DARK,
            (OsFlavor::Windows, false) => WINDOWS_LIGHT,
            (OsFlavor::Gnome, true) => GNOME_DARK,
            (OsFlavor::Gnome, false) => GNOME_LIGHT,
        }
    }
}

const fn rgb(r: u8, g: u8, b: u8) -> Color32 {
    Color32::from_rgb(r, g, b)
}

const MACOS_DARK: Theme = Theme {
    flavor: OsFlavor::MacOs,
    dark: true,
    panel: rgb(0x2b, 0x2b, 0x2d),
    well: rgb(0x23, 0x23, 0x25),
    well_border: rgb(0x3a, 0x3a, 0x3e),
    raised: rgb(0x33, 0x33, 0x36),
    headerbar: rgb(0x2b, 0x2b, 0x2d),
    footer: rgb(0x2b, 0x2b, 0x2d),
    rule: rgb(0x3c, 0x3c, 0x40),
    stripe: Color32::from_rgba_premultiplied(8, 8, 8, 8),
    fg: rgb(0xe9, 0xe9, 0xeb),
    dim: rgb(0x98, 0x98, 0x9d),
    faint: rgb(0x6a, 0x6a, 0x70),
    accent: rgb(0x0a, 0x84, 0xff),
    accent_fg: Color32::WHITE,
    accent_text: rgb(0x41, 0x9c, 0xff),
    ok: rgb(0x7f, 0xbf, 0x6a),
    danger: rgb(0xe0, 0x70, 0x5f),
    btn: rgb(0x48, 0x48, 0x4c),
    btn_fg: rgb(0xe9, 0xe9, 0xeb),
    btn_border: rgb(0x3c, 0x3c, 0x40),
    well_radius: 8,
    btn_radius: 6,
    body_size: 13.0,
};

const MACOS_LIGHT: Theme = Theme {
    flavor: OsFlavor::MacOs,
    dark: false,
    panel: rgb(0xf5, 0xf5, 0xf7),
    well: rgb(0xec, 0xec, 0xef),
    well_border: rgb(0xdc, 0xdc, 0xe1),
    raised: rgb(0xe4, 0xe4, 0xe8),
    headerbar: rgb(0xf5, 0xf5, 0xf7),
    footer: rgb(0xf5, 0xf5, 0xf7),
    rule: rgb(0xd2, 0xd2, 0xd7),
    stripe: Color32::from_rgba_premultiplied(0, 0, 0, 7),
    fg: rgb(0x1d, 0x1d, 0x1f),
    dim: rgb(0x6e, 0x6e, 0x73),
    faint: rgb(0x9d, 0x9d, 0xa3),
    accent: rgb(0x00, 0x7a, 0xff),
    accent_fg: Color32::WHITE,
    accent_text: rgb(0x00, 0x6a, 0xe0),
    ok: rgb(0x3f, 0x8b, 0x34),
    danger: rgb(0xc4, 0x39, 0x2e),
    btn: Color32::WHITE,
    btn_fg: rgb(0x1d, 0x1d, 0x1f),
    btn_border: rgb(0xd2, 0xd2, 0xd7),
    well_radius: 8,
    btn_radius: 6,
    body_size: 13.0,
};

const WINDOWS_DARK: Theme = Theme {
    flavor: OsFlavor::Windows,
    dark: true,
    panel: rgb(0x2b, 0x2b, 0x2b),
    well: rgb(0x32, 0x32, 0x32),
    well_border: rgb(0x1f, 0x1f, 0x1f),
    raised: rgb(0x38, 0x38, 0x38),
    headerbar: rgb(0x2b, 0x2b, 0x2b),
    footer: rgb(0x20, 0x20, 0x20),
    rule: rgb(0x38, 0x38, 0x38),
    stripe: Color32::TRANSPARENT,
    fg: Color32::WHITE,
    dim: rgb(0x9d, 0x9d, 0x9d),
    faint: rgb(0x6d, 0x6d, 0x6d),
    accent: rgb(0x60, 0xcd, 0xff),
    accent_fg: rgb(0x1b, 0x1b, 0x1b),
    accent_text: rgb(0x60, 0xcd, 0xff),
    ok: rgb(0x6c, 0xcb, 0x5f),
    danger: rgb(0xff, 0x99, 0xa4),
    btn: rgb(0x38, 0x38, 0x38),
    btn_fg: Color32::WHITE,
    btn_border: rgb(0x45, 0x45, 0x45),
    well_radius: 4,
    btn_radius: 4,
    body_size: 14.0,
};

const WINDOWS_LIGHT: Theme = Theme {
    flavor: OsFlavor::Windows,
    dark: false,
    panel: rgb(0xfb, 0xfb, 0xfb),
    well: rgb(0xf6, 0xf6, 0xf6),
    well_border: rgb(0xe5, 0xe5, 0xe5),
    raised: rgb(0xef, 0xef, 0xef),
    headerbar: rgb(0xfb, 0xfb, 0xfb),
    footer: rgb(0xf3, 0xf3, 0xf3),
    rule: rgb(0xe5, 0xe5, 0xe5),
    stripe: Color32::TRANSPARENT,
    fg: rgb(0x1b, 0x1b, 0x1b),
    dim: rgb(0x5f, 0x5f, 0x5f),
    faint: rgb(0x9b, 0x9b, 0x9b),
    accent: rgb(0x00, 0x5f, 0xb8),
    accent_fg: Color32::WHITE,
    accent_text: rgb(0x00, 0x5f, 0xb8),
    ok: rgb(0x0f, 0x7b, 0x0f),
    danger: rgb(0xc4, 0x2b, 0x1c),
    btn: Color32::WHITE,
    btn_fg: rgb(0x1b, 0x1b, 0x1b),
    btn_border: rgb(0xd1, 0xd1, 0xd1),
    well_radius: 4,
    btn_radius: 4,
    body_size: 14.0,
};

const GNOME_DARK: Theme = Theme {
    flavor: OsFlavor::Gnome,
    dark: true,
    panel: rgb(0x38, 0x38, 0x38),
    well: rgb(0x30, 0x30, 0x30),
    well_border: Color32::from_rgba_premultiplied(20, 20, 20, 20),
    raised: rgb(0x42, 0x42, 0x42),
    headerbar: rgb(0x30, 0x30, 0x30),
    footer: rgb(0x38, 0x38, 0x38),
    rule: Color32::from_rgba_premultiplied(26, 26, 26, 26),
    stripe: Color32::TRANSPARENT,
    fg: Color32::WHITE,
    dim: rgb(0x9a, 0x99, 0x96),
    faint: rgb(0x77, 0x76, 0x7b),
    accent: rgb(0x35, 0x84, 0xe4),
    accent_fg: Color32::WHITE,
    accent_text: rgb(0x78, 0xae, 0xed),
    ok: rgb(0x8f, 0xf0, 0xa4),
    danger: rgb(0xff, 0x7b, 0x63),
    btn: rgb(0x45, 0x45, 0x4a),
    btn_fg: Color32::WHITE,
    btn_border: rgb(0x45, 0x45, 0x4a),
    well_radius: 12,
    btn_radius: 6,
    body_size: 13.5,
};

const GNOME_LIGHT: Theme = Theme {
    flavor: OsFlavor::Gnome,
    dark: false,
    panel: rgb(0xfa, 0xfa, 0xfa),
    well: Color32::WHITE,
    well_border: Color32::from_rgba_premultiplied(0, 0, 0, 23),
    raised: rgb(0xf0, 0xf0, 0xf0),
    headerbar: rgb(0xf0, 0xf0, 0xf0),
    footer: rgb(0xfa, 0xfa, 0xfa),
    rule: Color32::from_rgba_premultiplied(0, 0, 0, 28),
    stripe: Color32::TRANSPARENT,
    fg: rgb(0x26, 0x26, 0x2b),
    dim: rgb(0x77, 0x76, 0x7b),
    faint: rgb(0xa4, 0xa3, 0xa8),
    accent: rgb(0x35, 0x84, 0xe4),
    accent_fg: Color32::WHITE,
    accent_text: rgb(0x1c, 0x71, 0xd8),
    ok: rgb(0x26, 0xa2, 0x69),
    danger: rgb(0xc0, 0x1c, 0x28),
    btn: rgb(0xea, 0xea, 0xec),
    btn_fg: rgb(0x26, 0x26, 0x2b),
    btn_border: rgb(0xea, 0xea, 0xec),
    well_radius: 12,
    btn_radius: 6,
    body_size: 13.5,
};
