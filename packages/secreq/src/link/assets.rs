//! Browser client assets embedded in the `secreq` binary.
//!
//! Fixed filenames are pinned in `packages/link-ui/vite.config.ts`, so this
//! needs no directory-embedding crate. Vite writes its committed output under
//! this crate's `dist/` because Cargo cannot package a sibling workspace
//! directory; that keeps `cargo install secreq` independent of Node and avoids
//! committing two copies of the bundle.

const INDEX_HTML: &str = include_str!("../../dist/link-ui/index.html");
const APP_JS: &str = include_str!("../../dist/link-ui/app.js");
const APP_CSS: &str = include_str!("../../dist/link-ui/app.css");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Asset {
    pub body: &'static str,
    pub content_type: &'static str,
}

pub(crate) fn get(path: &str) -> Option<Asset> {
    match path {
        "/" | "/pair" => Some(Asset {
            body: INDEX_HTML,
            content_type: "text/html; charset=utf-8",
        }),
        "/app.js" => Some(Asset {
            body: APP_JS,
            content_type: "text/javascript; charset=utf-8",
        }),
        "/app.css" => Some(Asset {
            body: APP_CSS,
            content_type: "text/css; charset=utf-8",
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_embedded_asset_is_non_empty() {
        for (name, asset) in [
            ("index.html", INDEX_HTML),
            ("app.js", APP_JS),
            ("app.css", APP_CSS),
        ] {
            assert!(!asset.trim().is_empty(), "{name} must not be empty");
        }
    }

    #[test]
    fn index_references_both_fixed_bundle_names() {
        assert!(INDEX_HTML.contains("app.js"));
        assert!(INDEX_HTML.contains("app.css"));
    }

    #[test]
    fn only_the_client_routes_are_assets() {
        assert!(get("/").is_some());
        assert!(get("/pair").is_some());
        assert!(get("/app.js").is_some());
        assert!(get("/app.css").is_some());
        assert!(get("/decision").is_none());
    }
}
