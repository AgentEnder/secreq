//! Minimal, read-only `.env` reader for `secreq run --env-file`.
//!
//! Parses `KEY=value` lines so their values can be scanned for
//! `secret://` references. Deliberately tiny: no interpolation, no
//! `export` keyword handling, no writing or scrubbing — unlike the
//! pre-pivot `import` tool, this never mutates the file. Values are
//! taken verbatim except for one layer of matching surrounding quotes.

/// Parse `.env` text into ordered `(key, value)` pairs. Blank lines and
/// `#` comments are skipped; a line with no `=` is skipped.
pub fn parse(input: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in input.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((key, value)) = trimmed.split_once('=') else {
            continue;
        };
        let key = key.trim().to_owned();
        if key.is_empty() {
            continue;
        }
        out.push((key, unquote(value.trim())));
    }
    out
}

/// Strip one layer of matching single or double quotes, if present.
fn unquote(value: &str) -> String {
    let bytes = value.as_bytes();
    if value.len() >= 2
        && (bytes[0] == b'"' || bytes[0] == b'\'')
        && bytes[bytes.len() - 1] == bytes[0]
    {
        value[1..value.len() - 1].to_owned()
    } else {
        value.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_pairs_ignoring_comments_and_blanks() {
        let input = "\
# a comment
DATABASE_URL=secret://op/Work/PG/url

STRIPE_KEY = secret://keychain/stripe
";
        let got = parse(input);
        assert_eq!(
            got,
            vec![
                (
                    "DATABASE_URL".to_owned(),
                    "secret://op/Work/PG/url".to_owned()
                ),
                (
                    "STRIPE_KEY".to_owned(),
                    "secret://keychain/stripe".to_owned()
                ),
            ]
        );
    }

    #[test]
    fn value_may_contain_equals_signs() {
        assert_eq!(
            parse("TOKEN=a=b=c"),
            vec![("TOKEN".to_owned(), "a=b=c".to_owned())]
        );
    }

    #[test]
    fn strips_matching_surrounding_quotes() {
        assert_eq!(
            parse("X=\"secret://op/x\"\nY='secret://op/y'"),
            vec![
                ("X".to_owned(), "secret://op/x".to_owned()),
                ("Y".to_owned(), "secret://op/y".to_owned()),
            ]
        );
    }

    #[test]
    fn skips_lines_without_an_equals() {
        assert_eq!(
            parse("NOTAVAR\nA=1"),
            vec![("A".to_owned(), "1".to_owned())]
        );
    }
}
