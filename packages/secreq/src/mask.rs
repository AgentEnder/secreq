//! Multi-provider output masking (§8).
//!
//! A [`Masker`] redacts any resolved secret value that appears in a child's
//! output, regardless of which provider it came from. It is a streaming filter:
//! callers [`push`](Masker::push) chunks as they arrive and [`finish`] at EOF.
//!
//! Two hard parts from the design are handled here:
//! - **Split across reads** — a secret straddling two chunks is caught by
//!   carrying a tail buffer and only emitting bytes that cannot begin a secret.
//! - **Binary safety** — matching is byte-exact, never UTF-8-dependent, so a
//!   binary stream that doesn't contain a secret passes through untouched.

/// A streaming, byte-exact redactor for a fixed set of secret values.
pub struct Masker {
    /// Secret byte-strings, sorted longest-first so overlapping matches prefer
    /// the longer secret.
    secrets: Vec<Vec<u8>>,
    /// Length of the longest secret; the most we ever need to hold back.
    max_len: usize,
    /// Replacement emitted in place of each matched secret.
    mask: Vec<u8>,
    /// Bytes carried over from a previous `push` (a potential partial match).
    buf: Vec<u8>,
}

/// The default redaction token written in place of a secret.
pub const DEFAULT_MASK: &[u8] = b"********";

impl Masker {
    /// Build a masker for the given secret values. Empty values are ignored
    /// (they would otherwise match everywhere). If no non-empty secrets remain,
    /// the masker is a pass-through.
    pub fn new<I, S>(secrets: I) -> Masker
    where
        I: IntoIterator<Item = S>,
        S: AsRef<[u8]>,
    {
        Masker::with_mask(secrets, DEFAULT_MASK)
    }

    /// Like [`new`](Masker::new) but with a custom replacement token.
    pub fn with_mask<I, S>(secrets: I, mask: &[u8]) -> Masker
    where
        I: IntoIterator<Item = S>,
        S: AsRef<[u8]>,
    {
        let mut secrets: Vec<Vec<u8>> = secrets
            .into_iter()
            .map(|s| s.as_ref().to_vec())
            .filter(|s| !s.is_empty())
            .collect();
        // Longest-first: prefer the longer secret when two overlap at a position.
        secrets.sort_by_key(|s| std::cmp::Reverse(s.len()));
        secrets.dedup();
        let max_len = secrets.first().map(|s| s.len()).unwrap_or(0);
        Masker {
            secrets,
            max_len,
            mask: mask.to_vec(),
            buf: Vec::new(),
        }
    }

    /// True when there is nothing to redact; callers may skip filtering.
    pub fn is_passthrough(&self) -> bool {
        self.secrets.is_empty()
    }

    /// Feed a chunk; returns the bytes that are safe to emit now. Bytes that
    /// might begin a secret completed by a later chunk are held back.
    pub fn push(&mut self, data: &[u8]) -> Vec<u8> {
        if self.is_passthrough() {
            return data.to_vec();
        }
        self.buf.extend_from_slice(data);
        self.scan(false)
    }

    /// Flush at end of stream: redact and emit everything remaining.
    pub fn finish(&mut self) -> Vec<u8> {
        if self.is_passthrough() {
            return Vec::new();
        }
        self.scan(true)
    }

    /// Scan `self.buf`, emitting redacted output. When `eof` is false, stop at
    /// the first trailing position that could still begin a secret and carry it
    /// over; when true, emit everything.
    fn scan(&mut self, eof: bool) -> Vec<u8> {
        let buf = std::mem::take(&mut self.buf);
        let len = buf.len();
        let mut out = Vec::with_capacity(len);
        let mut i = 0;

        while i < len {
            if let Some(match_len) = self.match_at(&buf[i..]) {
                out.extend_from_slice(&self.mask);
                i += match_len;
                continue;
            }
            // No complete match here. Near the end of a non-final chunk this
            // position may be the start of a secret finished by a later push.
            if !eof && len - i < self.max_len && self.is_secret_prefix(&buf[i..]) {
                break; // hold back from i
            }
            out.push(buf[i]);
            i += 1;
        }

        // Anything not emitted is carried for the next push (empty at EOF).
        self.buf = buf[i..].to_vec();
        out
    }

    /// If a secret matches at the start of `slice`, return its length (longest).
    fn match_at(&self, slice: &[u8]) -> Option<usize> {
        self.secrets
            .iter()
            .find(|s| slice.starts_with(s))
            .map(|s| s.len())
    }

    /// True if `slice` is a strict, incomplete prefix of some secret — i.e. it
    /// could grow into a match once more bytes arrive.
    fn is_secret_prefix(&self, slice: &[u8]) -> bool {
        self.secrets
            .iter()
            .any(|s| s.len() > slice.len() && s.starts_with(slice))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Convenience: push then finish, returning the full masked output.
    fn mask_all(masker: &mut Masker, chunks: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for chunk in chunks {
            out.extend(masker.push(chunk));
        }
        out.extend(masker.finish());
        out
    }

    #[test]
    fn redacts_a_whole_secret_in_one_chunk() {
        let mut m = Masker::new(["hunter2"]);
        let out = mask_all(&mut m, &[b"user=admin pass=hunter2 done"]);
        assert_eq!(out, b"user=admin pass=******** done");
    }

    #[test]
    fn redacts_a_secret_split_across_two_chunks() {
        let mut m = Masker::new(["SECRETVALUE"]);
        // The secret straddles the chunk boundary.
        let out = mask_all(&mut m, &[b"before SECRE", b"TVALUE after"]);
        assert_eq!(out, b"before ******** after");
    }

    #[test]
    fn redacts_secret_split_across_many_tiny_chunks() {
        let mut m = Masker::new(["abcdef"]);
        let chunks: Vec<&[u8]> = vec![b"x", b"a", b"b", b"c", b"d", b"e", b"f", b"y"];
        assert_eq!(mask_all(&mut m, &chunks), b"x********y");
    }

    #[test]
    fn redacts_multiple_distinct_secrets() {
        let mut m = Masker::new(["alpha", "bravo"]);
        let out = mask_all(&mut m, &[b"alpha then bravo then alpha"]);
        assert_eq!(out, b"******** then ******** then ********");
    }

    #[test]
    fn prefers_the_longer_overlapping_secret() {
        // "tokenABC" contains "token"; the longer secret must win.
        let mut m = Masker::new(["token", "tokenABC"]);
        let out = mask_all(&mut m, &[b"x tokenABC y"]);
        assert_eq!(out, b"x ******** y");
    }

    #[test]
    fn does_not_hold_back_bytes_that_cannot_start_a_secret() {
        // A non-final push whose tail can't begin the secret emits immediately.
        let mut m = Masker::new(["SECRET"]);
        let emitted = m.push(b"hello world ");
        assert_eq!(emitted, b"hello world "); // nothing held back
    }

    #[test]
    fn holds_back_only_a_viable_partial_tail() {
        let mut m = Masker::new(["SECRET"]);
        // "...SEC" is a viable prefix and is held back; the rest is emitted now.
        let emitted = m.push(b"value SEC");
        assert_eq!(emitted, b"value ");
        let rest = m.push(b"RET!");
        assert_eq!(rest, b"********!");
    }

    #[test]
    fn passthrough_when_no_secrets() {
        let mut m = Masker::new(Vec::<&str>::new());
        assert!(m.is_passthrough());
        assert_eq!(mask_all(&mut m, &[b"anything at all"]), b"anything at all");
    }

    #[test]
    fn empty_secrets_are_ignored() {
        let mut m = Masker::new(["", "x"]);
        assert_eq!(mask_all(&mut m, &[b"axbxc"]), b"a********b********c");
    }

    #[test]
    fn binary_stream_without_secret_is_untouched() {
        let mut m = Masker::new(["nope"]);
        let data: Vec<u8> = (0u8..=255).collect();
        assert_eq!(mask_all(&mut m, &[&data]), data);
    }

    #[test]
    fn custom_mask_token() {
        let mut m = Masker::with_mask(["pw"], b"[redacted]");
        assert_eq!(mask_all(&mut m, &[b"a pw b"]), b"a [redacted] b");
    }
}
