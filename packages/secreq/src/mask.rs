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
//!
//! Both of the masker's own buffers hold plaintext — the secrets it matches
//! against, and the tail it carries — so both are [`Zeroizing`], for the
//! reason `secret.rs` gives: a masker outlives the child whose output it
//! filters, and one masker per stream means these are the copies most likely
//! to still be resident in a coredump or paged out to swap.

use zeroize::Zeroizing;

/// A streaming, byte-exact redactor for a fixed set of secret values.
pub struct Masker {
    /// Secret byte-strings, sorted longest-first so overlapping matches prefer
    /// the longer secret. Plaintext, and held for the child's whole lifetime.
    secrets: Vec<Zeroizing<Vec<u8>>>,
    /// Length of the longest secret; the most we ever need to hold back.
    max_len: usize,
    /// Replacement emitted in place of each matched secret. Not secret.
    mask: Vec<u8>,
    /// Bytes carried over from a previous `push` (a potential partial match).
    /// Held back precisely *because* they may be the head of a secret, so this
    /// is live secret material between pushes.
    buf: Zeroizing<Vec<u8>>,
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
        let mut secrets: Vec<Zeroizing<Vec<u8>>> = secrets
            .into_iter()
            .map(|s| Zeroizing::new(s.as_ref().to_vec()))
            .filter(|s| !s.is_empty())
            .collect();
        // Longest-first: prefer the longer secret when two overlap at a position.
        secrets.sort_by_key(|s| std::cmp::Reverse(s.len()));
        // `dedup` by value; `Zeroizing` is deliberately not `PartialEq`, and a
        // dropped duplicate scrubs rather than being freed as plaintext.
        secrets.dedup_by(|a, b| a[..] == b[..]);
        let max_len = secrets.first().map_or(0, |s| s.len());
        Masker {
            secrets,
            max_len,
            mask: mask.to_vec(),
            buf: Zeroizing::new(Vec::new()),
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
        // Taken out to scan, put back below — the same allocation each time.
        // `out` never receives a whole secret (a match becomes the mask), so
        // it is not scrubbed; the carry is, and it is the one that holds live
        // secret bytes between calls.
        let mut buf = std::mem::replace(&mut self.buf, Zeroizing::new(Vec::new()));
        let len = buf.len();
        let mut out = Vec::with_capacity(len);
        let mut i = 0;

        while i < len {
            // Hold back BEFORE matching, not after. `match_at` is longest-first
            // only among secrets already fully present in `buf`; when a shorter
            // secret ends exactly at the buffer's end and a longer one starting
            // with it is still arriving, matching first would commit to the
            // short one and then emit the longer secret's tail verbatim on the
            // next push. Asking `is_secret_prefix` first defers that position
            // until the bytes that disambiguate it have landed.
            //
            // This cannot over-hold: `is_secret_prefix` requires
            // `s.len() > slice.len()`, so a position whose match is already
            // complete at full length is never deferred.
            if !eof && len - i < self.max_len && self.is_secret_prefix(&buf[i..]) {
                break; // hold back from i
            }
            if let Some(match_len) = self.match_at(&buf[i..]) {
                out.extend_from_slice(&self.mask);
                i += match_len;
                continue;
            }
            out.push(buf[i]);
            i += 1;
        }

        // Anything not emitted is carried for the next push (empty at EOF).
        // Draining in place rather than reallocating the tail keeps one buffer
        // for the masker's life: the consumed head is left in the allocation
        // that gets scrubbed on drop instead of being freed as plaintext on
        // every push, and the hot path loses an allocation rather than gaining
        // one.
        buf.drain(..i);
        self.buf = buf;
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
    //! Nothing here asserts the scrubbing itself. Seeing a buffer zeroized
    //! means reading an allocation after its owner is dropped — undefined
    //! behaviour, and a test that did it would be measuring the allocator
    //! rather than this module. `Zeroizing`'s `Drop` is the guarantee; what
    //! these tests hold is the other half of it, that wrapping the buffers
    //! changed nothing about what the filter emits.

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

    /// The chunk-boundary half of `prefers_the_longer_overlapping_secret`.
    ///
    /// When the read splits exactly where the *shorter* secret ends, the
    /// masker must not commit to it — the longer secret's remaining bytes
    /// would then be emitted verbatim. Masking must not depend on where the
    /// kernel happened to split the child's output.
    #[test]
    fn longer_overlapping_secret_survives_a_split_at_the_shorter_one() {
        let mut split = Masker::new(["token", "tokenABC"]);
        let out = mask_all(&mut split, &[b"x token", b"ABC y"]);
        assert_eq!(out, b"x ******** y");

        // ...and the result is identical to the unsplit stream.
        let mut whole = Masker::new(["token", "tokenABC"]);
        assert_eq!(out, mask_all(&mut whole, &[b"x tokenABC y"]));
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
