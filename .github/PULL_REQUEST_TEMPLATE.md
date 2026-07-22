<!--
Thanks for contributing to secreq! Please read CONTRIBUTING.md if you
haven't. Keep PRs focused — one logical change each.

If this fixes a SECURITY vulnerability, do NOT describe the exploit
here. Coordinate through the private process in SECURITY.md first.
-->

## What & why

<!-- What does this change, and why? Link the issue it closes. -->

Closes #

## How it works

<!-- A short walkthrough of the approach so a reviewer can reason about
     the security impact from the description alone. -->

## Security impact

<!-- Required. If "none", say so and why. Otherwise: which trust
     boundary does this touch, and how does it preserve the invariants? -->

- [ ] Consent still gates every secret release (consent before fetch).
- [ ] Fail-closed defaults are preserved (no daemon / no `--yes` / no
      graphical env / daemon unreachable ⇒ deny).
- [ ] No secret values added to logs, prompts, the audit log, or the
      approvals cache.
- [ ] Cache scope unchanged (or the change to `(wrap, ppid,
      parent_start_time)` is intentional and explained above).

## Checklist

- [ ] `cargo test` passes.
- [ ] `cargo clippy --all-targets -- -D warnings` is clean.
- [ ] `cargo fmt --check` is clean.
- [ ] No JSON-schema drift
      (`cargo run --example gen-schema | diff -q - docs/wraps.schema.json`;
      same for `gen-auto-rules-schema`).
- [ ] UI change? Screenshot fixtures regenerated and
      `dev-docs/ui-screenshots/README.md` updated.
- [ ] Docs updated (user-facing → `docs/`; internals → `dev-docs/`).
- [ ] A test covers the new behavior (especially any new fail-closed
      path).
