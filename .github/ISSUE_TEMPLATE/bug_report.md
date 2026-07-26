---
name: Bug report
about: Report incorrect or unexpected behavior
title: ''
labels: bug
assignees: ''
---

<!--
⚠️  SECURITY ISSUE? STOP.
If this bug can leak a credential, bypass the consent prompt, or
otherwise weaken a trust boundary, do NOT file it here. Report it
privately — see SECURITY.md.

Never paste real secret values or `secret://` refs that point at live
credentials. Use placeholders.
-->

## What happened

A clear description of the bug and what you expected instead.

## Reproduction

Steps to reproduce, including the relevant (redacted) configuration:

1. `secreq wrap …` / relevant `wraps.json5` or rule (secrets removed)
2. Command run: `…`
3. Observed: `…`

## Expected behavior

What you expected to happen.

## Environment

- `secreq` version / commit: <!-- `secreq --version` or the commit sha -->
- OS + version:
- Secret provider(s) involved (`op` / `keychain` / `pass` / `lastpass` / custom):
- Running via the PATH shim, `secreq run`, the SSH agent, or the scoped agent?

## Logs / output

Relevant output with **all secret values redacted**.

```
paste here
```

## Additional context

Anything else that might help.
