# Contributor documentation

This directory holds documents aimed at people working **on** `secreq`
(maintainers, contributors, AI coding agents). For docs aimed at people
**using** `secreq`, see [`../docs/`](../docs/).

## Index

| Reading | For |
|---|---|
| [`AGENTS.md`](./AGENTS.md) | AI-agent orientation: mental model in 60s, module map, common tasks, invariants. |
| [`architecture.md`](./architecture.md) | Module map, data flow for `secreq <BINARY>`, consent-daemon threading, masking algorithm. |
| [`plans/`](./plans/) | Historical design documents (pre-pivot). Kept for context, not as a source of truth. |

## Why "dev-docs" and not "docs/internal"

Keeping the directory hierarchy flat makes it obvious at a glance which
docs are for users vs contributors. `docs/` only contains user-facing
material; `dev-docs/` only contains contributor material; no mixed
audiences.

If you're writing a new document, ask: *would a user looking at "how do
I use secreq" want this?* If yes → `docs/`. If no → here.
