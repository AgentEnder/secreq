# Contributor fixtures

This directory holds **generated fixtures** that the test suites produce and
the docs site consumes. For docs aimed at people **using** `secreq`, see
[`../docs/`](../docs/).

## Index

| Directory | For |
|---|---|
| [`ui-screenshots/`](./ui-screenshots/) | Generated PNGs of the consent-window UI in representative states, one folder per fixture, each carrying the `layout.json` that guards its renders and holds the caption the docs site publishes. |
| [`cli-transcripts/`](./cli-transcripts/) | Recorded pty sessions for the interactive CLI flows (`init`, `wrap`, `ssh setup`, the bare picker), replayed by the docs site via `::term{id=…}`. |

Both are regenerated, never hand-edited — see each directory's `README.md`
for the recipe, and [`../CLAUDE.md`](../CLAUDE.md) for when regeneration is
mandatory.

## Where the prose docs went

Architecture notes, the agent orientation guide, the release runbook, the
launch checklist, and the fifteen design/implementation plans now live in
**brain**, under the `secreq` area, so they're searchable alongside the tasks
and changesets that reference them:

```sh
brain read secreq                     # list the area's docs
brain search "consent daemon threading"
brain search "auto-rules evaluation order" --area secreq
brain graph areas/secreq/architecture.md
```

Rough map of the old paths:

| Was | Now |
|---|---|
| `dev-docs/architecture.md` | `areas/secreq/architecture.md` |
| `dev-docs/AGENTS.md` | `areas/secreq/agents.md` |
| `dev-docs/RELEASING.md` | `areas/secreq/releasing.md` |
| `dev-docs/launch-checklist.md` | `areas/secreq/launch-checklist.md` |
| `dev-docs/plans/*.md` | `areas/secreq/design/*.md` |

Source comments and docs in this repo cite those by their brain path — e.g.
`brain: areas/secreq/design/2026-06-02-auto-rules.md` — which
`brain read`/`brain graph` resolve directly.
