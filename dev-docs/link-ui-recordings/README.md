# Linked-device browser recordings

These fixtures drive the production Link UI in Chromium against a deterministic
local HTTP/SSE server. They are documentation evidence, not hand-authored demo
videos: pairing generates and stores a real browser key, and approval signs the
canonical request fixture before the fake host advances its queue.

Regenerate them from the repository root after changing the Link UI, the
canonical fixture, or the recording harness:

```sh
pnpm --filter @secreq/link-ui record:flows
```

The first run needs the pinned browser:

```sh
pnpm --filter @secreq/link-ui exec playwright install chromium
```

`pnpm --filter @secreq/link-ui test` checks the source digest, asset digests,
viewport, metadata, and fixture file set. The docs site copies each recording
into its public build and exposes it through `::flow{screen=<fixture-id>}`.
