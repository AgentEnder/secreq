---
name: Feature request
about: Suggest an idea or enhancement
title: ''
labels: enhancement
assignees: ''
---

<!--
Before filing: `secreq` deliberately does NOT do some things
(project-scope config, cloud sync, rotation, drift detection, being a
long-lived secret broker). See "What this project deliberately doesn't
do" in dev-docs/AGENTS.md so we don't rehash a settled decision.
-->

## Problem

What are you trying to do that `secreq` makes hard or impossible today?
Describe the problem before the solution.

## Proposed solution

What you'd like to see. If it touches the trust model, the wire
protocol, or rule semantics, describe how it preserves the existing
security invariants (consent before fetch, fail-closed defaults,
direct-parent cache scope, no secret values in logs/audit).

## Alternatives considered

Other approaches you thought about and why they fall short.

## Additional context

Anything else — links, prior art (e.g. how 1Password Shell Plugins /
aws-vault / envchain handle it), screenshots.
