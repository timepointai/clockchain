# Contributing

Use a scoped branch and pull request. CI checks format, Clippy, real-Postgres
integration tests, Wasm compatibility and Python operator tests. Run the relevant
checks locally before pushing. No mocks replace database behavior.

Preserve append-only events, the typed write path, exact integer coordinates,
explicit query times, governed TT semantics and truthful evidence states. Additive
read contracts require compatibility. Never change an applied migration's bytes.

Public CI has read-only repository permission and no production secrets. Merging
does not deploy. The owner releases explicitly through [the private release
procedure](docs/CICD-FLY.md). Publication of claims has its own digest-bound human
approvals; deployment authorization does not substitute for them.

Commit messages: `type: description`, without attribution tags or emojis.
Public availability does not change the project's licensing or grant access to
private deployments or data. Do not contribute credentials or private evidence.
