# Standing owner hold

Read this file before release, publication, generation, or fixture work. These
constraints remain active until the owner explicitly changes them.

- No deployment or production writes, except the owner-authorized v1 launch
  below.
- No historical or image generation, model calls, new model attempts, or retries.
- The private inaugural fixture is frozen: preserve its files, receipts, bindings,
  image bytes and hashes. Do not replace its sources. Apart from the authorized
  1968 entry below, do not publish any subset.
- Excluded private images do not imply a signed absence decision.
- Passing tests or a software merge do not authorize release or publication.

## Owner launch decisions — 2026-10-01

The owner decided the following:

- **Defaults.** The governed defaults in [STAGE-E.md](docs/design/STAGE-E.md) are
  accepted as pinned for `fold_version` 1, with production `max_hops = 4`.
- **Stage (f).** Runtime integration, as planned in
  [STAGE-F.md](docs/design/STAGE-F.md), is authorized.
- **Release.** One owner-operated release of v1 onto a **fresh, empty v1
  database** is authorized. Production writes are limited to:
  - provisioning that database;
  - binding its rule identity, with the owner's curator key set;
  - the single inaugural entry below.

  The v0 database is left untouched as an archive.
- **Inaugural entry.** The Engelbart 1968 "Mother of All Demos" subject, newly
  authored as a v1 Genesis from the fixture's 1968 claim. It carries no media
  and no signed absence decision. The 1973 claim, its influence edge, and both
  images stay private and held. The fixture files themselves stay unchanged.
- **Human-only steps.** The owner, or the owner's agent at the owner's explicit
  instruction in that session, runs deployment from the owner's workstation.
  Never from CI or a cloud session. Only the owner generates, holds and uses
  the root/curator signing key. Only the owner approves and submits the
  inaugural entry.
- **Still held.** Generation and model calls remain held. Issue #6 disposition
  and any further publication remain owner decisions.

## Launch record — 2026-10-02

v1 was released onto the fresh database. The inaugural Engelbart 1968 Genesis was
admitted on 2026-10-02 as event `95f7fe16…a75185b6`, and it is the only entry.
Production stays on private ingress, with posture `live`.

## Owner decision: post-launch program — 2026-10-03

The owner authorized building all twelve post-launch items in
[STAGE-G.md](docs/design/STAGE-G.md). Building and supervised merging in this
repository are authorized. These remain explicit owner actions, run from the owner's
workstation:

- production deploys, including update releases;
- public ingress or exposure;
- production secrets;
- key ceremonies, including the hot delegate key;
- any new entry, edge or media;
- merges in consumer repositories.

Generation and model calls remain held.

## PR #5 merge record — 2026-09-28

PR #5 merged under the owner's independent HTTP policy decision and explicit
merge authorization, conditional on green CI. Deployment, generation and
publication remain held. [Issue #6](https://github.com/timepointai/clockchain/issues/6)
records gates that block the first production entry, not this software merge.

Local synthetic tests, scoped software changes and review evidence are permitted
when requested. They must not use the inaugural fixture as test content. A request
for a recommendation does not authorize implementing the recommended design.

Keep these constraints here; do not repeat the checklist in routine turn updates.
Report a violation, changed instruction or concrete blocker when relevant.
