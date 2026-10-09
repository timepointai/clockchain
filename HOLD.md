# Standing owner hold

Read this file before release, publication, generation, or fixture work. These
constraints remain active until the owner explicitly changes them.

- No deployment or production writes. The 2026-10-01 launch authorization below
  is consumed; a routine release needs its own dated owner authorization.
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

## Launch completion — 2026-10-02 (UTC)

The 2026-10-01 launch authorization was executed and is consumed:

- the fresh v1 database was provisioned and its rule identity bound with the
  owner's curator key set;
- exactly one owner-signed inaugural Genesis, the Engelbart 1968 subject, was
  admitted on 2026-10-02 as event `95f7fe16…a75185b6`;
- the v0 database is untouched and kept as an archive;
- the v0 tick machine was removed; v1 runs no tick.

Production stays on private ingress, with posture `live`. Any routine release
after this point is a separate, per-release owner authorization under the
2026-10-03 program below. Still held: generation and model calls, the 1973 claim
and its influence edge, both images, any further publication, and the
disposition of issue #6.

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

Under this program the owner ran one verified update release (build
`af82d9e4cd8d`, 2026-10-05) and one Delegate to a per-subject hot key on the
inaugural subject (2026-10-05). The root key stays with the owner. Those were
explicit owner actions; they do not authorize further deploys or entries.

## Owner decisions — 2026-10-08

The owner decided the following on 2026-10-08, after the 2026-10-07 wrap-up:

- **One update release** onto the populated v1 store is authorized, through the
  verified update lane ([OPERATIONS.md](docs/OPERATIONS.md) section 2), of `main`
  as of this record's merge commit. It ships the acceptance-diagnostics fix
  (PR #28) and documentation. No rule, identity or store change is part of it.
- **Public read exposure** is authorized through the merged read-only gateway
  ([PUBLIC-ACCESS.md](docs/PUBLIC-ACCESS.md)): one gateway machine, public IPv6
  only, no IPv4, no custom domain. The node's current read key is imported as the
  gateway app's secret and shared, not rotated. The node itself stays on private
  ingress. Disabling ingress is the one-command IP release; it leaves the key in
  the gateway app. Revoking a compromised gateway would require rotating the node
  read key for every holder, which this decision does not authorize; that would
  need a new dated decision.
- **Issue #6** may be closed. Its gate-by-gate disposition is recorded in the
  closing comment on the issue.
- **Sealing**: node-signed seals ([SEALING.md](docs/design/SEALING.md) option A
  variant: the node signs a stateless seal on request with the receipt key, and
  the operator keeps a hash-chained seal log outside the `cc_v1` store, fetched
  periodically from the workstation) are authorized as software only. Nothing is
  deployed by this decision; a later release ships it.
- **v0 archive**: a read-only dump of the v0 database into the owner's private
  archive outside the checkout is authorized. Dropping the v0 database is not.
- These are run by the owner, or by the owner's agent at the owner's explicit
  instruction in the 2026-10-08 session, from the owner's workstation, never
  from CI or a cloud session. That includes the gateway steps PUBLIC-ACCESS.md
  describes as owner-run (importing the read key, allocating the public IP).

Execution record, 2026-10-08 (UTC): the update release ran through the verified
lane and production now serves build `c56f73a89bcf` with identity, commitment and
export unchanged and verified backups before and after; the gateway was deployed
and given its public IPv6, and the PUBLIC-ACCESS.md verify block passed; issue #6
was closed with its disposition. The seal-log software merged (PR #34, `002649e`)
after this record; it is not deployed.

Public read of the existing corpus is the only publication this decision
authorizes; the earlier "any further publication" hold is consumed to that
extent. Still held: generation and model calls; the 1973 claim and its influence
edge; both images; any further entry, edge or media; key generation, rotation or
revocation; consumer-repository merges.

## Owner decisions — 2026-10-09

The owner decided the following on 2026-10-09, after the 2026-10-08 close-out,
to finish the public read launch. Content stays at the one inaugural subject.

- **IPv4.** The gateway may also be given one shared IPv4 address
  (`fly ips allocate-v4 --shared`), so IPv4-only readers can reach it. Still no
  custom domain. Disabling ingress then means releasing both addresses.
- **Routine release.** One update release onto the populated v1 store is
  authorized, through the verified update lane
  ([OPERATIONS.md](docs/OPERATIONS.md) section 2), of `main` as of this record's
  merge commit. It ships `GET /v1/seal` (PR #34) and documentation. No rule,
  identity or store change is part of it. The node's existing receipt key signs
  seals; no key is generated.
- **Seal job.** The hourly seal log job (`ops/seal_v1.py`) may be installed on
  the owner's workstation against the released node, with the node's public
  key (`node_key=` in its boot log) pinned. The seal route stays off the public
  gateway contract.
- **Public host.** The gateway's host name may be published in this repository
  (README, PUBLIC-ACCESS, INTEGRATIONS). This is the one exception to the rule
  that keeps hostnames out of the public tree; node hostnames, IPs, the instance
  id and private paths remain excluded.
- **Consumer repositories.** The three flag-gated read integrations
  (api-gateway #56, mcp #13, web-app #345) may be merged with their flags off.
  Enabling a flag or setting the public URL in a consumer is a separate owner
  step per repository, not authorized here.
- **v0 archive.** Restated from 2026-10-08: a read-only dump into the private
  archive is authorized; dropping the v0 database is not.
- These are run by the owner, or by the owner's agent at the owner's explicit
  instruction in the 2026-10-09 session, from the owner's workstation, never
  from CI or a cloud session.

Execution record, 2026-10-09 (UTC): the gateway received a shared IPv4 at
16:35Z and the PUBLIC-ACCESS.md verify block passed over IPv4 and IPv6; the
update release ran through the verified lane and production serves build
`df094748ad64` since 18:36Z with identity, commitment and export unchanged and
verified backups before and after (a first build attempt failed on a transient
toolchain download before any production step); the seal log's first entry was
recorded at 18:48Z and the hourly job is installed on the workstation; the host
is published in this repository by the same pull request as this record; the
v0 database was dumped read-only into the private archive. Consumer merges
are recorded as they land in [INTEGRATIONS.md](docs/INTEGRATIONS.md).

Still held: generation and model calls; the 1973 claim and its influence edge;
both images; any further entry, edge or media; key generation, rotation or
revocation; any broader delegate scope (a design memo may be written;
nothing implemented); dropping v0.

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
