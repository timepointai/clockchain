# Security and private operation

Report vulnerabilities through [GitHub private vulnerability reporting](https://github.com/timepointai/clockchain/security/advisories/new).
Do not post credentials, exploit captures or production data in public issues.
Never include secret values in logs, command arguments or reports. Revoke an
exposed credential before addressing copies in source or Git history.

## Public source and private artifacts

This repository is public. Its files and Git history can be cloned and indexed.
`.gitignore` prevents accidental addition of matching untracked files; it cannot
remove tracked files or past commits. `.dockerignore` admits only build inputs
and excludes common private artifacts from remote build context uploads.
Review staged changes and use a redacted history scanner before publishing:

```sh
git diff --cached --check
gitleaks git --log-opts=--all --redact=100
```

Keep live briefs, captures, model selections, approvals, credentials, signing
seeds, backups, operator handoffs and research plans outside the checkout. Review
commit author metadata too; removing a personal address from a working tree does
not remove it from history. History rewrites require explicit coordination and
cannot recall existing clones. Use a verified GitHub noreply address for public
commits.

Enable repository secret scanning and push protection. They complement local
review; supported patterns and scan coverage are limited. See
[GitHub secret scanning](https://docs.github.com/en/code-security/concepts/secret-security/secret-scanning).
CI has read-only repository permissions, uses synthetic data, and never deploys.
Do not add production secrets to CI or run untrusted pull-request code with them.

## Keys and identity

The v1 curator signing seed is generated, held and used only by the owner, on
the owner's workstation ([FIRST-ENTRY.md](docs/FIRST-ENTRY.md)). The node never
receives it; Fly secrets hold only the database URL, node credentials, the
instance id and the curators' public keys. Release tooling recomputes the
expected instance, rule identity and empty commitment from the checkout and the
operator environment instead of trusting what the node reports. Do not remove or
rotate signing identity as a housekeeping step: the curator set is part of the
bound rule identity of a v1 store.

## Network and request boundaries

Owner deployments use private Flycast ingress with no public IP allocations on
either app or database. Recheck allocations and machine services before releases:
adding a public IP can expose configured services. Other peers on the same Fly
private network can still reach them. See [Flycast](https://fly.io/docs/networking/flycast/).

Corpus reads and writes require scoped Bearer authentication: the read key
reads, only the write key submits, uploads bodies or exports. In v1 mode only
`/health` and `/ready` are anonymous; they report build, posture and rule
identity (instance, fold, filter version, curator public keys, hop bound), not
corpus data. A frozen posture refuses writes. v1 envelopes and bodies are
limited to 1 MiB each. The runtime uses a non-root container user. No HTTP route
executes model output or starts a generation worker. Signed admission is
separate from authentication: a valid credential cannot make an invalid
envelope valid.

The checked-in Fly configuration sets request concurrency to soft 8 / hard 16 for
the single app machine. This bounds simultaneous requests routed through Fly
Proxy, not requests per second, direct private-network connections or response
bytes. See [Fly concurrency](https://fly.io/docs/apps/concurrency/). These
controls do not constitute a public-service abuse defense or a traffic-spend cap.

`robots.txt` at the repository root is a deny-all crawler file for the node to
serve. Crawler rules are voluntary and cannot secure private material or control
GitHub's hosting of this repository. See [robots.txt limitations](https://developers.google.com/search/docs/crawling-indexing/robots/intro).

## Data egress and residual risk

Private ingress does not restrict outbound traffic. No network egress allowlist
is established by this repository. The v1 node runs no scheduled tick; the v0
anchor tick contacted OpenTimestamps. Generation and model calls remain held.

Bearer holders can retrieve their permitted data. A compromised runtime or
private-network peer is outside what robots directives can prevent. App-level
Fly secrets may be available to multiple process groups; secret names do not
prove process isolation. Verify credential placement and operator separation
privately before expanding exposure.

Runtime and Fly configuration changes take effect only through the explicit
[owner release procedure](docs/CICD-FLY.md), with exact-image isolated acceptance
and backup/restore checks. A source commit is not evidence of deployed protection.
Keep actual machine IDs, audit captures and dated findings in the private handoff.
