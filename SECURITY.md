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

Keep live briefs, captures, model selections, approvals, credentials, backups,
operator handoffs and research plans outside the checkout. Review commit author
metadata too; removing a personal address from a working tree does not remove it
from history. History rewrites require explicit coordination and cannot recall
existing clones. Use a verified GitHub noreply address for public commits.

Enable repository secret scanning and push protection. They complement local
review; supported patterns and scan coverage are limited. See
[GitHub secret scanning](https://docs.github.com/en/code-security/concepts/secret-security/secret-scanning).
CI has read-only repository permissions, uses synthetic data, and never deploys.
Do not add production secrets to CI or run untrusted pull-request code with them.

## Network and request boundaries

Owner deployments use private Flycast ingress with no public IP allocations on
either app or database. Recheck allocations and machine services before releases:
adding a public IP can expose configured services. Other peers on the same Fly
private network can still reach them. See [Flycast](https://fly.io/docs/networking/flycast/).

All corpus reads and writes require scoped Bearer authentication, checked before
request bodies are parsed. `/health` and static `/robots.txt` contain no corpus
data and are anonymous. The runtime uses a non-root container user. No HTTP route
executes model output or starts a generation worker. Publication approvals and
the signed ledger path are separate from authentication.

The checked-in Fly configuration sets request concurrency to soft 8 / hard 16 for
the single app machine. This bounds simultaneous requests routed through Fly
Proxy, not requests per second, direct private-network connections or response
bytes. See [Fly concurrency](https://fly.io/docs/apps/concurrency/). JSON bodies
have Axum's default 2 MiB limit except image uploads (12 MiB) and media absence
decisions (32 KiB); list queries also have bounded page sizes. These controls do
not constitute a public-service abuse defense or a traffic-spend cap.

The node serves deny-all `robots.txt` and sets `X-Robots-Tag`, `Cache-Control:
private, no-store`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`
and a restrictive Content-Security-Policy on responses, including refusals.
Crawler rules are voluntary and cannot secure private material or control
GitHub's hosting of this repository. See [robots.txt limitations](https://developers.google.com/search/docs/crawling-indexing/robots/intro).

## Data egress and residual risk

Private ingress does not restrict outbound traffic. No network egress allowlist
is established by this repository. The scheduled anchor contacts OpenTimestamps;
reviewed inference separately sends the authorized source packet to its pinned
provider. Inference children exclude database and signing credentials, disable
proxy inheritance and refuse HTTP redirects. Source text and model output are
untrusted data, never operator instructions or permission to invoke tools.

Bearer holders can retrieve their permitted data. A compromised runtime or
private-network peer is outside what robots directives can prevent. App-level
Fly secrets may be available to multiple process groups; secret names do not
prove process isolation. Verify signing-key placement and operator/worker
separation privately before expanding exposure. Do not remove or rotate signing
identity as a housekeeping step.

Runtime and Fly configuration changes take effect only through the explicit
[owner release procedure](docs/CICD-FLY.md), with exact-image isolated acceptance
and backup/restore checks. A source commit is not evidence of deployed protection.
Keep actual machine IDs, audit captures and dated findings in the private handoff.
