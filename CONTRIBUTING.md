# Contributing

Thanks for looking at Clockchain. Read [README.md](README.md) first, then
[AGENTS.md](AGENTS.md) (current working rules) and [HOLD.md](HOLD.md) (standing
owner constraints). Public availability does not change the project's licensing
or give access to private deployments or data.

## What a change must preserve

- Append-only events and the typed write path.
- Exact integer coordinates and explicit query times.
- Governed TT semantics. TT is upstream for the ontology, envelope and conformance vectors.
- Truthful evidence states. A missing body, missing evidence, unknown date and deliberate media absence stay distinct.
- Applied migrations. Never change the bytes of a migration that has been applied; add a new one, numbered in dependency order.
- Additive read contracts. A change to an existing read must stay compatible.

## Branch and pull request flow

1. Branch from `main` with a scoped name, for example `docs/readme-overhaul`.
2. Keep one concern per pull request.
3. Run the checks below before you push.
4. Open a pull request against `main`. Say what changed and why, and which checks you ran.
5. CI must be green. Merging does not deploy. The owner releases explicitly, as in [docs/CICD-FLY.md](docs/CICD-FLY.md).

Work starts from an explicit scope from the owner. No old backlog is an active order.

## Commit messages

One plain sentence in sentence case, with no `type:` prefix, no emojis and no
tool or co-author attribution lines. Say what the change does. Examples from the
history:

- Update webpki-roots to 1.0.10 to drop the compromised emSign ECC root
- Add a static-hosting Fly template for the explorer
- Document delegate --genesis-dir

Merge commits keep the default "Merge pull request" text.

## Git hooks

`githooks/pre-commit` refuses a commit on a detached HEAD. Enable it once per clone:

```sh
git config core.hooksPath githooks
```

Bypass it for a single commit with `git commit --no-verify`. The hook does not
scan for secrets, so check your own diff.

## Tests and checks

Tests run against a real PostgreSQL. No mock replaces database behavior. Start
the local database and run the Rust gate:

```sh
make db-up
make check        # cargo fmt check, Clippy with warnings as errors, cargo test
```

CI runs more than `make check`. In `.github/workflows/ci.yml` the job `check` also:

- builds `cc-core`, `cc-filter`, `cc-wasm-vectors` and `cc-wasm-verify` for `wasm32-unknown-unknown` and runs the Wasm vector check and the explorer Node tests;
- regenerates the v1 rule vectors with `python3 crates/cc-core/tests/vectors/v1_rule_reference.py` and fails if the committed files change;
- runs `cargo test --all`, builds `cc-node`, `cc-publisher` and `cc-gateway`;
- runs `python3 clients/fixtures/record.py --check` and the Python client tests;
- runs the Python operator tests: `python3 -m pip install -r ops/requirements.txt`, then `python3 -m unittest discover -s ops -p 'test_*.py'`. This includes a check that [docs/reference/openapi.json](docs/reference/openapi.json) matches the routers.

Two more jobs run the TypeScript client (`clients-ts`: `npm ci`, `npm run typecheck`, `npm test` in `clients/typescript`) and the Stage 0 reference fold (`stage0`).

`ops/ci-local.sh` reproduces the format, Clippy, Wasm core build, Rust test and
Python operator steps. **It drops every `cc_test_%` database and the `cc_app`
role on the cluster it points at.** Use an isolated local cluster, never a shared
or production one. Details are in [docs/LOCAL-DEV.md](docs/LOCAL-DEV.md).

Run the checks that match your change. A docs-only change needs none, but run
`python3 -m unittest discover -s ops -p 'test_*.py'` if you touched
`docs/reference/openapi.json`.

## Secrets and private data

Never commit credentials, API keys, signing seeds, tokens, `.env` files, backups,
production data, private hostnames or private research. Tokens are read from the
environment, never from command-line arguments. CI has read-only repository
permission and holds no production secrets. If you think you committed a secret,
tell the owner at once and do not rely on a later commit to hide it. To report a
vulnerability, follow [SECURITY.md](SECURITY.md).

## Content and approvals

Publishing a claim needs its own digest-bound human approval. Permission to
deploy does not stand in for it. Infrastructure work does not authorize anyone, human or
agent, to stage, approve, sign or publish content that the owner has reserved for
human operation.
