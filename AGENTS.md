# Clockchain core — working instructions

Public Rust/Postgres core. Read README.md and the relevant current contract.
Production data, credentials, source captures, approval records and backups stay
outside this checkout. Do not restore retired Railway or wrapper tooling.

Follow the owner's current scoped instruction; no old backlog is an active order.
TT remains upstream for ontology/envelope/conformance. Preserve identity and applied
migration bytes; reject malformed inputs and keep unknown evidence explicit.

Run `make check`, Wasm build and `python3 -m unittest discover -s ops -p 'test_*.py'`
for relevant implementation changes. Tests use real Postgres. Docker acceptance
runs the exact immutable image with isolated synthetic data; it cannot target
production. Deployment is an explicit local owner action, never a main-branch side
effect. Keep tag+digest tick updates, skip-start, compatible migration recovery,
backup/restore checks and scoped authorization intact.

Owner-designated human-only publications remain human-operated. Infrastructure work
does not authorize an agent to stage, approve, sign or publish their content.
Private evidence and the exact operator handoff are retained outside this repo.

No secrets in code, logs or reports. Commit messages contain only the description,
with no co-author or tool attribution. Do not add application code to old archive repos.
