#!/usr/bin/env bash
# Run EXACTLY what .github/workflows/ci.yml runs, against a CLEAN cluster.
#
# This exists because a green `cargo test` on this machine was not evidence
# about CI, twice in one session, in two different ways:
#
#   * `cargo fmt --check` had been failing in CI for four consecutive pushes
#     while nobody read the output. Nothing local ran it.
#   * `0002` creates the cluster-global `cc_app` role and two ephemeral
#     databases provisioning at once race for it. It could not reproduce here:
#     `cleanup` is best-effort, 36 leaked test databases had accumulated, and
#     objects they owned made the role undroppable — so it was always already
#     present and the guard's happy path always taken.
#
# The second one is the point. The local suite was not merely unrun, it was
# green FOR A REASON THAT DID NOT HOLD IN CI. Dropping the leaked databases and
# the role is what turned it red, so this drops them first, every time.
#
# Needs a local Postgres. Refuses rather than skipping — a check that quietly
# does nothing is worse than one that is absent, because it reports as passing.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

pg_isready -q || { echo "no local Postgres — start one, do not skip this" >&2; exit 1; }
: "${TEST_DATABASE_URL:=postgres://$(whoami)@localhost:5432/postgres}"
export TEST_DATABASE_URL DATABASE_URL="$TEST_DATABASE_URL"

step(){ printf '\n=== %s\n' "$1"; }

step "clean cluster (leaked databases, then the cluster-global role)"
for d in $(psql -d postgres -At -c \
    "select datname from pg_database where datname like 'cc_test_%'"); do
    psql -d postgres -q -c "DROP DATABASE IF EXISTS \"$d\"" 2>/dev/null || true
done
psql -d postgres -q -c "DROP ROLE IF EXISTS cc_app" 2>/dev/null || true
# Assert the precondition rather than assuming the drops worked. A role that
# survived because something still depends on it puts this back to testing the
# dirty case while printing the clean one.
[[ "$(psql -d postgres -At -c "select count(*) from pg_roles where rolname='cc_app'")" == "0" ]] \
    || { echo "cc_app survived the drop — something still owns objects; not a clean run" >&2; exit 1; }

step "Format          (cargo fmt --all -- --check)"
cargo fmt --all -- --check

step "Clippy          (cargo clippy --all-targets -- -D warnings)"
cargo clippy --all-targets -- -D warnings

step "Wasm purity     (cc-core + cc-filter to wasm32)"
cargo build -p cc-core -p cc-filter --target wasm32-unknown-unknown

step "Test            (cargo test --all, real Postgres)"
cargo test --all

step "Offline evaluation contract"
python3 -m unittest discover -s ops -p 'test_*.py'

printf '\nci-local: PASS — this is what CI runs\n'
