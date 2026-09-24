# --- builder ---------------------------------------------------------------
# rustls everywhere (see Cargo.toml sqlx features) => no libssl-dev needed;
# pkg-config is kept for any transitive build script that probes for it.
#
# Keep this tag in step with `rust-toolchain.toml` (1.97.1). The image ships
# rustup, so a stale tag still builds — it just downloads the pinned toolchain
# on every cold build, paying for a second Rust install to produce the same
# binary. It was pinned at 1.86 while the workspace moved to 1.97.1; the tree
# now depends transitively on `home`, whose MSRV is 1.88, so the old tag's only
# remaining effect was to make the build depend on that download succeeding.
FROM rust:1.97-slim-bookworm AS builder
# CI builds from its exact checkout and injects CC_BUILD_REV. .dockerignore
# excludes .git, so a release must never rely on a git fallback for identity.
RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config git \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY . .
# Runtime sqlx::query only + sqlx::migrate! embeds the migrations at compile
# time, so this build needs NO database.
#
# The build SHA is baked in, not read at runtime: /health publishes it so a
# deploy can be verified against the code it claims to be running (M6 "deploy
# truth"), and a value the container could compute for itself would prove
# nothing about which commit produced the binary.
# An explicit build arg still wins, for build systems that know their revision
# and do not ship `.git`. Left EMPTY by default rather than "unknown": build.rs
# treats blank as absent and falls through to git, whereas a literal "unknown"
# would be a value and would suppress the fallback.
ARG CC_BUILD_REV=""
ENV CC_BUILD_REV=${CC_BUILD_REV}
# Railway builds from its own checkout and does NOT ship `.git`, so the git
# fallback below resolves to "unknown" there — measured, not assumed: the first
# build after removing the stale stamp published exactly that. Railway does
# expose the commit as a build argument, so declaring it here is what makes the
# revision knowable at all on that platform.
ARG RAILWAY_GIT_COMMIT_SHA=""
# Mark the tree safe: the build context is copied in as root, and git refuses to
# read a repo owned by another user, which would make `git rev-parse` fail for a
# reason that has nothing to do with the revision.
RUN git config --global --add safe.directory /build || true
# Resolve the revision HERE rather than leaving it to build.rs's
# rerun-if-changed. That mechanism is correct in a working tree and unreliable
# in a layer cache: cargo may reuse a cached build-script result while still
# recompiling the crate, which republishes an OLD sha on NEW code. That is
# exactly what happened — /health served a v3 build string from a v4 binary,
# and a stale deploy stamp is worse than no stamp because it is what someone
# reads first while diagnosing an incident.
#
# `unknown` when git is unreachable, never a guess. An honest blank beats a
# confident wrong sha, which is the same rule the ledger applies to coordinates.
RUN CC_BUILD_REV="${CC_BUILD_REV:-${RAILWAY_GIT_COMMIT_SHA:-$(git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)}}" \
    && CC_BUILD_REV="$(printf %.12s "$CC_BUILD_REV")" \
    && export CC_BUILD_REV \
    && echo "building revision ${CC_BUILD_REV}" \
    && cargo build --locked --release -p cc-node --bin cc-node \
    && cargo build --locked --release -p cc-anchor --bin cc-anchor-tick \
    && cargo build --locked --release -p cc-migrator --bin cc-migrator \
    && cargo build --locked --release -p cc-publisher --bin cc-publisher

# --- runtime ---------------------------------------------------------------
FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates python3 python3-jsonschema python3-cryptography python3-psycopg \
    && rm -rf /var/lib/apt/lists/*
# Never root: the node's whole job is refusing unauthorized writes, and a
# container that can rewrite its own filesystem weakens that for no benefit.
RUN groupadd -r clockchain && useradd -r -g clockchain -d /app -s /sbin/nologin clockchain
WORKDIR /app
COPY --from=builder /build/target/release/cc-node /usr/local/bin/cc-node
# The scheduled seal/anchor driver. It ships in the same image so a cron tick
# runs the SAME build as the node — a tick from a different build could seal a
# root under a different filter version than the node serves.
COPY --from=builder /build/target/release/cc-anchor-tick /usr/local/bin/cc-anchor-tick
# The sanctioned writer. It ships here because there is no raw-insert bypass:
# genesis and any replay must go through `Signed::sign` + `cc_ledger::commit`,
# the same path every other writer uses. Without this binary in the image the
# only way to seed a chain whose database has no public route is to write rows
# by hand, which is exactly the bypass the design refuses to have.
COPY --from=builder /build/target/release/cc-migrator /usr/local/bin/cc-migrator
COPY --from=builder /build/target/release/cc-publisher /usr/local/bin/cc-publisher
# Migrations are embedded in the binary; the dir is copied for operator use
# (e.g. `cc-node migrate` and manual inspection).
COPY --from=builder /build/migrations /app/migrations
COPY --from=builder /build/ops/model_policy.py /build/ops/model_runtime.py /build/ops/model_transport.py /build/ops/model_catalog.py /build/ops/model_evaluate.py /build/ops/local_generate.py /build/ops/corpus_audit.py /build/ops/generation_worker.py /app/ops/
COPY --from=builder /build/vendor/tt /app/vendor/tt
USER clockchain
EXPOSE 8080
CMD ["cc-node"]
