# Image for the public read gateway (cc-gateway). NOT DEPLOYED; see
# docs/PUBLIC-ACCESS.md.
#
# Build context is the repo root, so the root deny-by-default .dockerignore
# applies. Do not add a Dockerfile.dockerignore next to this file: BuildKit
# would use it in place of the root one.

# --- builder ---------------------------------------------------------------
# Keep this tag in step with `rust-toolchain.toml` and the root Dockerfile.
FROM rust:1.97-slim-bookworm AS builder
# rustls only, so no libssl-dev; pkg-config is kept, as in the root image, for
# any transitive build script that probes for it.
RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY . .
# The gateway alone. It has no cc-node, cc-ledger or sqlx dependency and no
# build script, so the build needs no database and no git revision.
RUN cargo build --locked --release -p cc-gateway --bin cc-gateway

# --- runtime ---------------------------------------------------------------
FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
# Never root: the process holds the node read key and nothing else.
RUN groupadd -r gateway && useradd -r -g gateway -d /app -s /sbin/nologin gateway
WORKDIR /app
COPY --from=builder /build/target/release/cc-gateway /usr/local/bin/cc-gateway
USER gateway
EXPOSE 8080
CMD ["cc-gateway"]
