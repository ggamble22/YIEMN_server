# syntax=docker/dockerfile:1.7

# Source code is pulled straight from GitHub, so no local copy is needed:
#   docker build -t auth-service .                                  # main
#   docker build -t auth-service --build-arg GIT_REF=my-branch .    # a branch, tag or commit
# Docker re-checks the ref on every build and only rebuilds if the commit changed.
ARG GIT_REPO=https://github.com/ggamble22/YIEMN_server.git
ARG GIT_REF=main

# ---- Fetch the source ----
FROM scratch AS source
ARG GIT_REPO
ARG GIT_REF
ADD ${GIT_REPO}#${GIT_REF} /repo

# ---- Base with cargo-chef for dependency-layer caching ----
FROM rust:1-slim-bookworm AS chef
RUN cargo install cargo-chef --locked
WORKDIR /app

# ---- Compute the dependency "recipe" (changes only when Cargo.toml/lock change) ----
FROM chef AS planner
COPY --from=source /repo/auth-service/ .
RUN cargo chef prepare --recipe-path recipe.json

# ---- Build deps (cached), then the app ----
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY --from=source /repo/auth-service/ .
RUN cargo build --release --bin auth-service

# ---- Minimal runtime: no shell, no package manager, runs as non-root ----
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=builder /app/target/release/auth-service /usr/local/bin/auth-service
USER nonroot:nonroot
EXPOSE 8080 9090
ENTRYPOINT ["/usr/local/bin/auth-service"]
