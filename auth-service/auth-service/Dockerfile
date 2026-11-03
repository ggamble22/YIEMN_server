# syntax=docker/dockerfile:1.7

# ---- Base with cargo-chef for dependency-layer caching ----
FROM rust:1-slim-bookworm AS chef
RUN cargo install cargo-chef --locked
WORKDIR /app

# ---- Compute the dependency "recipe" (changes only when Cargo.toml/lock change) ----
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ---- Build deps (cached), then the app ----
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release --bin auth-service

# ---- Minimal runtime: no shell, no package manager, runs as non-root ----
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=builder /app/target/release/auth-service /usr/local/bin/auth-service
USER nonroot:nonroot
EXPOSE 8080 9090
ENTRYPOINT ["/usr/local/bin/auth-service"]
