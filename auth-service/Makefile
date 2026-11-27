.PHONY: run run-memory run-https test lint fmt docker up down

run-memory: ## Run with no dependencies (in-memory store)
	STORAGE_BACKEND=memory PHOTO_STORAGE=memory PHOTO_MODERATION=off LOG_FORMAT=pretty \
	JWT_SECRET=local-dev-secret-change-me-at-least-32-bytes \
	cargo run

run-https: ## Like run-memory, but HTTPS on https://localhost:8443 (self-signed)
	STORAGE_BACKEND=memory PHOTO_STORAGE=memory PHOTO_MODERATION=off LOG_FORMAT=pretty \
	TLS_SELF_SIGNED=true \
	JWT_SECRET=local-dev-secret-change-me-at-least-32-bytes \
	cargo run

up: ## Full local stack: DynamoDB Local + service
	docker compose up --build

down:
	docker compose down

test:
	cargo test --all-targets

lint:
	cargo fmt --all -- --check
	cargo clippy --all-targets -- -D warnings

fmt:
	cargo fmt --all

docker:
	docker build -t auth-service:dev .
