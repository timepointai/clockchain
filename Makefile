# Clockchain v2 developer targets.
# A default DATABASE_URL matching .env.example lets every target work without a
# .env file; override on the command line, e.g. `make migrate DATABASE_URL=...`.
DATABASE_URL ?= postgres://clockchain:clockchain@localhost:5432/clockchain
TEST_DATABASE_URL ?= $(DATABASE_URL)
export DATABASE_URL
export TEST_DATABASE_URL

.PHONY: db-up db-down migrate run test fmt fmt-check lint check

db-up:
	docker compose up -d db

db-down:
	docker compose down -v

migrate:
	cargo run -p cc-node -- migrate

run:
	cargo run -p cc-node

test:
	cargo test

fmt:
	cargo fmt

fmt-check:
	cargo fmt --all -- --check

lint:
	cargo clippy --all-targets -- -D warnings

# The exact CI gate: formatting, lints-as-errors, and the real-DB test suite.
check: fmt-check lint test
