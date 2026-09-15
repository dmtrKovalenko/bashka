BIN := target/release/bashka
JS := node

.PHONY: build test corpus clippy fmt run-example validate clean next-version pin-installer

build:
	cargo build --release

# All unit + integration tests, including the filesystem corpus.
test:
	cargo test

# Just the benign/malicious fixture corpus (tests/fixtures/{benign,malicious}).
corpus:
	cargo test --test corpus -- --nocapture

clippy:
	cargo clippy --all-targets

fmt:
	cargo fmt

# Analyze one script without running it, e.g. `make check FILE=tests/fixtures/malicious/cryptominer.sh`
check: build
	$(BIN) --check < $(FILE)

# Run `bashka --check` over every installer in installers.toml and regenerate docs/validation.md.
# Scripts are cached in target/installers/ (delete to refresh) and never executed. Needs node or bun.
validate: build
	$(JS) scripts/validate_installers.js --markdown docs/validation.md

clean:
	cargo clean

# Release helpers used by .github/workflows/release.yml; runnable locally for a dry run.
next-version:
	scripts/next_version.sh

# Point install.sh at a release: `make pin-installer VERSION=0.3.0 BINARIES_DIR=./binaries`.
# Needs cargo-edit (`cargo install cargo-edit`) for `cargo set-version`.
pin-installer:
	@test -n "$(VERSION)" || (echo "usage: make pin-installer VERSION=0.3.0 BINARIES_DIR=./binaries" && exit 1)
	cargo set-version "$(VERSION)"
	scripts/pin_installer.sh "$(VERSION)" "$(BINARIES_DIR)"
