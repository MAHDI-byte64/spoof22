# freespoof — common developer tasks.
# Human docs are in Persian (README.md); this Makefile stays English.

CARGO ?= cargo
NATIVE_RUSTFLAGS := -C target-cpu=native

.PHONY: all build release native test fmt fmt-check clippy check \
        musl aarch64 docker fuzz bench clean setcap install

all: check

build:
	$(CARGO) build

release:
	$(CARGO) build --release

# Release build with host-native CPU features (AVX2/AVX-512). NOT portable.
native:
	RUSTFLAGS="$(NATIVE_RUSTFLAGS)" $(CARGO) build --release

test:
	$(CARGO) test --all

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all -- --check

clippy:
	$(CARGO) clippy --all-targets -- -D warnings

# The full CI gate.
check: fmt-check clippy test

# Static musl build (no glibc).
musl:
	rustup target add x86_64-unknown-linux-musl
	$(CARGO) build --release --target x86_64-unknown-linux-musl

aarch64:
	rustup target add aarch64-unknown-linux-musl
	$(CARGO) build --release --target aarch64-unknown-linux-musl

# Optional io_uring send backend (Linux).
io-uring:
	$(CARGO) build --release --features io_uring

docker:
	docker build -t freespoof -f deploy/Dockerfile .

# Fuzz the packet parsers (needs nightly + cargo-fuzz).
fuzz:
	cd fuzz && cargo +nightly fuzz run parse_frame

bench:
	$(CARGO) bench

# Grant the caps so freespoof can run unprivileged.
setcap:
	sudo setcap cap_net_raw,cap_net_admin+ep ./target/release/freespoof

# Install locally from this checkout (build + copy to /usr/local/bin + setcap).
# For remote one-line installs use scripts/install.sh (see README). Needs root.
install: release
	install -d /usr/local/bin
	install -m0755 target/release/freespoof target/release/freespoof-client target/release/freespoof-server /usr/local/bin/
	command -v setcap >/dev/null 2>&1 && setcap cap_net_raw,cap_net_admin+ep /usr/local/bin/freespoof || true
	@echo "نصب شد. برای پیکربندی: sudo bash scripts/freespoof-manager.sh"

clean:
	$(CARGO) clean
