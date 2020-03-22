#!/bin/bash

# Install and update dependencies
rustup update
rustup component add clippy
cargo install cargo-audit
cargo install --force cargo-outdated
cargo update

# Clean
cargo clean

# Check dependencies
cargo outdated
cargo audit

# Format and check code
cargo fix
cargo fmt
cargo clippy -- -D clippy::pedantic -D clippy::cargo -D clippy::all -W clippy::nursery

# Build
cargo build --release
