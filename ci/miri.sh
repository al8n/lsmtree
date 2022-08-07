#!/bin/bash
set -e

rustup toolchain install nightly --component miri
rustup override set nightly
cargo miri setup

export MIRIFLAGS="-Zmiri-strict-provenance -Zmiri-disable-isolation -Zmiri-allow-communication"

cargo miri test --no-default-features --target x86_64-unknown-linux-gnu
cargo miri test --no-default-features --target aarch64-unknown-linux-gnu
cargo miri test --no-default-features --target i686-unknown-linux-gnu
cargo miri test --no-default-features --target powerpc64-unknown-linux-gnu