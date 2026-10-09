#!/bin/sh
set -eu
keywarden_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
keywarden_bin="$HOME/.local/bin/keywarden"
keywarden_share="$HOME/.local/share/keywarden"
if [ -e "$keywarden_bin" ] && [ ! -f "$keywarden_share/install-source" ]; then
  echo 'An existing keywarden command has no installation record. Review it before replacing it.' >&2
  exit 1
fi
if [ -f "$keywarden_share/install-source" ] && [ "$(cat "$keywarden_share/install-source")" != "$keywarden_root" ]; then
  echo 'The existing installation belongs to another checkout.' >&2
  exit 1
fi
RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$HOME=/build" cargo build --release --manifest-path "$keywarden_root/apps/broker-rs/Cargo.toml"
mkdir -p "$HOME/.local/bin" "$keywarden_share"
install -m 755 "$keywarden_root/apps/broker-rs/target/release/keywarden-broker" "$keywarden_bin"
install -m 644 "$keywarden_root/scripts/keywarden-qr.swift" "$keywarden_share/keywarden-qr.swift"
printf '%s\n' "$keywarden_root" > "$keywarden_share/install-source"
printf 'Installed %s\n' "$keywarden_bin"
