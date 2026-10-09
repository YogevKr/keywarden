#!/bin/sh
set -eu

relay_url=${KEYWARDEN_E2E_RELAY_URL:?Set KEYWARDEN_E2E_RELAY_URL for the deployed relay}

opgate op --profile agent -- read 'op://agents/Keywarden Relay Token/password' |
  KEYWARDEN_E2E_RELAY_URL="$relay_url" \
  KEYWARDEN_E2E_REAL_OPGATE=1 \
  KEYWARDEN_E2E_BROKER_EXEC=apps/broker-rs/target/debug/keywarden-broker \
  node -e '
    let token = "";
    process.stdin.on("data", (chunk) => { token += chunk; });
    process.stdin.on("end", () => {
      const env = { ...process.env, KEYWARDEN_E2E_RELAY_TOKEN: token.trim() };
      const child = require("node:child_process").spawn(
        process.execPath,
        ["--experimental-strip-types", "scripts/e2e-worker.ts"],
        { env, stdio: "inherit" },
      );
      child.on("exit", (code) => process.exit(code ?? 1));
    });
  '
