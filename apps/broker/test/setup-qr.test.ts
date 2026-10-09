import assert from "node:assert/strict";
import { inflateRawSync } from "node:zlib";
import test from "node:test";
import { encodeSetupQr } from "../src/setup-qr.ts";

test("setup QR uses raw DEFLATE for the iOS Compression decoder", () => {
  const value = encodeSetupQr({
    relayURL: "https://relay.example",
    relayToken: "relay-token",
    brokerId: "broker-1",
    phoneId: "phone-1",
    pairingToken: "pair-1",
    signingPublicKey: ["signing-x", "signing-y"],
    encryptionPublicKey: ["encryption-x", "encryption-y"],
  });

  assert.match(value, /^kw2:/);
  const encoded = value.slice(4).replaceAll("-", "+").replaceAll("_", "/");
  const compressed = Buffer.from(encoded + "=".repeat((4 - encoded.length % 4) % 4), "base64");
  const compact = JSON.parse(inflateRawSync(compressed).toString("utf8")) as Record<string, unknown>;
  assert.deepEqual(compact, {
    r: "https://relay.example",
    t: "relay-token",
    b: "broker-1",
    p: "phone-1",
    q: "pair-1",
    s: ["signing-x", "signing-y"],
    e: ["encryption-x", "encryption-y"],
  });
});
