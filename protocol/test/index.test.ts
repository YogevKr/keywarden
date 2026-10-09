import assert from "node:assert/strict";
import test from "node:test";
import {
  canonicalize,
  decryptWithPrivateKey,
  encryptForPublicKey,
  exportPrivateKey,
  exportPublicKey,
  generateEncryptionKeyPair,
  generateSigningKeyPair,
  hashRequest,
  importEncryptionPrivateKey,
  signEnvelope,
  verifyEnvelope,
} from "../src/index.ts";

test("canonicalization sorts object keys", () => {
  assert.equal(canonicalize({ b: 2, a: 1 }), '{"a":1,"b":2}');
});

test("P-256 envelope encrypts and decrypts", async () => {
  const keys = await generateEncryptionKeyPair();
  const publicKey = await exportPublicKey(keys.publicKey);
  const payload = await encryptForPublicKey("secret stays local", publicKey);
  const privateKey = await importEncryptionPrivateKey(await exportPrivateKey(keys.privateKey));
  assert.equal(await decryptWithPrivateKey(payload, privateKey), "secret stays local");
});

test("signed envelopes verify", async () => {
  const signing = await generateSigningKeyPair();
  const encryption = await generateEncryptionKeyPair();
  const body = await encryptForPublicKey("request", await exportPublicKey(encryption.publicKey));
  const envelope = await signEnvelope("session_request", body, signing.privateKey, await exportPublicKey(signing.publicKey));
  assert.equal(await verifyEnvelope(envelope), true);
  envelope.signature = `${envelope.signature}x`;
  assert.equal(await verifyEnvelope(envelope), false);
});

test("request hashes remain stable", async () => {
  const request = {
    version: 1 as const,
    type: "open_session" as const,
    id: "req_1",
    agent: "codex",
    host: "MacBook",
    phoneId: "phone_1",
    reason: "test",
    scope: { accounts: ["agent" as const], vaults: ["agents"], items: "all" as const, operations: ["read" as const] },
    durationSeconds: 60,
    idleTimeoutSeconds: 30,
    createdAt: "2026-10-06T00:00:00.000Z",
    expiresAt: "2026-10-06T00:01:00.000Z",
    nonce: "nonce",
  };
  assert.equal(await hashRequest(request), await hashRequest({ ...request, scope: { ...request.scope } }));
});
