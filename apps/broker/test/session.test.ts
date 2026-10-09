import assert from "node:assert/strict";
import test from "node:test";
import { SessionStore } from "../src/session.ts";

const scope = {
  accounts: ["agent" as const],
  vaults: ["agents"],
  items: "all" as const,
  operations: ["read" as const, "write" as const],
};

test("approved lease permits operations inside its scope", async () => {
  const store = new SessionStore();
  const pending = await store.createRequest({
    agent: "codex",
    host: "MacBook",
    phoneId: "phone-1",
    reason: "test",
    scope,
    durationSeconds: 300,
    idleTimeoutSeconds: 60,
  });
  const lease = store.approve(pending.request.id, {
    version: 1,
    type: "approval_decision",
    requestId: pending.request.id,
    requestHash: pending.requestHash,
    decision: "approve",
    decidedAt: new Date().toISOString(),
    nonce: "decision",
  });
  assert.equal(store.authorize({ version: 1, leaseId: lease.id, profile: "agent", operation: "read", vault: "agents", args: ["item", "get", "item-1", "--vault", "agents"] }).id, lease.id);
});

test("lease rejects an account, vault, or operation outside its scope", async () => {
  const store = new SessionStore();
  const pending = await store.createRequest({
    agent: "codex",
    host: "MacBook",
    phoneId: "phone-1",
    reason: "test",
    scope,
    durationSeconds: 300,
    idleTimeoutSeconds: 60,
  });
  const lease = store.approve(pending.request.id, {
    version: 1,
    type: "approval_decision",
    requestId: pending.request.id,
    requestHash: pending.requestHash,
    decision: "approve",
    decidedAt: new Date().toISOString(),
    nonce: "decision",
  });
  assert.throws(() => store.authorize({ version: 1, leaseId: lease.id, profile: "work", operation: "read", vault: "agents", args: ["item", "get", "item-1", "--vault", "agents"] }), /Account/);
  assert.throws(() => store.authorize({ version: 1, leaseId: lease.id, profile: "agent", operation: "read", vault: "work", args: [] }), /Vault/);
  assert.throws(() => store.authorize({ version: 1, leaseId: lease.id, profile: "agent", operation: "delete", vault: "agents", args: [] }), /Operation/);
  assert.throws(() => store.authorize({ version: 1, leaseId: lease.id, profile: "agent", operation: "read", vault: "agents", args: ["item", "edit"] }), /Command/);
});

test("item scopes reject an unlisted item", async () => {
  const store = new SessionStore();
  const pending = await store.createRequest({
    agent: "codex", host: "MacBook", phoneId: "phone-1", reason: "test",
    scope: { ...scope, items: ["item-1"] }, durationSeconds: 300, idleTimeoutSeconds: 60,
  });
  const lease = store.approve(pending.request.id, {
    version: 1, type: "approval_decision", requestId: pending.request.id,
    requestHash: pending.requestHash, decision: "approve", decidedAt: new Date().toISOString(), nonce: "decision",
  });
  assert.throws(() => store.authorize({ version: 1, leaseId: lease.id, profile: "agent", operation: "read", vault: "agents", itemId: "item-2", args: ["item", "get", "item-2", "--vault", "agents"] }), /Item/);
});

test("approval cannot change the requested scope", async () => {
  const store = new SessionStore();
  const pending = await store.createRequest({
    agent: "codex",
    host: "MacBook",
    phoneId: "phone-1",
    reason: "test",
    scope,
    durationSeconds: 300,
    idleTimeoutSeconds: 60,
  });
  assert.throws(() => store.approve(pending.request.id, {
    version: 1,
    type: "approval_decision",
    requestId: pending.request.id,
    requestHash: `${pending.requestHash}tampered`,
    decision: "approve",
    decidedAt: new Date().toISOString(),
    nonce: "decision",
  }), /match/);
});

test("personal and work accounts are valid session scopes", async () => {
  const store = new SessionStore();
  for (const account of ["personal", "work"] as const) {
    const pending = await store.createRequest({
      agent: "codex", host: "MacBook", phoneId: "phone-1", reason: "test",
      scope: { accounts: [account], vaults: [account === "personal" ? "Keywarden Personal" : "Example Work"], items: "all", operations: ["read"] },
      durationSeconds: 300, idleTimeoutSeconds: 60,
    });
    const lease = store.approve(pending.request.id, {
      version: 1, type: "approval_decision", requestId: pending.request.id,
      requestHash: pending.requestHash, decision: "approve", decidedAt: new Date().toISOString(), nonce: "decision",
    });
    assert.equal(store.authorize({ version: 1, leaseId: lease.id, profile: account, operation: "read", vault: pending.request.scope.vaults[0], args: ["item", "get", "item-1", "--vault", pending.request.scope.vaults[0]] }).id, lease.id);
  }
});

test("all-vault sessions authorize a target vault", async () => {
  const store = new SessionStore();
  const pending = await store.createRequest({
    agent: "codex", host: "MacBook", phoneId: "phone-1", reason: "test",
    scope: { accounts: ["personal"], vaults: ["*"], items: "all", operations: ["read"] },
    durationSeconds: 300, idleTimeoutSeconds: 60,
  });
  const lease = store.approve(pending.request.id, {
    version: 1, type: "approval_decision", requestId: pending.request.id,
    requestHash: pending.requestHash, decision: "approve", decidedAt: new Date().toISOString(), nonce: "decision",
  });
  assert.equal(store.authorize({ version: 1, leaseId: lease.id, profile: "personal", operation: "read", vault: "Example Work", args: ["item", "get", "item-1", "--vault", "Example Work"] }).id, lease.id);
});

test("an operation can use the only matching lease without its ID or account", async () => {
  const store = new SessionStore();
  const pending = await store.createRequest({
    agent: "codex", host: "MacBook", phoneId: "phone-1", reason: "test",
    scope: { accounts: ["personal"], vaults: ["*"], items: "all", operations: ["read"] },
    durationSeconds: 300, idleTimeoutSeconds: 60,
  });
  store.approve(pending.request.id, {
    version: 1, type: "approval_decision", requestId: pending.request.id,
    requestHash: pending.requestHash, decision: "approve", decidedAt: new Date().toISOString(), nonce: "decision",
  });
  assert.doesNotThrow(() => store.authorize({ version: 1, leaseId: "active", profile: "auto", operation: "read", vault: "Keywarden Personal", args: ["item", "get", "item-1", "--vault", "Keywarden Personal"] }));
});
