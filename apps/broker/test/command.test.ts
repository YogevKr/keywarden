import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { commandTarget } from "../src/command.ts";
import { SessionStore } from "../src/session.ts";
import type { OperationRequest } from "../../../protocol/src/index.ts";

const cases = JSON.parse(await readFile(new URL("../../../protocol/test/command-cases.json", import.meta.url), "utf8")) as { name: string; valid: boolean; operation: OperationRequest }[];
for (const fixture of cases) {
  test(`command scope: ${fixture.name}`, () => {
    if (fixture.valid) assert.doesNotThrow(() => commandTarget(fixture.operation));
    else assert.throws(() => commandTarget(fixture.operation));
  });
}

test("an item lease checks the executed target even without a declared item", async () => {
  const store = new SessionStore();
  const pending = await store.createRequest({agent: "test", host: "test", phoneId: "test", reason: "test", scope: {accounts: ["agent"], vaults: ["agents"], items: ["item-1"], operations: ["read", "list"]}, durationSeconds: 60, idleTimeoutSeconds: 30});
  const lease = store.approve(pending.request.id, {version: 1, type: "approval_decision", requestId: pending.request.id, requestHash: pending.requestHash, decision: "approve", decidedAt: new Date().toISOString(), nonce: "test"});
  const operation: OperationRequest = {version: 1, leaseId: lease.id, profile: "agent", operation: "read", vault: "agents", args: ["item", "get", "item-2", "--vault", "agents"]};
  assert.throws(() => store.authorize(operation), /Item/);
  assert.throws(() => store.authorize({...operation, operation: "list", args: ["item", "list", "--vault", "agents"]}), /Item/);
  operation.args[2] = "item-1";
  assert.equal(store.authorize(operation).id, lease.id);
});
