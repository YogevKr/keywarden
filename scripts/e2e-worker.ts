import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { spawn, type ChildProcess } from "node:child_process";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import {
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
} from "../protocol/src/index.ts";
import type { JsonValue, SignedEnvelope } from "../protocol/src/index.ts";

const relayURL = (process.env.KEYWARDEN_E2E_RELAY_URL ?? "http://127.0.0.1:8787").replace(/\/$/, "");
const relayToken = process.env.KEYWARDEN_E2E_RELAY_TOKEN ?? "relay-test-token";

interface RelayEntry {
  requestId: string;
  phoneId: string;
  expiresAt: string;
  envelope: SignedEnvelope;
}

async function main(): Promise<void> {
  const directory = await mkdtemp(join(tmpdir(), "keywarden-worker-e2e-"));
  const socketPath = join(directory, "broker.sock");
  const fakeOp = join(directory, "op");
  const realOpgate = process.env.KEYWARDEN_E2E_REAL_OPGATE === "1";
  const realOperation = process.env.KEYWARDEN_E2E_REAL_OPERATION ?? (realOpgate ? "list" : "read");
  const realItemId = process.env.KEYWARDEN_E2E_ITEM_ID;
  let broker: ChildProcess | undefined;
  try {
    await checkRelay();
    if (!realOpgate) {
      await writeFile(
        fakeOp,
        "#!/bin/sh\n" +
          "[ \"$OP_SERVICE_ACCOUNT_TOKEN\" = service-token ] || exit 17\n" +
          'if [ "$1 $2" = "vault get" ]; then printf \'{"id":"agents","name":"agents"}\'; exit 0; fi\n' +
          "printf 'fake-op-ok:%s' \"$*\"\n",
        { mode: 0o700 },
      );
      await chmod(fakeOp, 0o700);
    }

    const phoneSigning = await generateSigningKeyPair();
    const phoneEncryption = await generateEncryptionKeyPair();
    const phoneSigningPublic = await exportPublicKey(phoneSigning.publicKey);
    const phoneEncryptionPublic = await exportPublicKey(phoneEncryption.publicKey);
    const brokerExecutable = process.env.KEYWARDEN_E2E_BROKER_EXEC ?? process.execPath;
    const brokerArguments = process.env.KEYWARDEN_E2E_BROKER_EXEC
      ? ["serve", "--token-stdin"]
      : ["--experimental-strip-types", fileURLToPath(new URL("../apps/broker/src/index.ts", import.meta.url)), "serve", "--token-stdin"];
    broker = spawn(
      brokerExecutable,
      brokerArguments,
      {
        env: {
          ...process.env,
          KEYWARDEN_STATE_DIR: join(directory, "state"),
          KEYWARDEN_SOCKET: socketPath,
          ...(realOpgate ? { KEYWARDEN_OPGATE_PROFILE: "agent", KEYWARDEN_OP_BIN: "opgate" } : { KEYWARDEN_OP_BIN: fakeOp }),
          KEYWARDEN_RELAY_URL: relayURL,
          KEYWARDEN_RELAY_TOKEN: relayToken,
          KEYWARDEN_PHONE_ID: undefined,
          KEYWARDEN_PHONE_SIGNING_PUBLIC_JWK: undefined,
          KEYWARDEN_PHONE_ENCRYPTION_PUBLIC_JWK: undefined,
        },
        stdio: ["pipe", "ignore", "pipe"],
      },
    );
    const errors: Buffer[] = [];
    broker.stderr?.on("data", (chunk: Buffer) => errors.push(chunk));
    broker.stdin?.end("service-token\n");

    await waitForSocket(socketPath);
    const identity = await socketJSON<{ brokerId: string; encryptionPublicJwk: JsonValue }>(socketPath, "GET", "/v1/identity");
    const pairingToken = "synthetic-qr-challenge";
    await writeFile(join(directory, "state", "pairing-setup.json"), JSON.stringify({version: 1, type: "keywarden_setup", brokerId: identity.brokerId, phoneId: "phone-1", pairingToken, createdAt: new Date().toISOString()}), {mode: 0o600});
    const pairingBody = await encryptForPublicKey(JSON.stringify({phoneId:"phone-1",pairingToken,signingPublicJwk:phoneSigningPublic,encryptionPublicJwk:phoneEncryptionPublic}), identity.encryptionPublicJwk);
    const pairingEnvelope = await signEnvelope("phone_pairing", pairingBody, phoneSigning.privateKey, phoneSigningPublic);
    assert.ok(!JSON.stringify(pairingEnvelope).includes(pairingToken));
    const pairingResponse = await fetch(`${relayURL}/v1/brokers/${identity.brokerId}/pairing`, {method:"POST",headers:{authorization:`Bearer ${relayToken}`,"content-type":"application/json"},body:JSON.stringify({phoneId:"phone-1",envelope:pairingEnvelope})});
    assert.equal(pairingResponse.status,200);
    const pending = await socketJSON<{ request: { id: string }; requestHash: string }>(socketPath, "POST", "/v1/session-requests", {
      agent: "codex",
      host: "MacBook",
      phoneId: "phone-1",
      reason: "Cloudflare Worker end to end test",
      scope: {
        accounts: ["agent"],
        vaults: ["agents"],
        items: realOpgate && realOperation === "read" && realItemId ? [realItemId] : "all",
        operations: [realOpgate ? realOperation : "read"],
      },
      durationSeconds: 30,
      idleTimeoutSeconds: 10,
    });

    const relayEntry = await waitForRelayRequest(identity.brokerId, pending.request.id);
    assert.equal(await verifyEnvelope(relayEntry.envelope), true);
    assert.doesNotMatch(JSON.stringify(relayEntry), /service-token/);
    const phonePrivateKey = await importEncryptionPrivateKey(await exportPrivateKey(phoneEncryption.privateKey));
    const request = JSON.parse(await decryptWithPrivateKey(relayEntry.envelope.body, phonePrivateKey)) as { id: string; scope: { vaults: string[]; items: string | string[] } };
    assert.deepEqual(request.scope.vaults, ["agents"]);
    if (realOpgate && realOperation === "read" && realItemId) assert.deepEqual(request.scope.items, [realItemId]);
    else assert.equal(request.scope.items, "all");
    assert.equal(await hashRequest(request as never), pending.requestHash);

    const decision = {
      version: 1 as const,
      type: "approval_decision" as const,
      requestId: request.id,
      requestHash: pending.requestHash,
      decision: "approve" as const,
      decidedAt: new Date().toISOString(),
      nonce: "worker-e2e-decision",
    };
    const decisionBody = await encryptForPublicKey(JSON.stringify(decision), identity.encryptionPublicJwk);
    const decisionEnvelope = await signEnvelope("approval_decision", decisionBody, phoneSigning.privateKey, phoneSigningPublic);
    const decisionResponse = await fetch(`${relayURL}/v1/brokers/${encodeURIComponent(identity.brokerId)}/phones/phone-1/requests/${encodeURIComponent(request.id)}/decision`, {
      method: "POST",
      headers: { authorization: `Bearer ${relayToken}`, "content-type": "application/json" },
      body: JSON.stringify(decisionEnvelope),
    });
    assert.equal(decisionResponse.status, 200);

    const approved = await waitForStatus(socketPath, request.id, "approved");
    assert.ok(approved.leaseId);
    const operation = await socketJSON<{ exitCode: number; stdout: string }>(socketPath, "POST", "/v1/operations", {
      version: 1,
      leaseId: approved.leaseId,
      profile: "agent",
      operation: realOpgate ? realOperation : "read",
      vault: "agents",
      ...(realOpgate && realOperation === "read" && realItemId ? { itemId: realItemId } : (!realOpgate ? { itemId: "item-1" } : {})),
      args: realOpgate && realOperation === "read" && realItemId
        ? ["item", "get", "--vault", "agents", realItemId, "--format", "json"]
        : realOpgate
          ? ["item", "list", "--vault", "agents", "--format", "json"]
          : ["item", "get", "--vault", "agents", "item-1"],
    });
    assert.equal(operation.exitCode, 0);
    if (realOpgate && realOperation === "read" && realItemId) {
      const item = JSON.parse(operation.stdout) as { id?: string; title?: string };
      assert.equal(item.id, realItemId);
      assert.equal(item.title, "Keywarden Pilot Test Item");
      await assert.rejects(
        socketJSON(socketPath, "POST", "/v1/operations", {
          version: 1,
          leaseId: approved.leaseId,
          profile: "agent",
          operation: "read",
          vault: "agents",
          itemId: "not-approved-item",
          args: ["item", "get", "--vault", "agents", "not-approved-item", "--format", "json"],
        }),
        /Item is outside/,
      );
    } else if (realOpgate) {
      const listed = JSON.parse(operation.stdout) as unknown;
      assert.ok(Array.isArray(listed));
    } else {
      assert.equal(operation.stdout, "fake-op-ok:item get --vault agents item-1");
    }
    const revokeBody = await encryptForPublicKey(JSON.stringify({version:1,type:"session_revoke",requestId:request.id,requestHash:pending.requestHash,decidedAt:new Date().toISOString(),nonce:"worker-revocation"}),identity.encryptionPublicJwk);
    const revokeEnvelope = await signEnvelope("session_revoke",revokeBody,phoneSigning.privateKey,phoneSigningPublic);
    const revoke = await fetch(`${relayURL}/v1/brokers/${identity.brokerId}/requests/${request.id}/revocation`,{method:"POST",headers:{authorization:`Bearer ${relayToken}`,"content-type":"application/json"},body:JSON.stringify(revokeEnvelope)});
    assert.equal(revoke.status,200);
    let revoked=false;
    for(let attempt=0;attempt<100;attempt++){
      const response=await fetch(`${relayURL}/v1/brokers/${identity.brokerId}/requests/${request.id}/status`,{headers:{authorization:`Bearer ${relayToken}`}});
      if(response.ok){
        const {envelope}=await response.json() as {envelope:SignedEnvelope};
        assert.equal(await verifyEnvelope(envelope),true);
        const state=JSON.parse(await decryptWithPrivateKey(envelope.body,phonePrivateKey));
        if(state.status==="revoked"){revoked=true;break;}
      }
      await sleep(100);
    }
    assert.equal(revoked,true,"Broker must confirm remote revocation");

    assert.equal(errors.join(""), "");
    console.log(JSON.stringify({ ok: true, relayURL, brokerId: identity.brokerId, requestId: request.id, operation: realOpgate ? realOperation : "read", itemId: realItemId, tokenSentToRelay: false, realOpgate }));
  } finally {
    broker?.kill("SIGTERM");
    await closeChild(broker);
    await rm(directory, { recursive: true, force: true });
  }
}

async function checkRelay(): Promise<void> {
  const response = await fetch(`${relayURL}/health`);
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { ok: true });
}

async function waitForRelayRequest(brokerId: string, requestId: string): Promise<RelayEntry> {
  for (let attempt = 0; attempt < 120; attempt += 1) {
    const response = await fetch(`${relayURL}/v1/brokers/${encodeURIComponent(brokerId)}/phones/phone-1/requests`, { headers: { authorization: `Bearer ${relayToken}` } });
    assert.equal(response.status, 200);
    const body = await response.json() as { requests: RelayEntry[] };
    const entry = body.requests.find((item) => item.requestId === requestId);
    if (entry) return entry;
    await sleep(50);
  }
  throw new Error("Worker did not return the pending request");
}

async function waitForStatus(socketPath: string, requestId: string, expected: string): Promise<{ leaseId?: string }> {
  for (let attempt = 0; attempt < 120; attempt += 1) {
    const status = await socketJSON<{ status: string; leaseId?: string }>(socketPath, "GET", `/v1/session-requests/${encodeURIComponent(requestId)}`);
    if (status.status === expected) return status;
    await sleep(50);
  }
  throw new Error(`Request did not reach ${expected}`);
}

async function waitForSocket(socketPath: string): Promise<void> {
  for (let attempt = 0; attempt < 120; attempt += 1) {
    try {
      await socketJSON(socketPath, "GET", "/health");
      return;
    } catch {
      await sleep(25);
    }
  }
  throw new Error("Broker socket did not start");
}

async function socketJSON<T = unknown>(socketPath: string, method: string, path: string, body?: unknown): Promise<T> {
  return new Promise((resolve, reject) => {
    const bodyText = body === undefined ? undefined : JSON.stringify(body);
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (bodyText !== undefined) headers["content-length"] = String(Buffer.byteLength(bodyText));
    const request = httpRequest({ socketPath, path, method, headers }, (response) => {
      const chunks: Buffer[] = [];
      response.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
      response.on("end", () => {
        const text = Buffer.concat(chunks).toString("utf8");
        let parsed: any;
        try { parsed = text ? JSON.parse(text) : {}; } catch (error) { reject(new Error(`${method} ${path}: ${error instanceof Error ? error.message : String(error)}; body=${JSON.stringify(text)}`)); return; }
        if ((response.statusCode ?? 500) >= 400) reject(new Error(`${method} ${path} HTTP ${response.statusCode}: ${parsed.error ?? text}`));
        else resolve(parsed as T);
      });
    });
    request.on("error", reject);
    if (bodyText !== undefined) request.write(bodyText);
    request.end();
  });
}

function closeChild(child: ChildProcess | undefined): Promise<void> {
  if (!child || child.exitCode !== null) return Promise.resolve();
  return new Promise((resolve) => child.once("exit", () => resolve()));
}

function sleep(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

void main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.stack ?? error.message : String(error)}\n`);
  process.exitCode = 1;
});
