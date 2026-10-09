import { createServer, request as httpRequest } from "node:http";
import { execFileSync } from "node:child_process";
import { chmod, mkdir, unlink } from "node:fs/promises";
import { dirname, join } from "node:path";
import {
  canonicalize,
  decryptWithPrivateKey,
  encryptForPublicKey,
  exportPublicKey,
  hashRequest,
  importEncryptionPrivateKey,
  randomId,
  signEnvelope,
  verifyEnvelope,
} from "../../../protocol/src/index.ts";
import type { ApprovalDecision, ClientMetadata, JsonValue, OpenSessionRequest, OperationRequest, SessionScope, SignedEnvelope } from "../../../protocol/src/index.ts";
import { clearPairingSetup, defaultStateDir, loadOrCreateIdentity, loadPairingSetup, loadPhonePairing, loadSigningPrivateKey, savePairingSetup, savePhonePairing } from "./identity.ts";
import type { PairingSetup, PhonePairing } from "./identity.ts";
import { getBrokerToken, runOpGate, setBrokerToken } from "./opgate.ts";
import { RelayClient } from "./relay.ts";
import { SessionStore } from "./session.ts";
import type { PendingRequest } from "./session.ts";
import { encodeSetupQr } from "./setup-qr.ts";

const DEFAULT_SOCKET = process.env.KEYWARDEN_SOCKET ?? "/Users/Shared/Keywarden/broker.sock";
const DEFAULT_RELAY_URL = "http://127.0.0.1:8787";
const DEFAULT_RELAY_TOKEN_REF = "op://agents/Keywarden Relay Token/password";

class Broker {
  readonly store = new SessionStore();
  readonly relay?: RelayClient;
  readonly identity;
  pairing?: PhonePairing;
  pairingSetup?: PairingSetup;
  readonly signingPrivateKey;
  readonly encryptionPrivateKey;

  private constructor(values: {
    identity: Awaited<ReturnType<typeof loadOrCreateIdentity>>;
    pairing?: PhonePairing;
    pairingSetup?: PairingSetup;
    signingPrivateKey: CryptoKey;
    encryptionPrivateKey: CryptoKey;
    relay?: RelayClient;
  }) {
    this.identity = values.identity;
    this.pairing = values.pairing;
    this.pairingSetup = values.pairingSetup;
    this.signingPrivateKey = values.signingPrivateKey;
    this.encryptionPrivateKey = values.encryptionPrivateKey;
    this.relay = values.relay;
  }

  static async create(): Promise<Broker> {
    const stateDir = defaultStateDir();
    const identity = await loadOrCreateIdentity(stateDir);
    const pairing = await loadPhonePairing(stateDir);
    const pairingSetup = await loadPairingSetup(stateDir);
    const relayUrl = process.env.KEYWARDEN_RELAY_URL;
    const relayToken = process.env.KEYWARDEN_RELAY_TOKEN ?? getBrokerToken();
    const relay = relayUrl && relayToken ? new RelayClient(relayUrl.replace(/\/$/, ""), relayToken) : undefined;
    return new Broker({
      identity,
      pairing,
      pairingSetup,
      signingPrivateKey: await loadSigningPrivateKey(identity),
      encryptionPrivateKey: await importEncryptionPrivateKey(identity.encryptionPrivateJwk),
      relay,
    });
  }

  async createSession(input: {
    agent: string;
    host: string;
    phoneId: string;
    reason: string;
    task?: string;
    client?: ClientMetadata;
    intent?: { task?: string | null; reason: string };
    scope: SessionScope;
    durationSeconds: number;
    idleTimeoutSeconds: number;
  }): Promise<PendingRequest> {
    await this.refreshPairing();
    const pending = await this.store.createRequest(input);
    if (!this.relay) return pending;
    if (!this.pairing) throw new Error("No phone pairing is configured");
    if (this.pairing.phoneId !== input.phoneId) throw new Error("Requested phone is not paired");
    const body = await encryptForPublicKey(JSON.stringify(pending.request), this.pairing.encryptionPublicJwk);
    const envelope = await signEnvelope("session_request", body, this.signingPrivateKey, this.identity.signingPublicJwk);
    await this.relay.submitRequest({
      brokerId: this.identity.brokerId,
      requestId: pending.request.id,
      phoneId: input.phoneId,
      expiresAt: pending.request.expiresAt,
      envelope,
    });
    void this.waitForDecision(pending).catch((error) => {
      process.stderr.write(`keywarden: approval wait failed: ${error instanceof Error ? error.message : String(error)}\n`);
    });
    return pending;
  }

  private async refreshPairing(): Promise<void> {
    if (!this.relay) return;
    this.pairingSetup = await loadPairingSetup();
    if (!this.pairingSetup) return;
    if (Date.now() - Date.parse(this.pairingSetup.createdAt) > 15 * 60 * 1000) {
      if (this.pairing) return;
      throw new Error("Setup QR expired. Create a fresh QR.");
    }
    const envelope = await this.relay.getPairing(this.identity.brokerId, this.pairingSetup.phoneId);
    if (!envelope) return;
    if (envelope.kind !== "phone_pairing" || !(await verifyEnvelope(envelope))) throw new Error("Invalid phone pairing signature");
    const received = JSON.parse(await decryptWithPrivateKey(envelope.body, this.encryptionPrivateKey)) as PhonePairing & {pairingToken: string};
    if (received.phoneId !== this.pairingSetup.phoneId || received.pairingToken !== this.pairingSetup.pairingToken || canonicalize(envelope.senderPublicKey) !== canonicalize(received.signingPublicJwk)) throw new Error("Pairing does not match setup QR");
    const paired: PhonePairing = {phoneId: received.phoneId, signingPublicJwk: received.signingPublicJwk, encryptionPublicJwk: received.encryptionPublicJwk};
    await savePhonePairing(paired);
    if (this.pairing?.phoneId !== paired.phoneId) for (const lease of this.store.leases.values()) this.store.revoke(lease.id);
    this.pairing = paired;
    await this.relay.acknowledgePairing(this.identity.brokerId, received.phoneId);
    await clearPairingSetup();
  }

  private async waitForDecision(pending: PendingRequest): Promise<void> {
    if (!this.relay || !this.pairing) return;
    while (pending.status === "pending" && new Date(pending.request.expiresAt).getTime() > Date.now()) {
      const envelope = await this.relay.getDecision(this.identity.brokerId, pending.request.id);
      if (envelope) {
        await this.acceptDecision(pending, envelope);
        await this.syncSession(pending);
        return;
      }
      await sleep(1000);
    }
    if (pending.status === "pending") pending.status = "expired";
  }

  async acceptDecision(pending: PendingRequest, envelope: SignedEnvelope): Promise<void> {
    if (!this.pairing) throw new Error("No phone pairing is configured");
    if (canonicalize(envelope.senderPublicKey) !== canonicalize(this.pairing.signingPublicJwk)) {
      throw new Error("Decision signer is not the paired phone");
    }
    if (!(await verifyEnvelope(envelope))) throw new Error("Decision signature is invalid");
    if (envelope.kind !== "approval_decision") throw new Error("Unexpected approval envelope kind");
    const decision = JSON.parse(await decryptWithPrivateKey(envelope.body, this.encryptionPrivateKey)) as ApprovalDecision;
    if (decision.requestId !== pending.request.id) throw new Error("Decision request ID does not match");
    if (decision.version !== 1 || decision.type !== "approval_decision" || decision.requestHash !== pending.requestHash) throw new Error("Invalid approval decision");
    if (decision.decision === "deny") {
      this.store.deny(pending.request.id);
      return;
    }
    this.store.approve(pending.request.id, decision);
  }

  private async syncSession(pending: PendingRequest): Promise<void> {
    if (!this.relay || !this.pairing) return;
    const deadline = Date.now() + (pending.request.durationSeconds + 60) * 1000;
    while (Date.now() < deadline) {
      try {
        const revoke = await this.relay.sessionEnvelope(this.identity.brokerId, pending.request.id, "revocation");
        if (revoke) {
          if (canonicalize(revoke.senderPublicKey) !== canonicalize(this.pairing.signingPublicJwk) || revoke.kind !== "session_revoke" || !(await verifyEnvelope(revoke))) throw new Error("Invalid revocation signature");
          const payload = JSON.parse(await decryptWithPrivateKey(revoke.body, this.encryptionPrivateKey));
          if (payload.version !== 1 || payload.type !== "session_revoke" || payload.requestId !== pending.request.id || payload.requestHash !== pending.requestHash) throw new Error("Invalid revocation request");
          if (pending.leaseId) this.store.revoke(pending.leaseId);
        }
        const status = this.store.status(pending);
        const body = await encryptForPublicKey(JSON.stringify(status), this.pairing.encryptionPublicJwk);
        const envelope = await signEnvelope("session_status", body, this.signingPrivateKey, this.identity.signingPublicJwk);
        await this.relay.sessionEnvelope(this.identity.brokerId, pending.request.id, "status", envelope);
        if (status.status !== "active") return;
      } catch {
        // Never silently leave remote access active when status/revocation is unavailable.
        if (pending.leaseId) this.store.revoke(pending.leaseId);
      }
      await sleep(3000);
    }
  }

  async approveForDevelopment(requestId: string): Promise<void> {
    if (process.env.KEYWARDEN_DEV_MODE !== "1") throw new Error("Development approval is disabled");
    const pending = this.store.requests.get(requestId);
    if (!pending) throw new Error("Unknown session request");
    const decision: ApprovalDecision = {
      version: 1,
      type: "approval_decision",
      requestId,
      requestHash: pending.requestHash,
      decision: "approve",
      decidedAt: new Date().toISOString(),
      nonce: randomId("dev_nonce"),
    };
    this.store.approve(requestId, decision);
  }

  async runOperation(operation: OperationRequest) {
    const resolved = this.store.resolveOperation(operation);
    this.store.authorize(resolved);
    return runOpGate(resolved.profile, resolved.args);
  }
}

async function main(): Promise<void> {
  const [command = "help", ...args] = process.argv.slice(2);
  if (command === "identity") {
    const identity = await loadOrCreateIdentity();
    const print = args.includes("--print");
    process.stdout.write(`${JSON.stringify({ brokerId: identity.brokerId, signingPublicJwk: identity.signingPublicJwk, encryptionPublicJwk: identity.encryptionPublicJwk }, null, 2)}\n`);
    if (!print) process.stdout.write("Public keys are safe to copy into the phone pairing screen.\n");
    return;
  }
  if (command === "serve") {
    if (args.includes("--token-stdin")) await loadTokenFromStdin();
    const broker = await Broker.create();
    await serve(broker, process.env.KEYWARDEN_SOCKET ?? DEFAULT_SOCKET);
    return;
  }
  if (command === "request-session") {
    const input = parseSessionArgs(args);
    const response = await localJsonRequest("POST", "/v1/session-requests", input);
    process.stdout.write(`${JSON.stringify(response, null, 2)}\n`);
    await waitForLocalRequest(response.request.id);
    return;
  }
  if (command === "approve") {
    const requestId = requiredFlag(args, "--request");
    process.stdout.write(`${JSON.stringify(await localJsonRequest("POST", "/v1/dev/approve", { requestId }), null, 2)}\n`);
    return;
  }
  if (command === "pair-phone") {
    const body = {
      phoneId: requiredFlag(args, "--phone-id"),
      encryptionPublicJwk: parseJsonFlag(args, "--encryption-public"),
      signingPublicJwk: parseJsonFlag(args, "--signing-public"),
    };
    process.stdout.write(`${JSON.stringify(await localJsonRequest("POST", "/v1/phone-pairing", body), null, 2)}\n`);
    return;
  }
  if (command === "pairing-qr") {
    const relayURL = optionalFlag(args, "--relay-url") ?? process.env.KEYWARDEN_RELAY_URL ?? DEFAULT_RELAY_URL;
    const relayToken = resolveRelayToken(args);
    const stateDir = defaultStateDir();
    const identity = await loadOrCreateIdentity(stateDir);
    const setup: PairingSetup = {
      version: 1,
      type: "keywarden_setup",
      brokerId: identity.brokerId,
      phoneId: randomId("phone"),
      pairingToken: randomId("pair"),
      createdAt: new Date().toISOString(),
    };
    await savePairingSetup(setup, stateDir);
    const payload = encodeSetupQr({
      relayURL,
      relayToken,
      brokerId: setup.brokerId,
      phoneId: setup.phoneId,
      pairingToken: setup.pairingToken,
      signingPublicKey: compactPublicKey(identity.signingPublicJwk),
      encryptionPublicKey: compactPublicKey(identity.encryptionPublicJwk),
    });
    const output = optionalFlag(args, "--output") ?? join(process.env.TMPDIR ?? "/tmp", "keywarden-pairing.png");
    const terminal = !args.includes("--no-terminal");
    if (terminal) process.stdout.write("Pairing QR:\n");
    execFileSync("swift", [join(process.cwd(), "scripts/keywarden-qr.swift"), output, ...(terminal ? ["--terminal"] : [])], {
      input: payload,
      stdio: ["pipe", terminal ? "inherit" : "ignore", "ignore"],
    });
    process.stdout.write(`Pairing QR written to ${output}\n`);
    return;
  }
  if (command === "op") {
    const separator = args.indexOf("--");
    const flags = separator >= 0 ? args.slice(0, separator) : args;
    const opArgs = separator >= 0 ? args.slice(separator + 1) : [];
    const operation = {
      version: 1,
      leaseId: optionalFlag(flags, "--lease") ?? "active",
      profile: optionalFlag(flags, "--profile") ?? "auto",
      operation: requiredFlag(flags, "--operation", "execute"),
      vault: optionalFlag(flags, "--vault"),
      itemId: optionalFlag(flags, "--item"),
      field: optionalFlag(flags, "--field"),
      args: opArgs,
    };
    const result = await localJsonRequest("POST", "/v1/operations", operation);
    process.stdout.write(result.stdout ?? "");
    if (result.stderr) process.stderr.write(result.stderr);
    process.exitCode = result.exitCode ?? 1;
    return;
  }
  process.stdout.write("Usage: keywarden {identity|serve|request-session|approve|pair-phone|pairing-qr|op}\n");
  process.stdout.write("  pairing-qr [--output path] [--no-terminal] [--relay-url url] [--relay-token-ref ref] [--opgate-profile name]\n");
}

function resolveRelayToken(args: string[]): string {
  const configured = process.env.KEYWARDEN_RELAY_TOKEN;
  if (configured) return configured;
  const profile = optionalFlag(args, "--opgate-profile") ?? process.env.KEYWARDEN_OPGATE_PROFILE ?? "agent";
  const reference = optionalFlag(args, "--relay-token-ref") ?? process.env.KEYWARDEN_RELAY_TOKEN_REF ?? DEFAULT_RELAY_TOKEN_REF;
  try {
    const token = execFileSync("opgate", ["op", "--profile", profile, "--", "read", reference], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
    if (token) return token;
  } catch {
    // Keep command output and token values out of the error message.
  }
  throw new Error(`Could not read the relay token through opgate profile '${profile}'`);
}

function compactPublicKey(value: JsonValue): [string, string] {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Broker public key is invalid");
  const x = value.x;
  const y = value.y;
  if (typeof x !== "string" || typeof y !== "string") throw new Error("Broker public key is invalid");
  return [x, y];
}

async function loadTokenFromStdin(): Promise<void> {
  process.stdin.setEncoding("utf8");
  let token = "";
  for await (const chunk of process.stdin) token += chunk;
  token = token.trim();
  if (!token) throw new Error("Empty service token on stdin");
  setBrokerToken(token);
}

async function serve(broker: Broker, socketPath: string): Promise<void> {
  await mkdir(dirname(socketPath), { recursive: true, mode: 0o770 });
  try { await unlink(socketPath); } catch { /* first start */ }
  const server = createServer(async (request, response) => {
    try {
      await route(broker, request, response);
    } catch (error) {
      sendJson(response, 400, { error: error instanceof Error ? error.message : String(error) });
    }
  });
  server.listen(socketPath, async () => {
    await chmod(socketPath, 0o600);
    const socketUser = process.env.KEYWARDEN_SOCKET_USER;
    if (socketUser) {
      execFileSync("chmod", ["+a", `${socketUser} allow read,write`, socketPath]);
    }
    process.stdout.write(`keywarden broker listening on ${socketPath}\n`);
  });
  await new Promise<void>((resolve) => process.once("SIGINT", () => { server.close(() => resolve()); }));
}

async function route(broker: Broker, request: import("node:http").IncomingMessage, response: import("node:http").ServerResponse): Promise<void> {
  const url = new URL(request.url ?? "/", "http://keywarden.local");
  if (request.method === "GET" && url.pathname === "/health") return sendJson(response, 200, { ok: true });
  if (request.method === "GET" && url.pathname === "/v1/identity") {
    return sendJson(response, 200, { brokerId: broker.identity.brokerId, signingPublicJwk: broker.identity.signingPublicJwk, encryptionPublicJwk: broker.identity.encryptionPublicJwk });
  }
  if (request.method === "POST" && url.pathname === "/v1/session-requests") {
    const body = await readJson(request);
    const pending = await broker.createSession(body);
    return sendJson(response, 202, serializePending(pending));
  }
  const requestMatch = url.pathname.match(/^\/v1\/session-requests\/([^/]+)$/);
  if (request.method === "GET" && requestMatch) {
    const pending = broker.store.requests.get(requestMatch[1]);
    if (!pending) return sendJson(response, 404, { error: "Unknown session request" });
    return sendJson(response, 200, serializePending(pending));
  }
  const revokeMatch = url.pathname.match(/^\/v1\/leases\/([^/]+)\/revoke$/);
  if (request.method === "POST" && revokeMatch) {
    broker.store.revoke(revokeMatch[1]);
    return sendJson(response, 200, { ok: true });
  }
  if (request.method === "POST" && url.pathname === "/v1/operations") {
    const body = await readJson(request) as OperationRequest;
    const result = await broker.runOperation(body);
    return sendJson(response, 200, result);
  }
  if (request.method === "POST" && url.pathname === "/v1/phone-pairing") {
    if (process.env.KEYWARDEN_DEV_MODE !== "1") throw new Error("Use QR pairing outside development mode");
    const body = await readJson(request) as PhonePairing;
    await savePhonePairing(body);
    return sendJson(response, 200, { ok: true, phoneId: body.phoneId });
  }
  if (request.method === "POST" && url.pathname === "/v1/dev/approve") {
    const body = await readJson(request) as { requestId: string };
    await broker.approveForDevelopment(body.requestId);
    return sendJson(response, 200, { ok: true });
  }
  sendJson(response, 404, { error: "Not found" });
}

function serializePending(pending: PendingRequest): Record<string, unknown> {
  const lease = pending.leaseId ? undefined : undefined;
  return { request: pending.request, requestHash: pending.requestHash, status: pending.status, leaseId: pending.leaseId, lease };
}

async function readJson(request: import("node:http").IncomingMessage): Promise<any> {
  const chunks: Buffer[] = [];
  let length = 0;
  for await (const chunk of request) {
    const buffer = Buffer.from(chunk);
    length += buffer.length;
    if (length > 1024 * 1024) throw new Error("Request body is too large");
    chunks.push(buffer);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
}

function sendJson(response: import("node:http").ServerResponse, status: number, body: unknown): void {
  response.writeHead(status, { "content-type": "application/json; charset=utf-8" });
  response.end(JSON.stringify(body));
}

async function localJsonRequest(method: string, path: string, body?: unknown): Promise<any> {
  const socketPath = process.env.KEYWARDEN_SOCKET ?? DEFAULT_SOCKET;
  return new Promise((resolve, reject) => {
    const encoded = body === undefined ? "" : JSON.stringify(body);
    const request = httpRequest({ socketPath, path, method, headers: { "content-type": "application/json", "content-length": Buffer.byteLength(encoded) } }, (response) => {
      const chunks: Buffer[] = [];
      response.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
      response.on("end", () => {
        const text = Buffer.concat(chunks).toString("utf8");
        const parsed = text ? JSON.parse(text) : {};
        if ((response.statusCode ?? 500) >= 400) reject(new Error(parsed.error ?? `HTTP ${response.statusCode}`));
        else resolve(parsed);
      });
    });
    request.on("error", reject);
    if (encoded) request.write(encoded);
    request.end();
  });
}

async function waitForLocalRequest(requestId: string): Promise<void> {
  while (true) {
    await sleep(1000);
    const status = await localJsonRequest("GET", `/v1/session-requests/${encodeURIComponent(requestId)}`);
    if (status.status === "approved" || status.status === "denied" || status.status === "expired") {
      process.stdout.write(`${JSON.stringify(status, null, 2)}\n`);
      return;
    }
  }
}

function parseSessionArgs(args: string[]) {
  const operations = repeatedFlag(args, "--operation");
  const allVaults = args.includes("--all-vaults");
  const vault = optionalFlag(args, "--vault");
  if (allVaults && vault) throw new Error("Use --all-vaults or --vault");
  if (!allVaults && !vault) throw new Error("Missing --vault or --all-vaults");
  return {
    agent: requiredFlag(args, "--agent"),
    host: requiredFlag(args, "--host"),
    phoneId: requiredFlag(args, "--phone"),
    reason: requiredFlag(args, "--reason"),
    scope: {
      accounts: [requiredFlag(args, "--account")],
      vaults: allVaults ? ["*"] : [vault!],
      items: "all",
      operations: operations.length ? operations : ["read"],
    },
    durationSeconds: Number(optionalFlag(args, "--duration") ?? 1800),
    idleTimeoutSeconds: Number(optionalFlag(args, "--idle-timeout") ?? 300),
  };
}

function requiredFlag(args: string[], name: string, fallback?: string): string {
  return optionalFlag(args, name) ?? fallback ?? (() => { throw new Error(`Missing ${name}`); })();
}

function optionalFlag(args: string[], name: string): string | undefined {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : undefined;
}

function repeatedFlag(args: string[], name: string): string[] {
  const values: string[] = [];
  for (let index = 0; index < args.length; index += 1) if (args[index] === name && args[index + 1]) values.push(args[index + 1]);
  return values;
}

function parseJsonFlag(args: string[], name: string): JsonValue {
  return JSON.parse(requiredFlag(args, name)) as JsonValue;
}

function sleep(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

void main().catch((error) => {
  process.stderr.write(`keywarden: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
