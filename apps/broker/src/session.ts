import {
  hashRequest,
  randomId,
} from "../../../protocol/src/index.ts";
import type { AccountName, ApprovalDecision, ClientMetadata, OpenSessionRequest, OperationRequest, SessionLease, SessionScope } from "../../../protocol/src/index.ts";
import { commandTarget } from "./command.ts";

export interface PendingRequest {
  request: OpenSessionRequest;
  requestHash: string;
  status: "pending" | "approved" | "denied" | "expired";
  leaseId?: string;
}

export class SessionStore {
  readonly requests = new Map<string, PendingRequest>();
  readonly leases = new Map<string, SessionLease>();

  async createRequest(input: {
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
    const now = Date.now();
    const duration = clamp(input.durationSeconds, 1, 24 * 60 * 60);
    const idleTimeout = clamp(input.idleTimeoutSeconds, 1, duration);
    const createdAt = new Date(now).toISOString();
    const request: OpenSessionRequest = {
      version: 1,
      type: "open_session",
      id: randomId("request"),
      agent: input.agent,
      host: input.host,
      phoneId: input.phoneId,
      reason: input.reason,
      intent: normalizeIntent(input.intent, input.task, input.reason),
      client: normalizeClientMetadata(input.client ?? manualClientMetadata(input.agent, input.host)),
      scope: normalizeScope(input.scope),
      durationSeconds: duration,
      idleTimeoutSeconds: idleTimeout,
      createdAt,
      expiresAt: new Date(now + duration * 1000).toISOString(),
      nonce: randomId("nonce"),
    };
    const pending = { request, requestHash: await hashRequest(request), status: "pending" as const };
    this.requests.set(request.id, pending);
    return pending;
  }

  approve(requestId: string, decision: ApprovalDecision): SessionLease {
    const pending = this.requests.get(requestId);
    if (!pending) throw new Error("Unknown session request");
    if (pending.status !== "pending") throw new Error(`Request is already ${pending.status}`);
    if (new Date(pending.request.expiresAt).getTime() <= Date.now()) {
      pending.status = "expired";
      throw new Error("Session request expired");
    }
    if (decision.requestHash !== pending.requestHash) throw new Error("Approval does not match request");
    if (decision.decision !== "approve") {
      pending.status = "denied";
      throw new Error("Session request denied");
    }
    const issuedAt = new Date().toISOString();
    const lease: SessionLease = {
      version: 1,
      id: randomId("lease"),
      requestId,
      requestHash: pending.requestHash,
      agent: pending.request.agent,
      host: pending.request.host,
      scope: pending.request.scope,
      issuedAt,
      expiresAt: new Date(Date.now() + pending.request.durationSeconds * 1000).toISOString(),
      idleUntil: new Date(Date.now() + pending.request.idleTimeoutSeconds * 1000).toISOString(),
      idleTimeoutSeconds: pending.request.idleTimeoutSeconds,
      status: "active",
    };
    pending.status = "approved";
    pending.leaseId = lease.id;
    this.leases.set(lease.id, lease);
    return lease;
  }

  deny(requestId: string): void {
    const pending = this.requests.get(requestId);
    if (!pending) throw new Error("Unknown session request");
    if (pending.status !== "pending") throw new Error(`Request is already ${pending.status}`);
    pending.status = "denied";
  }

  revoke(leaseId: string): void {
    const lease = this.leases.get(leaseId);
    if (lease) lease.status = "revoked";
  }

  status(pending: PendingRequest): Record<string, unknown> {
    const lease = pending.leaseId ? this.leases.get(pending.leaseId) : undefined;
    if (lease?.status === "active" && Math.min(Date.parse(lease.expiresAt), Date.parse(lease.idleUntil)) <= Date.now()) lease.status = "expired";
    return { version: 1, type: "session_status", requestId: pending.request.id, requestHash: pending.requestHash,
      status: lease?.status ?? pending.status, issuedAt: lease?.issuedAt, expiresAt: lease?.expiresAt,
      idleUntil: lease?.idleUntil, observedAt: new Date().toISOString() };
  }

  authorize(operation: OperationRequest): SessionLease {
    const resolved = this.resolveOperation(operation);
    if (resolved.leaseId === "direct-agent") {
      this.authorizeDirectAgent(resolved);
      return directAgentLease();
    }
    const lease = this.leases.get(resolved.leaseId);
    if (!lease) throw new Error("Unknown session lease");
    const now = Date.now();
    if (lease.status !== "active") throw new Error(`Session lease is ${lease.status}`);
    if (new Date(lease.expiresAt).getTime() <= now) {
      lease.status = "expired";
      throw new Error("Session lease expired");
    }
    if (new Date(lease.idleUntil).getTime() <= now) {
      lease.status = "expired";
      throw new Error("Session lease idle timeout reached");
    }
    if (!lease.scope.accounts.includes(resolved.profile)) throw new Error("Account is outside the lease scope");
    if (!lease.scope.operations.includes(resolved.operation)) throw new Error("Operation is outside the lease scope");
    if (!resolved.vault) throw new Error("Operation must name a vault");
    if (!lease.scope.vaults.includes("*") && !lease.scope.vaults.includes(resolved.vault)) {
      throw new Error("Vault is outside the lease scope");
    }
    const target = commandTarget(resolved);
    if (lease.scope.items !== "all") {
      if (!target.item || !lease.scope.items.includes(target.item)) {
        throw new Error("Item is outside the lease scope");
      }
    }
    lease.idleUntil = new Date(now + lease.idleTimeoutSeconds * 1000).toISOString();
    return lease;
  }

  resolveOperation(operation: OperationRequest): OperationRequest & { profile: AccountName } {
    if (operation.leaseId === "direct-agent") {
      return { ...operation, profile: operation.profile === "auto" ? "agent" : operation.profile };
    }
    if (operation.leaseId !== "active") {
      const lease = this.leases.get(operation.leaseId);
      if (!lease) throw new Error("Unknown session lease");
      return this.withAccount(operation, lease);
    }
    const target = commandTarget(operation);
    const now = Date.now();
    const candidates = [...this.leases.values()].filter((lease) => {
      if (lease.status !== "active" || Date.parse(lease.expiresAt) <= now || Date.parse(lease.idleUntil) <= now) return false;
      if (operation.profile !== "auto" && !lease.scope.accounts.includes(operation.profile)) return false;
      if (!lease.scope.operations.includes(operation.operation)) return false;
      if (!operation.vault || (!lease.scope.vaults.includes("*") && !lease.scope.vaults.includes(operation.vault))) return false;
      if (lease.scope.items !== "all" && (!target.item || !lease.scope.items.includes(target.item))) return false;
      return true;
    });
    if (candidates.length === 0) throw new Error("No active lease matches this operation");
    if (candidates.length > 1) throw new Error("Multiple active leases match; specify --lease");
    return this.withAccount(operation, candidates[0]);
  }

  private authorizeDirectAgent(operation: OperationRequest): void {
    if (operation.profile !== "agent") throw new Error("Account is outside the direct agent scope");
    if (!["read", "list", "write", "create", "delete"].includes(operation.operation)) {
      throw new Error("Operation is outside the direct agent scope");
    }
    if (operation.vault !== "agents") throw new Error("Vault is outside the direct agent scope");
    commandTarget(operation);
  }

  private withAccount(operation: OperationRequest, lease: SessionLease): OperationRequest & { profile: AccountName } {
    const accounts = operation.profile === "auto" ? lease.scope.accounts : [operation.profile];
    if (accounts.length !== 1) throw new Error("Active lease has multiple accounts; specify --profile");
    return { ...operation, leaseId: lease.id, profile: accounts[0] };
  }
}

function manualClientMetadata(agent: string, host: string): ClientMetadata {
  return {
    product: "manual",
    clientName: agent,
    displayName: agent,
    productVersion: "unknown",
    protocolVersion: "unknown",
    transport: "local",
    sessionId: null,
    sessionName: null,
    host,
    project: null,
    pid: null,
    capabilities: [],
  };
}

function normalizeIntent(intent: { task?: string | null; reason: string } | undefined, task: string | undefined, reason: string): { task: string | null; reason: string } {
  if (intent && intent.reason !== reason) throw new Error("Approval intent reason must match reason");
  return { task: intent?.task ?? task ?? null, reason };
}

function normalizeClientMetadata(client: ClientMetadata): ClientMetadata {
  return {
    ...client,
    sessionId: client.sessionId ?? null,
    sessionName: client.sessionName ?? null,
    project: client.project ?? null,
    pid: client.pid ?? null,
  };
}

function normalizeScope(scope: SessionScope): SessionScope {
  const accounts = [...new Set(scope.accounts)] as AccountName[];
  const vaults = [...new Set(scope.vaults.map((vault) => vault.trim()).filter(Boolean))];
  const operations = [...new Set(scope.operations)];
  if (accounts.length === 0) throw new Error("A session needs an account");
  if (vaults.length === 0) throw new Error("A session needs a vault scope");
  if (operations.length === 0) throw new Error("A session needs an operation scope");
  if (operations.some((operation) => !["read", "list", "write", "create", "delete"].includes(operation))) throw new Error("Unsupported operation scope");
  if (scope.items !== "all" && (!Array.isArray(scope.items) || scope.items.length === 0)) throw new Error("Invalid item scope");
  return { accounts, vaults, items: scope.items === "all" ? "all" : [...new Set(scope.items)], operations };
}

function clamp(value: number, min: number, max: number): number {
  if (!Number.isFinite(value)) throw new Error("Duration must be a number");
  return Math.min(max, Math.max(min, Math.floor(value)));
}

function directAgentLease(): SessionLease {
  const now = new Date().toISOString();
  return {
    version: 1,
    id: "direct-agent",
    requestId: "direct-agent",
    requestHash: "direct-agent",
    agent: "local-agent",
    host: "local",
    scope: { accounts: ["agent"], vaults: ["agents"], items: "all", operations: ["read", "list", "write", "create", "delete"] },
    issuedAt: now,
    expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24 * 365).toISOString(),
    idleUntil: new Date(Date.now() + 1000 * 60 * 60 * 24 * 365).toISOString(),
    idleTimeoutSeconds: 60 * 60 * 24 * 365,
    status: "active",
  };
}
