interface Env {
  BROKER_CHANNELS: { idFromName(name: string): unknown; get(id: unknown): DurableObjectStub };
  KEYWARDEN_RELAY_TOKEN: string;
}

interface DurableObjectStub {
  fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response>;
}

interface PendingRequest {
  requestId: string;
  phoneId: string;
  expiresAt: string;
  envelope: unknown;
  createdAt: string;
  decision?: unknown;
  revocation?: unknown;
  status?: unknown;
}

interface PairingRecord {
  phoneId: string;
  envelope: unknown;
  createdAt: string;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (new URL(request.url).pathname === "/health") return json({ ok: true });
    if (!authorized(request, env)) return json({ error: "Unauthorized" }, 401);

    const url = new URL(request.url);
    const match = url.pathname.match(/^\/v1\/brokers\/([^/]+)(\/.*)?$/);
    if (!match) return json({ error: "Not found" }, 404);
    const brokerId = decodeURIComponent(match[1]);
    const suffix = match[2] ?? "/";
    const id = env.BROKER_CHANNELS.idFromName(brokerId);
    const stub = env.BROKER_CHANNELS.get(id);
    return stub.fetch(new Request(`https://keywarden.internal${suffix}`, request));
  },
};

export class BrokerChannel {
  private readonly state: any;

  constructor(state: any) {
    this.state = state;
  }

  async fetch(request: Request): Promise<Response> {
    await this.prune();
    const url = new URL(request.url);
    const segments = url.pathname.split("/").filter(Boolean);

    if (segments.length === 3 && segments[0] === "phones" && segments[2] === "push") {
      const key = `push:${decodeURIComponent(segments[1])}`;
      if (request.method === "POST") {
        const envelope = await request.json();
        if (!validEnvelope(envelope, "push_registration")) return json({ error: "Invalid registration" }, 400);
        await this.state.storage.put(key, { envelope }); return json({ ok: true });
      }
      if (request.method === "GET") {
        const value = await this.state.storage.get(key);
        return value ? json(value) : json({ error: "Not registered" }, 404);
      }
    }

    if (request.method === "POST" && segments.length === 1 && segments[0] === "requests") {
      const body = await request.json() as PendingRequest;
      if (!body.requestId || !body.phoneId || !body.expiresAt || !validEnvelope(body.envelope, "session_request") || !Number.isFinite(Date.parse(body.expiresAt)) || Date.parse(body.expiresAt) <= Date.now()) return json({ error: "Invalid request" }, 400);
      if (await this.state.storage.get(`request:${body.requestId}`)) return json({ error: "Request already exists" }, 409);
      const entry: PendingRequest = { requestId: body.requestId, phoneId: body.phoneId, expiresAt: body.expiresAt, envelope: body.envelope, createdAt: new Date().toISOString() };
      await this.state.storage.put(`request:${body.requestId}`, entry);
      return json({ ok: true });
    }

    if (request.method === "POST" && segments.length === 1 && segments[0] === "pairing") {
      const body = await request.json() as PairingRecord;
      if (!body.phoneId || !validEnvelope(body.envelope, "phone_pairing")) return json({ error: "Upgrade Keywarden to pair this phone" }, 400);
      const entry: PairingRecord = { phoneId: body.phoneId, envelope: body.envelope, createdAt: new Date().toISOString() };
      await this.state.storage.put(`pairing:${body.phoneId}`, entry);
      return json({ ok: true });
    }

    if (request.method === "GET" && segments.length === 2 && segments[0] === "pairing") {
      const phoneId = decodeURIComponent(segments[1]);
      const entry = await this.state.storage.get(`pairing:${phoneId}`) as PairingRecord | undefined;
      if (!entry) return json({ error: "Pairing not available" }, 404);
      return json({ envelope: entry.envelope });
    }

    if (request.method === "POST" && segments.length === 3 && segments[0] === "pairing" && segments[2] === "ack") {
      const phoneId = decodeURIComponent(segments[1]);
      const entry = await this.state.storage.get(`pairing:${phoneId}`) as PairingRecord | undefined;
      if (!entry) return json({ error: "Pairing not available" }, 404);
      await this.state.storage.delete(`pairing:${phoneId}`);
      return json({ ok: true });
    }

    if (request.method === "GET" && segments.length === 3 && segments[0] === "phones" && segments[2] === "requests") {
      const phoneId = decodeURIComponent(segments[1]);
      const listed = await this.state.storage.list({ prefix: "request:" });
      const requests: PendingRequest[] = [];
      for (const value of listed.values()) {
        const entry = value as PendingRequest;
        if (entry.phoneId === phoneId && !entry.decision && new Date(entry.expiresAt).getTime() > Date.now()) requests.push(entry);
      }
      return json({ requests });
    }

    if (request.method === "POST" && segments.length === 5 && segments[0] === "phones" && segments[2] === "requests" && segments[4] === "decision") {
      const phoneId = decodeURIComponent(segments[1]);
      const requestId = decodeURIComponent(segments[3]);
      const key = `request:${requestId}`;
      const entry = await this.state.storage.get(key) as PendingRequest | undefined;
      if (!entry) return json({ error: "Unknown request" }, 404);
      if (entry.phoneId !== phoneId) return json({ error: "Wrong phone" }, 403);
      if (entry.decision) return json({ error: "Decision already recorded" }, 409);
      if (new Date(entry.expiresAt).getTime() <= Date.now()) return json({ error: "Request expired" }, 410);
      const decision = await request.json();
      if (!validEnvelope(decision, "approval_decision")) return json({ error: "Invalid decision" }, 400);
      entry.decision = decision;
      await this.state.storage.put(key, entry);
      return json({ ok: true });
    }

    if (request.method === "GET" && segments.length === 2 && segments[0] === "decisions") {
      const entry = await this.state.storage.get(`request:${decodeURIComponent(segments[1])}`) as PendingRequest | undefined;
      if (!entry?.decision) return json({ error: "Decision not available" }, 404);
      return json({ envelope: entry.decision });
    }

    // These endpoints store opaque, signed ciphertext. The broker validates it.
    if (segments.length === 3 && segments[0] === "requests" && ["status", "revocation"].includes(segments[2])) {
      const key = `request:${decodeURIComponent(segments[1])}`;
      const entry = await this.state.storage.get(key) as PendingRequest | undefined;
      if (!entry) return json({ error: "Unknown request" }, 404);
      const field = segments[2] as "status" | "revocation";
      if (request.method === "GET") return entry[field] ? json({ envelope: entry[field] }) : json({ error: "Not available" }, 404);
      if (request.method === "POST") {
        const envelope = await request.json();
        if (!validEnvelope(envelope, field === "status" ? "session_status" : "session_revoke")) return json({ error: "Invalid session message" }, 400);
        entry[field] = envelope;
        await this.state.storage.put(key, entry);
        return json({ ok: true });
      }
    }

    return json({ error: "Not found" }, 404);
  }

  private async prune(): Promise<void> {
    const listed = await this.state.storage.list({ prefix: "request:" });
    const removals: Promise<void>[] = [];
    for (const [key, value] of listed) {
      const entry = value as PendingRequest;
      const expired = new Date(entry.expiresAt).getTime() <= Date.now();
      const old = Date.now() - new Date(entry.createdAt).getTime() > 24 * 60 * 60 * 1000;
      if ((expired && !entry.decision) || old) removals.push(this.state.storage.delete(key));
    }
    await Promise.all(removals);
  }
}

function authorized(request: Request, env: Env): boolean {
  const expected = env.KEYWARDEN_RELAY_TOKEN;
  if (!expected) return false;
  return request.headers.get("authorization") === `Bearer ${expected}`;
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json; charset=utf-8" } });
}

function validEnvelope(value: unknown, kind: string): boolean {
  if (!value || typeof value !== "object") return false;
  const envelope = value as Record<string, any>;
  return envelope.version === 1 && envelope.kind === kind && typeof envelope.signature === "string"
    && envelope.body?.version === 1 && envelope.body?.algorithm === "ECDH-P256-AES-256-GCM"
    && typeof envelope.body?.ciphertext === "string" && typeof envelope.body?.iv === "string"
    && !!envelope.senderPublicKey && !!envelope.body?.ephemeralPublicKey;
}
