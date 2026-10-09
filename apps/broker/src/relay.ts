import type { JsonValue, SignedEnvelope } from "../../../protocol/src/index.ts";

export class RelayClient {
  readonly baseUrl: string;
  readonly token: string;

  constructor(baseUrl: string, token: string) {
    this.baseUrl = baseUrl;
    this.token = token;
  }

  private headers(): HeadersInit {
    return {
      authorization: `Bearer ${this.token}`,
      "content-type": "application/json",
    };
  }

  async submitRequest(input: {
    brokerId: string;
    requestId: string;
    phoneId: string;
    expiresAt: string;
    envelope: SignedEnvelope;
  }): Promise<void> {
    const response = await fetch(`${this.baseUrl}/v1/brokers/${encodeURIComponent(input.brokerId)}/requests`, {
      method: "POST",
      headers: this.headers(),
      body: JSON.stringify(input),
    });
    if (!response.ok) throw new Error(`Relay request failed with HTTP ${response.status}`);
  }

  async getDecision(brokerId: string, requestId: string): Promise<SignedEnvelope | undefined> {
    const response = await fetch(
      `${this.baseUrl}/v1/brokers/${encodeURIComponent(brokerId)}/decisions/${encodeURIComponent(requestId)}`,
      { headers: this.headers() },
    );
    if (response.status === 404) return undefined;
    if (!response.ok) throw new Error(`Relay decision failed with HTTP ${response.status}`);
    const body = await response.json() as { envelope: SignedEnvelope };
    return body.envelope;
  }

  async sessionEnvelope(brokerId: string, requestId: string, field: "status" | "revocation", envelope?: SignedEnvelope): Promise<SignedEnvelope | undefined> {
    const response = await fetch(`${this.baseUrl}/v1/brokers/${encodeURIComponent(brokerId)}/requests/${encodeURIComponent(requestId)}/${field}`, {
      method: envelope ? "POST" : "GET", headers: this.headers(), body: envelope ? JSON.stringify(envelope) : undefined,
    });
    if (response.status === 404 && !envelope) return undefined;
    if (!response.ok) throw new Error(`Relay session update failed with HTTP ${response.status}`);
    if (!envelope) return (await response.json() as { envelope: SignedEnvelope }).envelope;
  }

  async getPairing(brokerId: string, phoneId: string): Promise<SignedEnvelope | undefined> {
    const response = await fetch(`${this.baseUrl}/v1/brokers/${encodeURIComponent(brokerId)}/pairing/${encodeURIComponent(phoneId)}`, {
      headers: this.headers(),
    });
    if (response.status === 404) return undefined;
    if (!response.ok) throw new Error(`Relay pairing lookup failed with HTTP ${response.status}`);
    return (await response.json() as {envelope: SignedEnvelope}).envelope;
  }

  async acknowledgePairing(brokerId: string, phoneId: string): Promise<void> {
    const response = await fetch(`${this.baseUrl}/v1/brokers/${encodeURIComponent(brokerId)}/pairing/${encodeURIComponent(phoneId)}/ack`, {
      method: "POST",
      headers: this.headers(),
    });
    if (!response.ok) throw new Error(`Relay pairing acknowledgement failed with HTTP ${response.status}`);
  }
}
