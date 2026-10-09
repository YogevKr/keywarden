export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };

export type AccountName = "agent" | "personal" | "work";
export type OperationName = "read" | "write" | "create" | "delete" | "list" | "execute";

export interface SessionScope {
  accounts: AccountName[];
  vaults: string[];
  items: "all" | string[];
  operations: OperationName[];
}

export interface ApprovalIntent {
  task?: string | null;
  reason: string;
}

export interface ClientMetadata {
  product: string;
  clientName: string;
  displayName: string;
  productVersion: string;
  protocolVersion: string;
  transport: string;
  sessionId?: string | null;
  sessionName?: string | null;
  host: string;
  project?: string | null;
  pid?: number | null;
  capabilities: string[];
}

export interface OpenSessionRequest {
  version: 1;
  type: "open_session";
  id: string;
  agent: string;
  host: string;
  phoneId: string;
  reason: string;
  intent?: ApprovalIntent;
  client?: ClientMetadata;
  scope: SessionScope;
  durationSeconds: number;
  idleTimeoutSeconds: number;
  createdAt: string;
  expiresAt: string;
  nonce: string;
}

export interface ApprovalDecision {
  version: 1;
  type: "approval_decision";
  requestId: string;
  requestHash: string;
  decision: "approve" | "deny";
  decidedAt: string;
  nonce: string;
}

export interface SessionLease {
  version: 1;
  id: string;
  requestId: string;
  requestHash: string;
  agent: string;
  host: string;
  scope: SessionScope;
  issuedAt: string;
  expiresAt: string;
  idleUntil: string;
  idleTimeoutSeconds: number;
  status: "active" | "revoked" | "expired";
}

export interface OperationRequest {
  version: 1;
  leaseId: string;
  profile: AccountName | "auto";
  operation: OperationName;
  vault?: string;
  itemId?: string;
  field?: string;
  args: string[];
}

export interface EncryptedPayload {
  version: 1;
  algorithm: "ECDH-P256-AES-256-GCM";
  ephemeralPublicKey: JsonValue;
  iv: string;
  ciphertext: string;
}

export interface SignedEnvelope {
  version: 1;
  kind: "session_request" | "approval_decision" | "session_status" | "session_revoke" | "push_registration" | "phone_pairing";
  body: EncryptedPayload;
  senderPublicKey: JsonValue;
  signature: string;
}

export function canonicalize(value: JsonValue): string {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("Cannot canonicalize a non-finite number");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((entry) => canonicalize(entry)).join(",")}]`;
  }
  const keys = Object.keys(value).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(",")}}`;
}

export function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function base64UrlToBytes(value: string): Uint8Array {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(padded);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

export async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return bytesToBase64Url(new Uint8Array(digest));
}

export async function hashRequest(request: OpenSessionRequest): Promise<string> {
  return sha256(canonicalize(request as unknown as JsonValue));
}

export async function generateSigningKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  ) as Promise<CryptoKeyPair>;
}

export async function generateEncryptionKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveKey"],
  ) as Promise<CryptoKeyPair>;
}

export async function exportPublicKey(key: CryptoKey): Promise<JsonValue> {
  return (await crypto.subtle.exportKey("jwk", key)) as unknown as JsonValue;
}

export async function exportPrivateKey(key: CryptoKey): Promise<JsonValue> {
  return (await crypto.subtle.exportKey("jwk", key)) as unknown as JsonValue;
}

export async function importSigningPublicKey(jwk: JsonValue): Promise<CryptoKey> {
  return crypto.subtle.importKey("jwk", jwk as JsonWebKey, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]);
}

export async function importSigningPrivateKey(jwk: JsonValue): Promise<CryptoKey> {
  return crypto.subtle.importKey("jwk", jwk as JsonWebKey, { name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);
}

export async function importEncryptionPublicKey(jwk: JsonValue): Promise<CryptoKey> {
  return crypto.subtle.importKey("jwk", jwk as JsonWebKey, { name: "ECDH", namedCurve: "P-256" }, true, []);
}

export async function importEncryptionPrivateKey(jwk: JsonValue): Promise<CryptoKey> {
  return crypto.subtle.importKey("jwk", jwk as JsonWebKey, { name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey"]);
}

export async function signText(privateKey: CryptoKey, value: string): Promise<string> {
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    privateKey,
    new TextEncoder().encode(value),
  );
  return bytesToBase64Url(new Uint8Array(signature));
}

export async function verifyText(publicKey: CryptoKey, value: string, signature: string): Promise<boolean> {
  return crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    publicKey,
    base64UrlToBytes(signature) as unknown as BufferSource,
    new TextEncoder().encode(value),
  );
}

export async function encryptForPublicKey(plaintext: string, recipientPublicJwk: JsonValue): Promise<EncryptedPayload> {
  const ephemeral = await generateEncryptionKeyPair();
  const recipient = await importEncryptionPublicKey(recipientPublicJwk);
  const key = await crypto.subtle.deriveKey(
    { name: "ECDH", public: recipient },
    ephemeral.privateKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(plaintext),
  );
  return {
    version: 1,
    algorithm: "ECDH-P256-AES-256-GCM",
    ephemeralPublicKey: await exportPublicKey(ephemeral.publicKey),
    iv: bytesToBase64Url(iv),
    ciphertext: bytesToBase64Url(new Uint8Array(ciphertext)),
  };
}

export async function decryptWithPrivateKey(payload: EncryptedPayload, privateKey: CryptoKey): Promise<string> {
  if (payload.version !== 1 || payload.algorithm !== "ECDH-P256-AES-256-GCM" || base64UrlToBytes(payload.iv).length !== 12) throw new Error("Invalid encryption envelope");
  const ephemeral = await importEncryptionPublicKey(payload.ephemeralPublicKey);
  const key = await crypto.subtle.deriveKey(
    { name: "ECDH", public: ephemeral },
    privateKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64UrlToBytes(payload.iv) as unknown as BufferSource },
    key,
    base64UrlToBytes(payload.ciphertext) as unknown as BufferSource,
  );
  return new TextDecoder().decode(plaintext);
}

export async function signEnvelope(
  kind: SignedEnvelope["kind"],
  body: EncryptedPayload,
  privateKey: CryptoKey,
  publicKey: JsonValue,
): Promise<SignedEnvelope> {
  const unsigned = { version: 1 as const, kind, body, senderPublicKey: publicKey };
  return {
    ...unsigned,
    signature: await signText(privateKey, canonicalize(unsigned as unknown as JsonValue)),
  };
}

export async function verifyEnvelope(envelope: SignedEnvelope): Promise<boolean> {
  if (envelope.version !== 1) return false;
  const { signature, ...unsigned } = envelope;
  const publicKey = await importSigningPublicKey(envelope.senderPublicKey);
  return verifyText(publicKey, canonicalize(unsigned as unknown as JsonValue), signature);
}

export function randomId(prefix: string): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return `${prefix}_${bytesToBase64Url(bytes)}`;
}
