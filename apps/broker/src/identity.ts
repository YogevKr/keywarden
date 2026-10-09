import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
  exportPrivateKey,
  exportPublicKey,
  generateEncryptionKeyPair,
  generateSigningKeyPair,
  randomId,
  importSigningPrivateKey,
} from "../../../protocol/src/index.ts";
import type { JsonValue } from "../../../protocol/src/index.ts";

export interface BrokerIdentity {
  brokerId: string;
  signingPrivateJwk: JsonValue;
  signingPublicJwk: JsonValue;
  encryptionPrivateJwk: JsonValue;
  encryptionPublicJwk: JsonValue;
}

export interface PhonePairing {
  phoneId: string;
  encryptionPublicJwk: JsonValue;
  signingPublicJwk: JsonValue;
}

export interface PairingSetup {
  version: 1;
  type: "keywarden_setup";
  brokerId: string;
  phoneId: string;
  pairingToken: string;
  createdAt: string;
}

export function defaultStateDir(): string {
  return process.env.KEYWARDEN_STATE_DIR ?? join(process.env.HOME ?? ".", "Library/Application Support/Keywarden");
}

async function writePrivateJson(path: string, value: unknown): Promise<void> {
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
}

export async function loadOrCreateIdentity(stateDir = defaultStateDir()): Promise<BrokerIdentity> {
  await mkdir(stateDir, { recursive: true, mode: 0o700 });
  const path = join(stateDir, "broker-identity.json");
  try {
    return JSON.parse(await readFile(path, "utf8")) as BrokerIdentity;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    const keyPair = await generateSigningKeyPair();
    const encryptionKeyPair = await generateEncryptionKeyPair();
    const identity: BrokerIdentity = {
      brokerId: randomId("broker"),
      signingPrivateJwk: await exportPrivateKey(keyPair.privateKey),
      signingPublicJwk: await exportPublicKey(keyPair.publicKey),
      encryptionPrivateJwk: await exportPrivateKey(encryptionKeyPair.privateKey),
      encryptionPublicJwk: await exportPublicKey(encryptionKeyPair.publicKey),
    };
    await writePrivateJson(path, identity);
    return identity;
  }
}

export async function loadPhonePairing(stateDir = defaultStateDir()): Promise<PhonePairing | undefined> {
  const envPhoneId = process.env.KEYWARDEN_PHONE_ID;
  const envEncryption = process.env.KEYWARDEN_PHONE_ENCRYPTION_PUBLIC_JWK;
  const envSigning = process.env.KEYWARDEN_PHONE_SIGNING_PUBLIC_JWK;
  if (envPhoneId && envEncryption && envSigning) {
    return {
      phoneId: envPhoneId,
      encryptionPublicJwk: JSON.parse(envEncryption) as JsonValue,
      signingPublicJwk: JSON.parse(envSigning) as JsonValue,
    };
  }
  try {
    return JSON.parse(await readFile(join(stateDir, "phone-pairing.json"), "utf8")) as PhonePairing;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    return undefined;
  }
}

export async function savePhonePairing(pairing: PhonePairing, stateDir = defaultStateDir()): Promise<void> {
  await mkdir(stateDir, { recursive: true, mode: 0o700 });
  await writePrivateJson(join(stateDir, "phone-pairing.json"), pairing);
}

export async function loadPairingSetup(stateDir = defaultStateDir()): Promise<PairingSetup | undefined> {
  try {
    return JSON.parse(await readFile(join(stateDir, "pairing-setup.json"), "utf8")) as PairingSetup;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    return undefined;
  }
}

export async function savePairingSetup(setup: PairingSetup, stateDir = defaultStateDir()): Promise<void> {
  await mkdir(stateDir, { recursive: true, mode: 0o700 });
  await writePrivateJson(join(stateDir, "pairing-setup.json"), setup);
}

export async function clearPairingSetup(stateDir = defaultStateDir()): Promise<void> {
  try {
    await import("node:fs/promises").then(({ unlink }) => unlink(join(stateDir, "pairing-setup.json")));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
}

export async function loadSigningPrivateKey(identity: BrokerIdentity): Promise<CryptoKey> {
  return importSigningPrivateKey(identity.signingPrivateJwk);
}
