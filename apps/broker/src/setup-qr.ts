import { deflateRawSync } from "node:zlib";

export interface SetupQrInput {
  relayURL: string;
  relayToken: string;
  brokerId: string;
  phoneId: string;
  pairingToken: string;
  signingPublicKey: [string, string];
  encryptionPublicKey: [string, string];
}

export function encodeSetupQr(input: SetupQrInput): string {
  const compact = JSON.stringify({
    r: input.relayURL,
    t: input.relayToken,
    b: input.brokerId,
    p: input.phoneId,
    q: input.pairingToken,
    s: input.signingPublicKey,
    e: input.encryptionPublicKey,
  });
  return `kw2:${deflateRawSync(Buffer.from(compact)).toString("base64url")}`;
}
