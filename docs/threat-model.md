# Keywarden threat model

## Data boundaries

1Password tokens, passwords, fields, and operation output stay on the Mac or the approved local process.

Cloudflare receives encrypted messages, device identifiers, request identifiers, expiry times, and an application relay token.

Cloudflare can observe timing and payload size. It has no 1Password token, client, or connection.

QR pairing encrypts its challenge to the broker. The phone signs its public-key registration.

The broker compares the decrypted challenge with its local setup record. The phone pins the broker keys from the QR.

Apple receives a generic alert and a device token. The Mac holds the Apple signing key in memory.

## Local access

The broker verifies the phone signature, request identifier, and request hash before it creates a lease.

Each operation resolves to one lease ID. Leases act as local bearer capabilities. Agent and host names are display labels.

The broker validates command structure, effective vault, effective item, operation, account, expiry, and idle timeout.

Unknown flags, account overrides, multiple targets, output files, and encoded secret-reference paths fail validation.

Item-scoped sessions cannot list a vault or create unrelated items. Execute and arbitrary command injection are unsupported.

The restricted launcher allows only the broker socket and approved filesystem areas. See [local isolation](local-isolation.md).

The broker administration socket is unavailable inside that sandbox. It accepts the local Apple key bootstrap.

The existing unrestricted agent session remains outside this boundary until it restarts through the launcher.

## MCP access

The MCP command uses local stdio and the broker Unix socket. It has no direct 1Password client.

The broker validates each MCP operation against the active lease. Implicit lease selection only chooses one matching lease.

The MCP process keeps lease metadata in memory. It does not cache returned secret values.

Session requests include two signed groups: client metadata from the MCP handshake and local process, plus agent-provided approval intent. Client metadata is display context. The broker never uses it for authorization.

MCP responses contain secret values when a read succeeds. The MCP client controls logs, transcripts, and model visibility.

Cloudflare does not see MCP traffic or secret values. It relays encrypted approval envelopes only.

## Phone access

The app verifies the pinned broker signature before it decrypts and displays a request.

It checks the encrypted request against the routing identifiers and expiry. It rejects a changed or unrelated request.

Face ID protects approval, denial, and revocation. Keychain stores phone keys, the relay token, and approval history.
The notification extension receives the phone decryption key, relay settings, encrypted request snapshots, and completed request IDs.
A dedicated keychain group shares these records with `WhenUnlockedThisDeviceOnly` protection.
The app retains its original signing key. The extension uses a separate copy protected with Keychain `biometryAny` access control.
The copy uses `WhenUnlockedThisDeviceOnly` and the dedicated notification access group.
Every decision starts a fresh biometric-only `LAContext`. The context disables authentication reuse and passcode fallback.
The extension verifies the request before authentication, then rechecks connection settings, completed IDs, and expiry afterward.
Only a verified broker status can produce an approval or denial confirmation.
Active confirmation must be no older than 20 seconds, including retries. Device unlock alone cannot authorize a decision.
The extension saves a receipt before sending. Retries reuse that signed decision and cannot switch its approval result.
The main app imports receipts into history. An unconfirmed receipt never appears as confirmed access or denial.
Notification actions stay inside the extension. More details opens the main app.
If iOS forwards an action to the background app, the app asks for review without signing.
Missing or expired requests never fall back to another request.

The app distinguishes approval sent, broker-confirmed access, revocation pending, revoked access, and expired access.

Stale status never appears as confirmed active access. The broker sends status during the session.

## Failure behavior

The broker enforces expiry on each operation. Restarts remove every lease.

Remote status or revocation failures revoke the affected lease. The app waits for a signed confirmation.

The relay retains decided requests for at most 24 hours. It removes expired undecided requests.

The development approval and local pairing endpoints require `KEYWARDEN_DEV_MODE=1`. The installed service does not enable that mode.

The phone keeps up to 200 local history records. History contains request metadata and decisions, not secret values.

## Limits

The Mac must remain awake and online. Push delivery depends on Apple and the phone notification settings.

Apple push credentials require a local bootstrap after broker restart. The key never enters Cloudflare or an agent environment.

The broker uses separate service-account profiles for the dedicated Personal and work vaults. Each service account remains limited by its vault permissions.

Built-in `Personal`, `Private`, `Employee`, and default `Shared` vaults stay outside service-account scope. Move required items into dedicated vaults.

Revocation cannot erase secrets already returned to an approved process. The human account owner can bypass the agent launcher.
