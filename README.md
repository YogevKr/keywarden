# Keywarden

Keywarden gives local agents scoped 1Password access after iPhone approval.

## Account behavior

| Account | Access |
| --- | --- |
| `agent` | Existing access to the dedicated `agents` vault, without phone approval. |
| `personal` | Phone approval for selected custom vaults or a session across allowed vaults. |
| `work` | Phone approval through a separate service-account profile. |

The local broker checks scope, expiry, and revocation before each operation.
Cloudflare relays encrypted approval messages. It receives no 1Password credentials or item values.

1Password service accounts restrict which vaults each profile can access.
Built-in Personal, Private, Employee, and default Shared vaults are excluded from this workflow.
Move required items into custom vaults and configure service accounts for those vaults.

Deployment addresses and push credential references belong in local configuration, outside this repository.

See [1Password authentication methods](https://www.1password.dev/sdks/concepts#authentication) and [Connect vault limits](https://developer.1password.com/docs/connect/get-started/).

## Current prototype

The native iOS app shows pending requests, active sessions, and approval history. Settings stays behind a toolbar button.

The Rust broker enforces each lease locally. Cloudflare stores encrypted messages and routing metadata. It never connects to 1Password.

```text
Agent sandbox ──► Rust broker ──► opgate profile ──► 1Password
                       │
                       ├── encrypted requests, decisions, status ──► Cloudflare ──► iPhone
                       └── generic notification ──────────────────► Apple ───────► iPhone
```

## Prototype commands

Agents can read, list, and discover fields with one command:

```sh
keywarden vaults
keywarden list --vault agents
keywarden list --vault agents --query deployment --limit 20
keywarden fields --vault agents --item ITEM_ID
keywarden read op://agents/ITEM_ID/FIELD_ID | consumer --stdin
keywarden list --account personal --vault 'Keywarden Personal' --reason 'Find deployment credentials'
```

Replace `consumer --stdin` with a command that accepts the value through standard input.
Enable your shell's `pipefail` option when pipeline failures must stop a script.
Read returns the exact value without an added newline. List and fields return JSON metadata.
Field metadata includes usable `reference` strings. It excludes field values.
Item listings include only IDs, titles, and categories. They exclude usernames and note excerpts.
Vault discovery returns names and IDs. Both forms work within the approved account scope.
Discovery supports `--query`, `--limit`, and `--cursor`. JSON results contain `totalCount` and `nextCursor`.

These commands reuse approved access and request phone approval when needed.
They wait up to 120 seconds and continue after approval. Use `--wait 0` to return immediately.
Pending approval returns a nonzero exit code and a request ID on stderr. Repeat the command after approval.
Use `--no-request` to require existing access. Use `--json` for a JSON read result containing the value.
Agent vault commands need no approval. Use `--account personal` or `--account work` when requesting new account access.

The CLI and MCP share scope checks, approval handling, and metadata filtering.

Check delivery with `keywarden status --request REQUEST_ID`.

Use `keywarden status` for local account access without contacting 1Password.
Use `keywarden status --check-provider` to test connections through existing list access.
The MCP equivalent is `keywarden_access_status` with `{"checkProvider":true}`.
Checks never request approval, read credential fields, or extend leases.
See [provider check results and the 0.3.0 field migration](docs/mcp.md#optional-provider-check).
Use `keywarden retry --request REQUEST_ID` to retry the notification without creating another request.
Use `keywarden cancel --request REQUEST_ID` to stop a pending request from granting access.
Apple acceptance does not confirm phone delivery. The current phone protocol has no delivery receipt.

```sh
./scripts/install.sh
keywarden start
keywarden status
keywarden pairing-qr
keywarden notifications enable
```

If the scanner cannot read the compact QR, use `keywarden pairing-qr --legacy`.

Existing paired phones keep their setup after an app upgrade. A new setup QR expires after 15 minutes.

In the iPhone app, open Settings to scan the QR and enable notifications.

```sh
keywarden request-session --account personal --vault 'Keywarden Personal' --reason 'Read deployment credentials' --duration 900
keywarden op --lease LEASE_ID --profile personal --operation read --vault 'Keywarden Personal' -- item get ITEM_ID --vault 'Keywarden Personal' --format=json
keywarden revoke --lease LEASE_ID
```

Use `--all-vaults` for a full session across every vault allowed by the selected account. The phone shows `All allowed vaults` before approval.

A session includes all items in the selected vault unless you supply `--item ITEM_ID`.

Repeat `--operation` to request more operations. Supported operations are `read`, `list`, `write`, `create`, and `delete`.

Use `keywarden run --workspace PATH -- COMMAND` to restrict an agent under your existing macOS account.

## MCP for code agents

Run the local stdio MCP adapter:

```sh
keywarden mcp
```

Configure the code agent with the command, for example:

```json
{
  "mcpServers": {
    "keywarden-1password": {
      "command": "keywarden",
      "args": ["mcp"]
    }
  }
}
```

The adapter connects only to the local broker socket. The broker connects to `opgate` after lease checks.

Use `keywarden_request_access` for phone approval on personal or work accounts. Agent access to the `agents` vault is active without approval.

The MCP handshake identifies Codex, Claude Code, or another client. Keywarden shows that identity, version, host, project, capability names, and any available session name on the phone. Supply `task` and `reason` to describe the approval intent.
The CLI detects Codex or Claude Code from parent process names and allowlisted session variables.
It shows `Keywarden CLI` when detection is unavailable. Use `--agent` to set an explicit label.
CLI and MCP session requests allow read and list by default. Explicit operations replace these defaults.
Use `keywarden request-session --help` to see scope, duration, and identity options.

Use `keywarden_access_status` without arguments for current account access. Supply `requestId` to poll a pending approval.
Pending MCP operations return `isError: false`, `status: "pending"`, and a request ID. Repeat the same call after approval.
MCP executes read and list only. Write, create, and delete lease scopes apply to CLI operations.

Use `keywarden_read_secret` with an `op://vault/item/field` reference. The adapter selects the only matching approved lease.

Use the returned `structuredContent.value` as an in-memory input to another code tool. Do not print or save it.

The secret read content message contains no value. Code mode must support MCP `structuredContent`.

The MCP process never stores secret values. Its stdout contains the requested tool result because MCP requires that response.

The MCP host can log tool results or show them to a model. Keywarden cannot control that host behavior.

The MCP adapter has no direct 1Password client and sends no secret value through Cloudflare.

Read [local isolation](docs/local-isolation.md) before relying on that restriction.

## Security and availability

The phone pins the broker signing key. The broker pins the phone signing key and checks the approved request hash.

QR pairing sends its challenge inside an encrypted envelope. The relay cannot use that challenge to replace the phone key.

The broker checks actual command arguments. A caller cannot declare one vault or item and execute against another.

Phone revocation requires a signed request. The app shows confirmation only after the broker sends a signed status.

The broker revokes access when session synchronization fails. It also enforces duration and idle limits on each operation.

Broker restarts end every session. The Mac must stay awake and online for remote access.

Notifications contain no account, vault, item, or secret values. The Mac contacts Apple directly.

`keywarden notifications enable` requires local personal-account approval. It holds the Apple key in broker memory until restart.

The existing `agent` profile keeps direct `agents` access. Personal and work operations use their dedicated service-account profiles after phone approval.

See [the threat model](docs/threat-model.md) and [setup](docs/setup.md).

## Development

```sh
npm run check
npm run rust:test
npm run rust:build
npm run test:sandbox
```

The TypeScript broker remains a protocol reference and test implementation. Use the Rust broker for the installed service and notifications.

For local Worker integration tests:

```sh
wrangler dev --local --port 8787 --var KEYWARDEN_RELAY_TOKEN:relay-test-token --config apps/relay-worker/wrangler.toml
npm run e2e:worker
npm run e2e:worker:rust
```

The tests use synthetic credentials unless you explicitly select the real pilot.

## Layout

```text
apps/broker-rs/     Rust broker, CLI, sandbox, service, and Apple notifications
apps/broker/        TypeScript reference broker
apps/ios/           SwiftUI app and simulator tests
apps/relay-worker/  Cloudflare encrypted message relay
protocol/          Shared protocol and command validation fixtures
scripts/           Install, QR, sandbox, and integration tools
docs/              Setup, isolation, and threat model
```
