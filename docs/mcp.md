# Keywarden 1Password MCP

Keywarden provides a local Model Context Protocol server for code agents.

The MCP server uses standard JSON-RPC over stdin and stdout. Start it with:

```sh
keywarden mcp
```

The MCP process connects to `/Users/Shared/Keywarden/broker.sock`, or `KEYWARDEN_SOCKET`.

## Configure a code agent

Use this MCP client entry:

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

Claude Code can use the same local command:

```sh
claude mcp add keywarden-1password -- ~/.local/bin/keywarden mcp
```

Codex can use the same command through its `keywarden-1password` MCP entry. The server title changes to `Keywarden 1Password for Codex` or `Keywarden 1Password for Claude Code` after initialization.

The client starts one MCP process per connection. The broker keeps pending requests and active leases for its lifetime.
An MCP process restart can reuse a matching pending request or active lease.
The broker matches the phone, client label, host, and requested scope.
It ignores session labels and approval text when it reuses access.
An expired request cannot be reused. A broker restart ends every session.
The broker accepts the older phone hash format that omits display metadata.

The MCP handshake identifies the client. Keywarden maps client names to `Codex`, `Claude Code`, or `MCP client`. It sends the client name, version, protocol version, transport, host, project name, process ID, capability names, and allowlisted session identifiers to the phone.

Codex and Claude Code do not define a standard MCP session-name field. Keywarden uses an available client title or these optional environment variables: `CODEX_SESSION_NAME`, `CLAUDE_SESSION_NAME`, and `MCP_SESSION_NAME`. It uses the matching session ID variables when present.

The agent can pass `sessionName` when it knows a session label that the MCP host does not expose. Keywarden treats this value as display metadata.

## Tool flow

```text
Code agent
   │ stdio JSON-RPC
   ▼
keywarden mcp
   │ local Unix socket
   ▼
Rust broker ── lease check ── opgate ── 1Password
   │
   └── encrypted approval messages ── Cloudflare ── iPhone
```

1. Call `keywarden_read_secret`, `keywarden_list_items`, or `keywarden_list_fields`. Automatic approval requests are enabled by default.
2. The broker creates one exact request for the account, vault, item, and operation.
3. Approve personal or work requests on the paired iPhone.
4. The tool returns its result after approval. Repeat the same call if its 25-second wait ended before approval.
5. Pass `structuredContent.value` directly to the next code tool.

The tools wait up to 25 seconds by default. Set `waitSeconds` to zero for an immediate result.
Every MCP `waitSeconds` field accepts integers from zero through 25. A value of 30 returns `invalid_wait`.
The pending response includes `requestId` and a next action in `structuredContent.error`.
Use `keywarden_request_access` for a planned session or a broad scope across several operations.
Session requests default to `operations: ["read", "list"]`, matching `keywarden request-session`.
Explicit operations replace this default. Use `["read"]` for a read-only request or `["list"]` for metadata listing only.
Write, create, and delete permissions require an explicit request.
Automatic requests from individual read or list tools still request only that operation.

Use `keywarden_list_fields` when you need field IDs or labels before reading a field. It returns metadata only.
Each supported field includes a `reference` for `keywarden_read_secret`. Copy that reference instead of assembling an `op://` path.

Metadata and status results appear as JSON in both text content and `structuredContent`.
Errors include their code, message, request ID when available, and next action in both outputs.
Secret values appear only in `structuredContent.value`. Text-only clients must use code mode or CLI piping for secret consumption.

## Equivalent CLI commands

```sh
keywarden list --vault agents
keywarden fields --vault agents --item ITEM_ID
keywarden read op://agents/ITEM_ID/FIELD_ID
keywarden list --account personal --vault 'Keywarden Personal' --reason 'Find the required item'
```

The CLI shares the MCP operation path. It derives scope from the command and reuses existing approvals.
It waits up to 120 seconds for new approval, then executes the operation in the same command.
Use `--wait 0` for immediate status, or `--wait SECONDS` for a limit from zero through 300 seconds.
Use `--no-request` to require existing access without creating a phone request.

Read writes exact value bytes to stdout for piping. It adds no newline. `--json` returns the reference and value.
List and fields return JSON objects matching MCP structured results.
Diagnostics use stderr. Failures return a nonzero exit code and a JSON error on stderr.
Long waits can also emit one progress line on stderr before the final result.
Use shell `pipefail` when a pipeline must fail if Keywarden fails.

Scope, duration, and revocation checks still apply. These commands never request write access automatically.

The adapter selects an active lease when exactly one approved lease matches the account, vault, item, and operation.
It checks broker-held leases when its connection has no matching cached approval.
This includes leases approved through the CLI or another MCP process. Resolution does not renew the lease's idle timeout.
When no lease matches and `requestIfNeeded` is enabled, it creates an exact scoped request.
Automatic requests use a 15-minute duration and a five-minute idle timeout.

Supply `leaseId` or `account` when several leases match. The broker still enforces the final scope.

`keywarden_list_items` returns item metadata only. It needs a lease with `list` permission.
Each item contains only `id`, `title`, and `category` when available.
Listings exclude `additional_information`, usernames, note excerpts, URLs, and field values.

## Discovery and pages

Call `keywarden_list_vaults` without arguments to discover the approval-free agent vault.
Use `account: "personal"` or `account: "work"` for those accounts.
Existing list approval limits the returned vaults. Without list approval, vault discovery requests list permission across all allowed vaults.
Set `requestIfNeeded: false` to prevent that request.

Vault discovery returns `id` and `name`. Either form works in item operations.
The broker resolves aliases inside approved account scopes and executes commands with the verified vault ID.
Alias resolution never grants another vault or account access. Vault metadata stays cached locally for up to 60 seconds.

Both discovery tools accept `query`, `limit`, and `cursor`.
Search checks returned metadata only. It does not search secret values.
The default page size is 100. Valid sizes range from one through 200.
Pass `nextCursor` into the next call with the same account, vault, and query.
A null `nextCursor` marks the last page. `totalCount` counts matching results.
Changed results invalidate the cursor. Restart discovery without a cursor after `invalid_cursor`.
Pagination occurs locally after 1Password returns metadata. It does not reduce the provider's listing cost.

CLI equivalents:

```sh
keywarden vaults
keywarden vaults --account personal --no-request
keywarden list --vault agents --query deployment --limit 20
keywarden list --vault agents --query deployment --limit 20 --cursor CURSOR
```

## Approval delivery and controls

`keywarden_access_status` returns `delivery` for each phone request. Pending errors include the same delivery details.

| Field | Meaning |
| --- | --- |
| `delivery.relay.state` | Whether the relay accepted the encrypted request. |
| `delivery.push.state` | Disabled, unregistered, failed, rejected, or accepted by Apple. |
| `delivery.push.acceptedAt` | Apple accepted the notification at this time. |
| `delivery.poll.state` | Waiting, retrying after a relay fault, or decision received. |
| `delivery.phoneReceipt` | `unconfirmed`; the current phone protocol does not send delivery receipts. |

Apple acceptance does not prove that the phone displayed an alert.
Open Keywarden when no alert appears. The encrypted request remains available without a notification.
The broker retries approval polling after relay faults. Polling ends when the request expires or reaches a terminal state.
Apple can retain an offline notification until request expiry. Separate requests use separate collapse identifiers.

Use `keywarden_manage_request` with `requestId` and `action: "retry"` to resend the notification.
Retry preserves the request, scope, and expiry. It never creates another approval request.
The broker permits one retry every 30 seconds.
Use `action: "cancel"` to prevent the pending request from granting access.
Cancellation rejects later approval decisions. The phone can still show a cached card until expiry.

```sh
keywarden status
keywarden status --request REQUEST_ID
keywarden retry --request REQUEST_ID
keywarden cancel --request REQUEST_ID
```

Global status lists pending request IDs. `lastAppleAcceptedAt` clarifies the older `lastPushAt` field.
Neither field confirms phone delivery.

## Value handling

The adapter does not log secret values. It does not cache secret values after a tool call.

The MCP response contains the value in `structuredContent.value` on stdout. Its text content message contains no value.

The MCP host receives that response and controls its logs, transcript, and model context.

Approval requests separate automatic client metadata from agent-provided intent. The intent contains the task and reason. The phone shows both groups before approval. Client metadata provides display context only. It does not grant access.

| Group | Source | Examples |
| --- | --- | --- |
| Client metadata | MCP handshake, local process, and allowlisted session environment | Codex, Claude Code, version, protocol, host, project, capabilities, session name |
| Approval intent | MCP tool arguments | Task, reason, account, vaults, items, operations, duration, idle timeout |

Code mode can keep the value in a variable and pipe it into another tool without printing it. Keywarden cannot prevent a client from logging or displaying it.

Cloudflare receives encrypted approval envelopes and routing metadata. It does not receive 1Password credentials, item values, or the MCP stream.

The MCP process has no 1Password token and no direct network connection to 1Password.

## Supported tools

| Tool | Function |
| --- | --- |
| `keywarden_request_access` | Request iPhone approval for a scoped lease. |
| `keywarden_access_status` | Poll the last request or a supplied request ID. |
| `keywarden_read_secret` | Read one approved `op://` field, or request exact access. |
| `keywarden_list_items` | List metadata in one approved vault, or request exact access. |
| `keywarden_list_fields` | List safe field metadata, or request exact item access. |
| `keywarden_list_vaults` | Discover approved vault IDs and names, with search and pages. |
| `keywarden_manage_request` | Retry a notification or cancel a pending request. |

The broker supports read, list, write, create, and delete lease scopes. The MCP adapter exposes read and list operations first.

The direct agent scope covers only the `agents` vault. It uses the existing local `agent` opgate profile.

## Failure behavior

The broker rejects changed vaults, items, fields, operations, accounts, flags, expired leases, idle leases, and revoked leases.

The MCP adapter does not retry a rejected lease against another lease. It reports the broker error to the MCP client.
Known provider faults return `item_not_found`, `field_not_found`, `vault_not_found`, `authentication_failed`, or `provider_permission_denied`.
Lease and account faults remain separate. Unknown provider failures use `op_rejected` and withhold provider output.

The existing `agent` profile remains available through its current opgate path. MCP approval applies to personal and work accounts when those profiles use phone-gated leases.
The CLI also selects direct agent access when `keywarden op` receives `--profile agent` without `--lease`.
This access still permits only the `agents` vault. Personal and work operations still require a matching lease.
