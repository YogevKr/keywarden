# Keywarden setup

The broker verifies phone approval for the existing `agents` vault and dedicated Personal and work vaults.

Keep existing agent vault access through opgate. Use the dedicated vaults for remote Personal and work access.

The Mac runs the Rust broker. Cloudflare relays encrypted messages. The iPhone reviews requests and signs decisions.

## Install and start

```sh
cd ~/projects/keywarden
./scripts/install.sh
keywarden start
keywarden status
```

The installer places the command under `~/.local/bin`. Add that directory to your shell path when needed.

The service uses `launchd` under your existing user. It reads the application relay token through the `agent` opgate profile.

Create `~/.config/keywarden/config.json` outside the repository:

```json
{
  "relayUrl": "https://YOUR_RELAY.workers.dev",
  "pushVault": "YOUR_APPLE_CREDENTIAL_VAULT",
  "pushItem": "YOUR_APPLE_PUSH_ITEM"
}
```

This file contains deployment references only. Keep tokens and private keys in 1Password.
The push item needs `apns_key_id`, `apns_team_id`, and `apns_auth_key_p8` fields.
The broker uses a local development relay when no relay address is configured.
`KEYWARDEN_RELAY_URL` or `--relay-url` overrides the configured relay address.

The iOS project leaves its signing team unset. Supply your team and provisioning profiles when building for TestFlight.

The service contains no credential values in its launch configuration. It invokes `opgate` locally for approved 1Password operations.

The broker maps accounts to profiles:

| Account | Profile |
| --- | --- |
| `agent` | `agent` |
| `personal` | `keywarden-personal` |
| `work` | `keywarden-work` |

Configure each service account for the required custom vaults. Create work accounts with an account administrator, then run:

```sh
opgate init keywarden-work --token-file ~/.config/opgate/keywarden-work.token
```

Keep service-account token files readable only by the local user. Do not put them in the `agents` vault.

The default socket is `/Users/Shared/Keywarden/broker.sock`. Local identity and pairing records live under `~/Library/Application Support/Keywarden/`.

Logs live under `~/Library/Logs/Keywarden/`. `keywarden stop` stops the broker and ends all sessions.

## Pair the phone

Existing pairing survives an app upgrade. Create a QR only for initial setup or a replacement pairing.

```sh
keywarden pairing-qr
```

If the phone cannot read the compact QR, use `keywarden pairing-qr --legacy`.

The command prints a compact QR and writes a PNG. Use `--output PATH` or `--no-terminal` when needed.

On the iPhone, open **Settings**, then tap **Scan setup QR**.

The app imports the connection, generates phone keys, and submits encrypted pairing. Pre-filled fields do not affect QR import.

The QR contains relay configuration and a one-time challenge. It contains no 1Password token or item value.

The QR expires after 15 minutes. The broker confirms the new pairing on the next status check or session request.

```sh
keywarden status
```

A replacement pairing revokes existing leases. Protect the QR image and remove it after pairing.

## Enable notifications

On the phone, open **Settings → Enable notifications** and permit alerts.

Settings shows **Enable notifications** only before the first permission decision.
After approval, use **Notification settings** to change alerts in iOS Settings.
If permission is denied, Keywarden links to iOS Settings instead of requesting permission again.
Quiet delivery and disabled alerts have separate states. Returning from iOS Settings refreshes the displayed state.

The permission row reports iPhone settings, not proof of push delivery.
The connection section separates saved pairing from the last successful sync.
Use **Advanced connection** for repairs. Edits apply only after saving.

On the Mac:

```sh
keywarden notifications enable
```

This command uses native personal-account approval through `opgate`. It resolves the existing Apple push key into memory.

The Mac sends generic alerts directly to Apple. Cloudflare receives the encrypted device registration, not the Apple key.

The key remains in broker memory until restart. Run the notification command again after restarting the broker.

```sh
keywarden status
```

`notifications: true` means the broker holds the Apple key. `lastPushAt` records the last accepted Apple delivery request.

Apple acceptance does not prove that the phone displayed an alert. Test delivery on the physical iPhone.

### Expanded notifications (build 13)

Open Keywarden once after installing build 13. The app prepares protected data for the notification extension.
Long-press a new notification to see the verified agent, session, account, vaults, items, operations, duration, and reason.

- **Approve** runs fresh Face ID inside the expanded notification. The main app stays closed.
- **Reject** runs fresh Face ID inside the expanded notification before sending a denial.
- **More details** opens the full request without starting a decision.

The extension checks the exact request, connection, and expiry again after Face ID.
It shows success only after verifying confirmation signed by the Mac.
Cancelling Face ID sends no decision. Device unlock alone cannot approve access.
The main app imports notification decisions into history when it next polls.
A failed connection shows an unconfirmed decision. Repeating the same action reuses the signed decision.
If iOS cannot run the extension, open the request in Keywarden. Background fallback never signs a decision.

The extension first checks locally cached encrypted requests. It can fetch encrypted requests with a short timeout.
It verifies the broker signature and request identity before displaying any scope.
Locked keychain data, missing setup, network errors, invalid signatures, and expired requests show a fallback message.
Open the app for the current status when preview details are unavailable.

The main app and extension share a dedicated keychain group for preview configuration and the phone decryption key.
These records use `WhenUnlockedThisDeviceOnly`. A separate shared signing-key copy also requires biometric Keychain access.
Each decision uses a fresh `LAContext` with biometric reuse disabled and no passcode fallback.
The extension saves an encrypted signed decision and its receipt before sending, so interrupted delivery can be retried.
Apple receives a generic alert and request ID. Cloudflare receives encrypted requests and decisions.
An expanded preview can show an earlier pending snapshot. The Mac remains authoritative for request and session state.

### iOS UX follow-ups

The table marks completed changes. Other entries remain proposals.

| Priority | Feature | Apple API | Product behavior and limits |
| --- | --- | --- | --- |
| Shipped in build 13 | Expanded notification details and decisions | [Notification content extension](https://developer.apple.com/documentation/usernotificationsui/customizing-the-appearance-of-notifications) | Show verified scope. Approve or reject here with fresh Face ID and signed Mac confirmation. |
| 1 | Notification preparation | [Notification service extension](https://developer.apple.com/documentation/usernotifications/modifying-content-in-newly-delivered-notifications) | Prepare encrypted request data before display. Keep generic text when keys or network access are unavailable. |
| Shipped in build 11 | Remove completed alerts | [Delivered notification removal](https://developer.apple.com/documentation/usernotifications/unusernotificationcenter/removedeliverednotifications(withidentifiers:)) | Remove alerts after a decision without clearing unrelated requests. |
| 2 | Active session countdown | [ActivityKit](https://developer.apple.com/documentation/activitykit) | Show duration and last confirmed state. Revocation opens the app for biometric authentication. |
| 2 | Quick access | [WidgetKit controls](https://developer.apple.com/documentation/widgetkit/creating-controls-to-perform-actions-across-the-system) | Open pending requests from Control Center or the Lock Screen. Do not approve automatically. |
| 2 | Decision feedback | [SwiftUI sensory feedback](https://developer.apple.com/documentation/swiftui/sensoryfeedback) | Confirm a sent decision through haptics. Show broker confirmation separately. |
| 3 | Urgent alerts | [Time Sensitive notifications](https://developer.apple.com/documentation/usernotifications/unnotificationinterruptionlevel/timesensitive) | Offer an opt-in for short-lived requests. Respect the user's Focus controls. |

The current phone keys use `WhenUnlockedThisDeviceOnly` storage. Keep that protection when adding extensions.
The content extension uses a dedicated keychain group. Store its signing-key copy only in biometric-protected Keychain storage. Never include keys in notification payloads.
Cloudflare must continue receiving encrypted requests only. Apple must not receive plaintext secrets or request scope.
The content extension should render available data immediately; it must not depend on a long network request.
Device unlock alone does not replace Keywarden's biometric decision check.

The settings change uses [UNNotificationSettings](https://developer.apple.com/documentation/usernotifications/unnotificationsettings) for actual permission and alert state.
It uses [openNotificationSettingsURLString](https://developer.apple.com/documentation/uikit/uiapplication/opennotificationsettingsurlstring) to open the app's notification controls directly.

## Request an open session

For one operation, use these commands. They request approval only when approved access is unavailable.

```sh
keywarden list --account personal --vault 'Keywarden Personal' --reason 'Find deployment credentials'
keywarden fields --account personal --vault 'Keywarden Personal' --item ITEM_ID
keywarden read 'op://Keywarden Personal/ITEM_ID/FIELD_ID'
```

The commands wait for phone approval and continue automatically. The default wait is 120 seconds.
Use `--wait 0` for immediate status or `--no-request` to require existing approved access.
Read returns raw value bytes for pipes. List and fields return JSON metadata.
Use `keywarden read --help` for options. Use an open session below when the task needs several operations.
Use `keywarden vaults` to discover the agent vault without knowing its name.
For approved personal vault discovery, use `keywarden vaults --account personal --no-request`.
Item listings return only IDs, titles, and categories. `--query` searches metadata; `--limit` and `--cursor` control pages.

If no alert appears, open Keywarden. Check `keywarden status --request REQUEST_ID` for relay and Apple acceptance states.
Apple acceptance cannot confirm phone display. Use `keywarden retry --request REQUEST_ID` to resend the same notification.
Use `keywarden cancel --request REQUEST_ID` to block a pending approval. A cached phone card can remain until expiry.

```sh
keywarden request-session \
  --account personal \
  --vault 'Keywarden Personal' \
  --duration 900 --idle-timeout 300 \
  --reason 'Check deployment credentials'
```

The command discovers the paired phone. It waits for approval and returns the lease ID.

Sessions request **read and list** by default, through both the CLI and MCP.
Use `--operation read` or MCP `operations: ["read"]` to request read access only.
Explicit operations replace the defaults. Writes, creation, and deletion require an explicit operation.

The CLI detects Codex or Claude Code from the nearest recognized parent process, then from allowlisted session variables.
It shows `Keywarden CLI` when it cannot identify the caller.
Available session IDs and names, the project name, and the process ID appear as client metadata.
The CLI does not inspect parent command arguments or session transcripts.
Use `--agent`, `--host`, or `--session-name` for explicit display overrides. Use `--task` to describe the approval intent.
Client labels provide context; they are not proof of caller identity.
Run `keywarden request-session --help` for defaults and all options.

The session covers all items in the selected dedicated vault. Add `--item ITEM_ID` to limit it to specific items.

Use `--all-vaults` instead of `--vault` to request every vault allowed by the selected account. The phone shows `All allowed vaults` before approval.

Repeat `--vault`, `--item`, or `--operation` when needed. The phone approval removes the need for local Mac approval.

```sh
keywarden op --lease LEASE_ID --profile personal --operation read --vault 'Keywarden Personal' \
  -- item get ITEM_ID --vault 'Keywarden Personal' --format=json
```

The broker compares actual arguments with the approved scope. It rejects unknown flags, account overrides, and changed targets.

To inspect or revoke:

```sh
keywarden status --request REQUEST_ID
keywarden revoke --lease LEASE_ID
```

The phone also has **Revoke access** on each session card. It waits for broker confirmation before showing revoked access.

The app starts checking requests when it opens. Settings and credential fields stay off the main screen.

History includes approval and denial decisions. It keeps up to 200 records in the device Keychain.

## Restrict the local agent

```sh
keywarden run --workspace ~/projects/example -- COMMAND
```

Read [local isolation](local-isolation.md) before using this launcher. Existing unrestricted agent processes need a restart through the launcher.

## Configure MCP

Code agents can connect through the local MCP adapter:

```sh
keywarden mcp
```

Add this command to the agent MCP configuration:

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

The adapter uses the broker socket. It never reads a 1Password token.

Call `keywarden_request_access` for personal or work access, then `keywarden_access_status`, then `keywarden_read_secret`.

The MCP handshake identifies Codex, Claude Code, or another client. Keywarden shows the client identity and available session metadata on the phone. Supply `task` and `reason` for the approval intent.

The agent account can read and list the `agents` vault without approval through the same MCP tools.

Pass `structuredContent.value` to the next code tool. Do not print or save it.

The MCP host controls transcript and log visibility. The adapter cannot prevent a host from showing tool results.

## Verify the implementation

```sh
npm run check:all
npm run test:sandbox
npm run worker:dry-run
```

For Worker integration, start Wrangler in another terminal:

```sh
wrangler dev --local --port 8787 \
  --var KEYWARDEN_RELAY_TOKEN:relay-test-token \
  --config apps/relay-worker/wrangler.toml
```

```sh
npm run e2e:worker
npm run e2e:worker:rust
```

These tests use synthetic credentials. They verify encrypted pairing, approval, operation execution, and remote revocation.

The real pilot uses the dedicated test item. It suppresses item values:

```sh
KEYWARDEN_E2E_REAL_OPERATION=read \
KEYWARDEN_E2E_ITEM_ID=YOUR_TEST_ITEM_ID \
  KEYWARDEN_E2E_RELAY_URL=https://YOUR_RELAY.workers.dev \
  npm run pilot:real
```

Run simulator tests with your simulator ID:

```sh
xcodegen --spec apps/ios/project.yml
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer \
  xcodebuild -project apps/ios/Keywarden.xcodeproj -scheme Keywarden \
  -destination 'platform=iOS Simulator,id=DEVICE_ID' \
  CODE_SIGNING_ALLOWED=YES CODE_SIGNING_REQUIRED=NO test
```

The tests cover encryption, broker identity, QR replacement, approval, history, revocation, and screen navigation.

Debug UI fixtures are excluded from release builds. TestFlight builds use production push entitlements.
