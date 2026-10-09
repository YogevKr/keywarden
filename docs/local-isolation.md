# Same-user agent isolation

The launcher preserves existing `agent` vault access and requires phone approval for Personal and work accounts.

The broker maps approved accounts to separate opgate profiles. Each service account can access only its dedicated vault.

Run the broker and the agent under your existing macOS user. No additional account or VM is required.

The agent must start through `keywarden run`. An existing unrestricted agent process remains unrestricted.

```text
Restricted agent process
    │  approved operation and lease ID
    ▼
Local broker socket ──► Rust broker ──► opgate ──► 1Password
                           │
                           ├── encrypted messages ──► Cloudflare relay
                           └── generic alerts ──────► Apple Push Notification service
```

For each 1Password command, the broker starts a foreground CLI daemon on a private socket.
Some 1Password CLI versions exit successfully without starting a daemon. The broker then runs the uncached command on the private socket path.
It still disables desktop settings, biometric integration, and caching. A nonzero daemon exit or startup timeout remains an error.
The broker stops that daemon after the command. This prevents detached CLI daemons and repeated macOS prompts.

## Start a restricted process

Install the trusted broker outside the writable project:

```sh
./scripts/install.sh
keywarden start
keywarden run --workspace ~/projects/example -- /bin/zsh -f
```

Use the same launcher for an agent command. The launcher preserves these provider variables when the parent command supplies them:

- `OPENAI_API_KEY`
- `ANTHROPIC_API_KEY`

Resolve provider credentials through `opgate` for the launch command. The launcher removes other credential variables.

Host authentication files remain blocked. Agent tools must support authentication through their supplied provider variable.

## Enforced restrictions

The launcher applies the macOS process sandbox before it starts the command. Child processes inherit that sandbox.

The process can read and write its selected workspace and its temporary directory. It can read system and installed tool files.

The process can access the broker socket. It cannot access the separate administration socket.

The process cannot read user credential directories, broker identity files, or another workspace.

The process cannot run the installed `op` and `opgate` binaries. Copied code still faces file and IPC restrictions.

The process can make HTTPS connections and DNS requests. The policy blocks loopback connections and unrelated Unix sockets.

The process cannot use unrestricted Apple events, Keychain IPC, debugger attachment, or signals to unrelated processes.

The broker validates actual command arguments against the approved vault, item, and operation. Client labels do not establish identity.

## Verification

```sh
cargo build --manifest-path apps/broker-rs/Cargo.toml
npm run test:sandbox
```

The probes use synthetic files and sockets. They test private reads, symlink reads, environment removal, direct commands, and socket restrictions.

The probes also confirm workspace writes and broker socket access.

## Limits

The account owner can start unrestricted processes or change the installed broker. This design does not restrict the human owner.

The sandbox applies only to processes launched through Keywarden. Existing Codex, Claude, Terminal, and automation sessions retain their permissions.

Apple marks `sandbox-exec` as deprecated. Recheck the probes after macOS updates. The launcher does not fall back to unrestricted execution.

A secret returned after approval remains available to its recipient. Revocation blocks later operations; it cannot erase earlier results.

The workspace must exclude credentials and trusted broker executables. Choose a project directory, not your home directory.
