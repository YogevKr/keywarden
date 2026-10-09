use crate::{env, flag_value, msg, Result, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

pub(crate) async fn local(method: &str, path: &str, body: Option<Value>) -> Result<Value> {
    let socket = env::var("KEYWARDEN_SOCKET")
        .unwrap_or_else(|_| "/Users/Shared/Keywarden/broker.sock".into());
    let socket = if path == "/v1/notification-credentials" {
        std::path::PathBuf::from(socket).with_extension("admin.sock")
    } else {
        socket.into()
    };
    let mut stream = UnixStream::connect(&socket)
        .await
        .map_err(|_| msg("Broker is unavailable. Run keywarden start."))?;
    let body = body.map(|body| body.to_string()).unwrap_or_default();
    stream.write_all(format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await?;
    let mut bytes = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(60),
        stream.take(9 * 1024 * 1024).read_to_end(&mut bytes),
    )
    .await
    .map_err(|_| msg("Broker response timed out"))??;
    let end = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| msg("Invalid broker response"))?;
    let header = String::from_utf8_lossy(&bytes[..end]);
    let status = header.split_whitespace().nth(1).unwrap_or("500");
    let value: Value = serde_json::from_slice(&bytes[end + 4..])?;
    if !status.starts_with('2') {
        return Err(msg(value["error"]
            .as_str()
            .unwrap_or("Broker request failed")));
    }
    Ok(value)
}

fn required(args: &[String], name: &str) -> Result<String> {
    flag_value(args, name)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| msg(format!("Missing {name}")))
}

fn repeated(args: &[String], name: &str) -> Vec<String> {
    args.windows(2)
        .filter(|pair| pair[0] == name)
        .map(|pair| pair[1].clone())
        .collect()
}

fn print(value: &Value) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

pub async fn run(args: &[String]) -> Result<()> {
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print_help(args.first().map(String::as_str));
        return Ok(());
    }
    match args.first().map(String::as_str) {
        Some("read" | "list" | "fields" | "vaults") => {
            let result = simple_command(args).await;
            if let Err(error) = result {
                let mut details = crate::mcp::error_with_delivery(&error).await;
                if details["error"]["code"] == "approval_required" {
                    details["error"]["next"] = serde_json::json!("Approve on your phone, then repeat the same command. The pending request is reused.");
                }
                match details["error"]["code"].as_str() {
                    Some("lease_required") => details["error"]["next"] = serde_json::json!("Repeat without --no-request to request phone approval, or use keywarden request-session for planned access."),
                    Some("account_required") => details["error"]["next"] = serde_json::json!("Supply --account personal or --account work for a new approval request."),
                    Some("lease_ambiguous") => details["error"]["next"] = serde_json::json!("Supply --account or --lease to select approved access."),
                    Some("lease_not_found" | "lease_revoked" | "lease_expired") => details["error"]["next"] = serde_json::json!("Check keywarden status. Request a new session if access is still needed."),
                    _ => {},
                }
                eprintln!("{}", details);
                std::process::exit(1);
            }
            Ok(())
        }
        Some("mcp") => crate::mcp::run().await,
        Some(action @ ("retry" | "cancel")) => {
            let id = required(args, "--request")?;
            print(
                &local(
                    "POST",
                    &format!("/v1/session-requests/{}/{action}", crate::url_escape(&id)),
                    Some(serde_json::json!({})),
                )
                .await?,
            )
        }
        Some("notifications") => {
            if args.get(1).map(String::as_str) != Some("configure") {
                let status = tokio::process::Command::new("opgate")
                    .args(["session", "--profile", "personal", "--"])
                    .arg(env::current_exe()?)
                    .args(["notifications", "configure"])
                    .status()
                    .await?;
                if !status.success() {
                    return Err(msg(
                        "Notification setup needs native personal account approval",
                    ));
                }
                return Ok(());
            }
            async fn secret(args: &[&str]) -> Result<String> {
                let output = tokio::process::Command::new("opgate")
                    .args(["op", "--profile", "personal", "--"])
                    .args(args)
                    .stdin(std::process::Stdio::null())
                    .output()
                    .await?;
                if !output.status.success() {
                    return Err(msg(
                        "Could not resolve Apple push credentials through opgate",
                    ));
                }
                String::from_utf8(output.stdout).map_err(|_| msg("Invalid credential encoding"))
            }
            let config = crate::config::load()?;
            let vault = config
                .push_vault
                .ok_or_else(|| msg("Set pushVault in ~/.config/keywarden/config.json"))?;
            let item_id = config
                .push_item
                .ok_or_else(|| msg("Set pushItem in ~/.config/keywarden/config.json"))?;
            if [vault.as_str(), item_id.as_str()]
                .iter()
                .any(|value| value.is_empty() || value.contains(['/', '\n', '\r']))
            {
                return Err(msg("Invalid push credential reference"));
            }
            let item: Value = serde_json::from_str(
                &secret(&["item", "get", &item_id, "--vault", &vault, "--format=json"]).await?,
            )
            .map_err(|_| msg("Invalid Apple push item"))?;
            let field = |name: &str| -> Result<String> {
                item["fields"]
                    .as_array()
                    .and_then(|fields| fields.iter().find(|field| field["label"] == name))
                    .and_then(|field| field["value"].as_str())
                    .map(str::to_owned)
                    .ok_or_else(|| msg("Missing Apple push metadata"))
            };
            let key =
                secret(&["read", &format!("op://{vault}/{item_id}/apns_auth_key_p8")]).await?;
            local("POST","/v1/notification-credentials",Some(serde_json::json!({"key_id":field("apns_key_id")?,"team_id":field("apns_team_id")?,"private_key":key}))).await?;
            println!("Notifications enabled until the broker restarts. The Apple key stays in local memory.");
            Ok(())
        }
        Some("status") => {
            let mut index = 1;
            while index < args.len() {
                match args[index].as_str() {
                    "--check-provider" => index += 1,
                    "--account" | "--request" => {
                        required(args, &args[index])?;
                        if args.get(index + 1).is_none_or(|v| v.starts_with("--")) {
                            return Err(msg(format!("Missing {} value", args[index])));
                        }
                        index += 2;
                    }
                    _ => return Err(msg(format!("Unknown status option: {}", args[index]))),
                }
            }
            if args.iter().any(|arg| arg == "--check-provider") {
                if flag_value(args, "--request").is_some() {
                    return Err(msg("--check-provider cannot be combined with --request."));
                }
                return print(
                    &local(
                        "POST",
                        "/v1/access/check",
                        Some(serde_json::json!({"account":flag_value(args, "--account")})),
                    )
                    .await?,
                );
            }
            if flag_value(args, "--account").is_some() {
                return Err(msg("--account requires --check-provider."));
            }
            let path = flag_value(args, "--request")
                .map(|id| format!("/v1/session-requests/{}", crate::url_escape(&id)))
                .unwrap_or_else(|| "/v1/status".into());
            print(&local("GET", &path, None).await?)
        }
        Some("request-session") => {
            validate_session_flags(args)?;
            let client = crate::client::cli_metadata(
                flag_value(args, "--agent").as_deref(),
                flag_value(args, "--host").as_deref(),
                flag_value(args, "--session-name").as_deref(),
            )?;
            let mut body = session_body(args, "", client)?;
            let phone = match flag_value(args, "--phone") {
                Some(phone) => phone,
                None => local("GET", "/v1/status", None).await?["phoneId"]
                    .as_str()
                    .ok_or_else(|| msg("Pair your phone first"))?
                    .into(),
            };
            body["phoneId"] = Value::String(phone);
            let pending = local("POST", "/v1/session-requests", Some(body)).await?;
            print(&pending)?;
            if args.iter().any(|arg| arg == "--no-wait") {
                return Ok(());
            }
            let id = pending["request"]["id"]
                .as_str()
                .ok_or_else(|| msg("Missing request ID"))?;
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                let status = local(
                    "GET",
                    &format!("/v1/session-requests/{}", crate::url_escape(id)),
                    None,
                )
                .await?;
                match status["session"]["status"]
                    .as_str()
                    .or(status["status"].as_str())
                {
                    Some("active" | "approved") => return print(&status),
                    Some("denied" | "expired" | "cancelled" | "revoked") => {
                        print(&status)?;
                        return Err(msg("Session was not approved"));
                    }
                    _ => (),
                }
            }
        }
        Some("op") => {
            let index = args
                .iter()
                .position(|arg| arg == "--")
                .ok_or_else(|| msg("Put the op command after --"))?;
            let flags = &args[..index];
            let profile = flag_value(flags, "--profile").unwrap_or_else(|| "auto".into());
            let default_lease = if profile == "agent" {
                "direct-agent"
            } else {
                "active"
            };
            let body = serde_json::json!({"version":1,"leaseId":flag_value(flags,"--lease").unwrap_or_else(||default_lease.into()),"profile":profile,"operation":required(flags,"--operation")?,"vault":required(flags,"--vault")?,"itemId":flag_value(flags,"--item"),"field":flag_value(flags,"--field"),"args":&args[index+1..]});
            let output = local("POST", "/v1/operations", Some(body)).await?;
            print!("{}", output["stdout"].as_str().unwrap_or(""));
            eprint!("{}", output["stderr"].as_str().unwrap_or(""));
            let code = output["exitCode"].as_i64().unwrap_or(1) as i32;
            if code != 0 {
                std::process::exit(code);
            }
            Ok(())
        }
        Some("revoke") => print(
            &local(
                "POST",
                &format!(
                    "/v1/leases/{}/revoke",
                    crate::url_escape(&required(args, "--lease")?)
                ),
                Some(serde_json::json!({})),
            )
            .await?,
        ),
        Some("run") => crate::sandbox::run(args).await,
        Some("start" | "stop") => crate::service::run(args).await,
        _ => {
            print_help(None);
            Ok(())
        }
    }
}

fn simple_arguments(args: &[String]) -> Result<(&'static str, Value, u64)> {
    let command = args.first().map(String::as_str).unwrap_or("");
    let mut body = serde_json::json!({});
    let mut wait = 120;
    let mut index = 1;
    let mut seen = std::collections::HashSet::new();
    while index < args.len() {
        let flag = args[index].as_str();
        if !flag.starts_with('-') && command == "read" && body.get("reference").is_none() {
            body["reference"] = Value::String(flag.into());
            index += 1;
            continue;
        }
        let key = match flag {
            "--account" | "--profile" => "account",
            "--lease" => "leaseId",
            "--vault" if ["list", "fields"].contains(&command) => "vault",
            "--item" if command == "fields" => "item",
            "--reason" => "reason",
            "--task" => "task",
            "--wait" => "waitSeconds",
            "--query" if ["list", "vaults"].contains(&command) => "query",
            "--cursor" if ["list", "vaults"].contains(&command) => "cursor",
            "--limit" if ["list", "vaults"].contains(&command) => "limit",
            "--agent" | "--host" | "--session-name" => flag,
            "--no-request" => "requestIfNeeded",
            "--json" => "json",
            _ => {
                return Err(msg(
                    "Invalid command argument. Run keywarden read, list, or fields --help.",
                ))
            }
        };
        if !seen.insert(key) {
            return Err(msg("Duplicate command option. Supply each option once."));
        }
        if flag == "--no-request" {
            body["requestIfNeeded"] = Value::Bool(false);
            index += 1;
            continue;
        }
        if flag == "--json" {
            index += 1;
            continue;
        }
        let value = args
            .get(index + 1)
            .filter(|value| !value.trim().is_empty() && !value.starts_with("--"))
            .ok_or_else(|| msg(format!("Missing value for {flag}")))?;
        if key == "waitSeconds" {
            wait = value
                .parse::<u64>()
                .ok()
                .filter(|seconds| *seconds <= 300)
                .ok_or_else(|| msg("--wait must be 0-300 seconds."))?;
        } else if key == "limit" {
            let limit = value
                .parse::<usize>()
                .ok()
                .filter(|limit| (1..=200).contains(limit))
                .ok_or_else(|| msg("Page limit must be 1-200"))?;
            body[key] = serde_json::json!(limit);
        } else if !key.starts_with("--") {
            body[key] = Value::String(value.clone());
        }
        index += 2;
    }
    let (tool, required_fields): (&str, &[&str]) = match command {
        "read" => ("keywarden_read_secret", &["reference"]),
        "list" => ("keywarden_list_items", &["vault"]),
        "fields" => ("keywarden_list_fields", &["vault", "item"]),
        "vaults" => ("keywarden_list_vaults", &[]),
        _ => return Err(msg("Unknown command")),
    };
    if required_fields.iter().any(|key| body.get(*key).is_none()) {
        return Err(msg(
            "Missing target. Run keywarden read, list, or fields --help.",
        ));
    }
    Ok((tool, body, wait))
}

async fn simple_command(args: &[String]) -> Result<()> {
    let (tool, body, wait) = simple_arguments(args)?;
    let client = crate::client::cli_metadata(
        flag_value(args, "--agent").as_deref(),
        flag_value(args, "--host").as_deref(),
        flag_value(args, "--session-name").as_deref(),
    )?;
    let result = crate::mcp::call_from_cli(client, tool, body, wait).await?;
    if tool == "keywarden_read_secret" && !args.iter().any(|arg| arg == "--json") {
        use std::io::Write;
        std::io::stdout().lock().write_all(
            result["value"]
                .as_str()
                .ok_or_else(|| msg("Broker returned invalid secret output"))?
                .as_bytes(),
        )?;
        Ok(())
    } else {
        print(&result)
    }
}

fn number(args: &[String], name: &str, default: i64) -> Result<i64> {
    match flag_value(args, name) {
        Some(value) => value.parse().map_err(|_| msg(format!("Invalid {name}"))),
        None => Ok(default),
    }
}

fn print_help(command: Option<&str>) {
    if matches!(command, Some("read" | "list" | "fields" | "vaults")) {
        println!(
            "keywarden read op://VAULT/ITEM/FIELD [--account personal]
keywarden list --vault NAME [--account personal]
keywarden fields --vault NAME --item ID [--account personal]
keywarden vaults [--account agent]

The broker reuses approved access. Personal and work access needs phone approval.
The agents vault uses existing agent access without approval.

  --account auto|agent|personal|work  Account (default: auto)
  --profile NAME                    Alias for --account
  --lease ID                        Use one exact lease
  --reason TEXT                     Explain why access is needed
  --task TEXT                       Task shown on the phone
  --wait SECONDS                    Wait for approval, 0-300 (default: 120)
  --no-request                      Use approved access only
  --json                            Return JSON, including values for read
  --query TEXT                      Search item or vault metadata
  --limit NUMBER                    Page size, 1-200 (default: 100)
  --cursor TEXT                     Fetch the next page
  --agent NAME                      Override the detected client label
  --host NAME                       Override the host label
  --session-name TEXT               Override the detected session label

Read writes the exact value to stdout for piping. It adds no newline.
List and fields return JSON metadata. Diagnostics use stderr.
Pending approval returns a request ID and a nonzero exit code.
Repeat the same command after approval. The broker reuses the request.
Use request-session for planned access with several operations."
        );
    } else if command == Some("status") {
        println!(
            "keywarden status
  Report local permissions and broker state without calling 1Password.
keywarden status --request ID
  Report one approval request.
keywarden status --check-provider [--account agent|personal|work]
  Check fresh vault metadata using existing list access. Default: all accounts.
  Report ok, failed, or skipped for each account. No new approval or lease renewal.
  Each account uses one provider command with an eight-second timeout.
  This does not verify field reads or writes. No vault contents are returned."
        );
    } else if command == Some("request-session") {
        println!(
            "keywarden request-session --account personal --vault NAME --reason TEXT

Session scope:
  --account agent|personal|work  Account (default: agent)
  --vault NAME                  Vault; repeat for several vaults
  --all-vaults                  Every vault allowed by the account
  --operation NAME              Repeat to set exact operations (default: read + list)
  --item ID                     Restrict items; repeat for several items
  --duration SECONDS            Access duration, 1-86400 (default: 900)
  --idle-timeout SECONDS        Idle limit, 1-duration (default: 300)

Approval details:
  --reason TEXT                 Why access is needed (required)
  --task TEXT                   Task shown on the phone
  --agent NAME                  Override the detected client label
  --host NAME                   Override the host label
  --session-name TEXT           Override the detected session label
  --phone ID                    Override the paired phone
  --no-wait                     Return the request without waiting for approval

Codex and Claude Code are detected from parent processes and session metadata.
An explicit --operation read requests read access only.
Writes, creation, and deletion always require an explicit operation."
        );
    } else {
        println!("Keywarden: local 1Password access with iPhone approval
  vaults [--account agent|personal|work]
  read op://VAULT/ITEM/FIELD [--account personal]
  list --vault NAME [--account personal]
  fields --vault NAME --item ID [--account personal]
    Reuses access, requests approval when needed, then returns the result.
    Read outputs raw bytes for pipes. List and fields output JSON metadata.
  start | stop | status
  pairing-qr [--legacy] [--output path]
  request-session --account personal --vault NAME | --all-vaults --reason TEXT
    Defaults: read + list, 900 seconds; detects Codex or Claude Code.
    Run keywarden request-session --help for all scope and identity options.
  status --request ID
  status --check-provider [--account agent|personal|work]
  retry --request ID | cancel --request ID
  op [--lease ID] [--profile personal] --operation read --vault NAME -- read op://NAME/ITEM/FIELD --no-newline
  mcp
  notifications enable
  revoke --lease ID
  run --workspace PATH -- COMMAND [ARGS...]
  serve --opgate");
    }
}

fn validate_session_flags(args: &[String]) -> Result<()> {
    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "--all-vaults" | "--no-wait" => index += 1,
            "--account" | "--vault" | "--reason" | "--operation" | "--item" | "--duration"
            | "--idle-timeout" | "--agent" | "--host" | "--session-name" | "--task" | "--phone" => {
                if args
                    .get(index + 1)
                    .is_none_or(|value| value.is_empty() || value.starts_with("--"))
                {
                    return Err(msg(format!(
                        "Missing value for {}. Run keywarden request-session --help.",
                        args[index]
                    )));
                }
                index += 2;
            }
            unknown => {
                return Err(msg(format!(
                    "Unknown option {unknown}. Run keywarden request-session --help."
                )))
            }
        }
    }
    Ok(())
}

fn session_body(args: &[String], phone: &str, client: crate::ClientMetadata) -> Result<Value> {
    let operations = repeated(args, "--operation");
    let operations = if operations.is_empty() {
        crate::default_session_operations()
    } else {
        operations
    };
    if operations
        .iter()
        .any(|op| !["read", "list", "write", "create", "delete"].contains(&op.as_str()))
    {
        return Err(msg(
            "Invalid operation. Use read, list, write, create, or delete.",
        ));
    }
    let account = flag_value(args, "--account").unwrap_or_else(|| "agent".into());
    if !["agent", "personal", "work"].contains(&account.as_str()) {
        return Err(msg("Invalid account. Use agent, personal, or work."));
    }
    let all_vaults = args.iter().any(|arg| arg == "--all-vaults");
    let vaults = repeated(args, "--vault");
    if all_vaults == !vaults.is_empty() {
        return Err(msg("Use --vault NAME or --all-vaults, but not both."));
    }
    if vaults.iter().any(|vault| vault == "*") {
        return Err(msg("Use --all-vaults to request every allowed vault."));
    }
    let items = repeated(args, "--item");
    let duration = number(args, "--duration", 900)?;
    let idle = number(args, "--idle-timeout", 300)?;
    if !(1..=86400).contains(&duration) || !(1..=duration).contains(&idle) {
        return Err(msg("Invalid duration. --duration must be 1-86400 seconds and --idle-timeout must be 1-duration."));
    }
    let reason = required(args, "--reason")?;
    Ok(serde_json::json!({
        "agent":client.display_name,"host":client.host,"client":client,
        "phoneId":phone,"reason":reason,"intent":{"reason":reason,"task":flag_value(args,"--task")},
        "scope":{"accounts":[account],"vaults":if all_vaults {vec!["*".to_owned()]} else {vaults},
            "items":if items.is_empty(){serde_json::json!("all")}else{serde_json::json!(items)},"operations":operations},
        "durationSeconds":duration,"idleTimeoutSeconds":idle
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command_args(args: &[&str]) -> Vec<String> {
        args.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn simple_commands_infer_scope_and_keep_outputs_explicit() {
        let (tool, body, wait) = simple_arguments(&command_args(&[
            "read",
            "op://agents/item/field",
            "--json",
            "--no-request",
        ]))
        .unwrap();
        assert_eq!(tool, "keywarden_read_secret");
        assert_eq!(body["reference"], "op://agents/item/field");
        assert_eq!(body["requestIfNeeded"], false);
        assert!(body.get("operation").is_none());
        assert_eq!(wait, 120);
        let (tool, body, wait) = simple_arguments(&command_args(&[
            "fields",
            "--vault",
            "v",
            "--item",
            "i",
            "--profile",
            "personal",
            "--wait",
            "0",
        ]))
        .unwrap();
        assert_eq!(tool, "keywarden_list_fields");
        assert_eq!(body["account"], "personal");
        assert_eq!(body["item"], "i");
        assert_eq!(wait, 0);
    }

    #[test]
    fn simple_commands_reject_missing_conflicting_and_unknown_options() {
        for args in [
            vec!["read"],
            vec!["list", "--vault"],
            vec!["fields", "--vault", "v"],
            vec!["read", "op://v/i/f", "--vault", "other"],
            vec![
                "list",
                "--vault",
                "v",
                "--account",
                "personal",
                "--profile",
                "work",
            ],
            vec!["list", "--vault", "v", "--wait", "301"],
            vec!["list", "--vault", "v", "--wait", "-1"],
            vec!["list", "--vault", "v", "--unknown", "x"],
        ] {
            assert!(simple_arguments(&command_args(&args)).is_err(), "{args:?}");
        }
    }

    fn args(extra: &[&str]) -> Vec<String> {
        [
            vec![
                "request-session",
                "--account",
                "personal",
                "--vault",
                "Test vault",
                "--reason",
                "Test access",
            ],
            extra.to_vec(),
        ]
        .concat()
        .into_iter()
        .map(str::to_owned)
        .collect()
    }

    #[test]
    fn default_session_allows_read_and_list_without_writes() {
        let body = session_body(
            &args(&[]),
            "phone-test",
            crate::ClientMetadata::manual("Codex", "Mac"),
        )
        .unwrap();
        assert_eq!(
            body["scope"]["operations"],
            serde_json::json!(["read", "list"])
        );
        assert_eq!(body["scope"]["vaults"], serde_json::json!(["Test vault"]));
        assert_eq!(body["client"]["displayName"], "Codex");
        assert_eq!(body["intent"]["reason"], "Test access");
    }

    #[test]
    fn explicit_operations_replace_defaults() {
        for operation in ["read", "list", "write", "create", "delete"] {
            let body = session_body(
                &args(&["--operation", operation]),
                "phone-test",
                crate::ClientMetadata::manual("Codex", "Mac"),
            )
            .unwrap();
            assert_eq!(body["scope"]["operations"], serde_json::json!([operation]));
        }
        let body = session_body(
            &args(&["--vault", "Second vault", "--task", "Deploy"]),
            "phone-test",
            crate::ClientMetadata::manual("Codex", "Mac"),
        )
        .unwrap();
        assert_eq!(
            body["scope"]["vaults"],
            serde_json::json!(["Test vault", "Second vault"])
        );
        assert_eq!(body["intent"]["task"], "Deploy");
    }

    #[test]
    fn malformed_operation_flag_cannot_silently_expand_scope() {
        for extra in [
            vec!["--operation"],
            vec!["--operation", "--no-wait"],
            vec!["--op", "read"],
        ] {
            assert!(validate_session_flags(&args(&extra)).is_err());
        }
        assert!(session_body(
            &args(&["--all-vaults"]),
            "phone-test",
            crate::ClientMetadata::manual("Codex", "Mac")
        )
        .is_err());
    }
}
