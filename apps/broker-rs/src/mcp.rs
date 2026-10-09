//! Local stdio adapter. All access passes through the broker's lease checks.
use crate::client::mcp_metadata as client_metadata;
#[cfg(test)]
use crate::client::normalize_client;
use crate::{cli, command, msg, ClientMetadata, OperationRequest, Result, Value, MAX_BODY_BYTES};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::time::{sleep, Duration, Instant};

const PROTOCOL_VERSION: &str = "2025-06-18";
const AUTO_ACCESS_DURATION_SECONDS: i64 = 900;
const AUTO_ACCESS_IDLE_TIMEOUT_SECONDS: i64 = 300;
const AUTO_ACCESS_WAIT_SECONDS: u64 = 25;

struct Server {
    initialized: bool,
    ready: bool,
    last_request: Option<String>,
    client: ClientMetadata,
    // Approval metadata only. Never cache secret values.
    approvals: HashMap<String, Value>,
    // Pending automatic requests, keyed by the exact operation scope.
    auto_requests: HashMap<String, String>,
}

impl Default for Server {
    fn default() -> Self {
        Self {
            initialized: false,
            ready: false,
            last_request: None,
            client: ClientMetadata::manual("MCP client", "Mac"),
            approvals: HashMap::new(),
            auto_requests: HashMap::new(),
        }
    }
}

// CLI shortcuts use the same scope selection, approval, and output filtering.
pub(crate) async fn call_from_cli(
    client: ClientMetadata,
    name: &str,
    mut args: Value,
    wait_seconds: u64,
) -> Result<Value> {
    let mut server = Server {
        client,
        ..Server::default()
    };
    let deadline = Instant::now() + Duration::from_secs(wait_seconds);
    let mut reported = false;
    loop {
        args["waitSeconds"] = json!(deadline
            .saturating_duration_since(Instant::now())
            .as_secs()
            .min(25));
        let result = server.call(name, args.clone()).await;
        match &result {
            Err(error)
                if error_details(error)["error"]["code"] == "approval_required"
                    && Instant::now() < deadline =>
            {
                if !reported {
                    eprintln!("Approval is pending on your phone. This command will continue after approval.");
                    reported = true;
                }
                sleep(Duration::from_millis(250)).await;
            }
            _ => return result,
        }
    }
}

pub async fn run() -> Result<()> {
    let mut input = BufReader::new(tokio::io::stdin());
    let mut output = tokio::io::stdout();
    let mut server = Server::default();
    loop {
        let mut line = Vec::new();
        let count = (&mut input)
            .take((MAX_BODY_BYTES + 1) as u64)
            .read_until(b'\n', &mut line)
            .await?;
        if count == 0 {
            return Ok(());
        }
        // Close on an oversized frame. Never echo request data in diagnostics.
        if count > MAX_BODY_BYTES {
            return Err(msg("MCP request exceeds the size limit"));
        }
        let response = match serde_json::from_slice::<Value>(&line) {
            Ok(request) => server.handle(request).await,
            Err(_) => Some(rpc_error(Value::Null, -32700, "Invalid JSON")),
        };
        if let Some(response) = response {
            output.write_all(&serde_json::to_vec(&response)?).await?;
            output.write_all(b"\n").await?;
            output.flush().await?;
        }
    }
}

impl Server {
    async fn handle(&mut self, request: Value) -> Option<Value> {
        let id = request.get("id").cloned();
        let valid_id = id
            .as_ref()
            .is_none_or(|id| id.is_string() || id.is_i64() || id.is_u64());
        if !request.is_object()
            || request["jsonrpc"] != "2.0"
            || !request["method"].is_string()
            || !valid_id
        {
            return Some(rpc_error(Value::Null, -32600, "Invalid JSON-RPC request"));
        }
        let method = request["method"].as_str().unwrap();
        if id.is_none() {
            if method == "notifications/initialized" && self.initialized {
                self.ready = true;
            }
            return None;
        }
        let id = id.unwrap();
        let params = request.get("params").cloned().unwrap_or(json!({}));
        if !params.is_object() {
            return Some(rpc_error(id, -32602, "Parameters must be an object"));
        }
        let result = match method {
            "initialize" => {
                if self.initialized {
                    return Some(rpc_error(id, -32600, "Already initialized"));
                }
                if !params["protocolVersion"].is_string()
                    || !params["capabilities"].is_object()
                    || !params["clientInfo"]["name"].is_string()
                    || !params["clientInfo"]["version"].is_string()
                {
                    return Some(rpc_error(id, -32602, "Invalid initialization parameters"));
                }
                let version = match params["protocolVersion"].as_str().unwrap() {
                    "2024-11-05" => "2024-11-05",
                    "2025-03-26" => "2025-03-26",
                    "2025-11-25" => "2025-11-25",
                    _ => PROTOCOL_VERSION,
                };
                let metadata = match client_metadata(&params, version) {
                    Ok(metadata) => metadata,
                    Err(error) => return Some(rpc_error(id, -32602, &error.to_string())),
                };
                self.client = metadata;
                self.initialized = true;
                json!({"protocolVersion":version,"capabilities":{"tools":{}},
                    "serverInfo":{"name":"keywarden-1password","title":format!("Keywarden 1Password for {}", self.client.display_name),"version":env!("CARGO_PKG_VERSION")},
                    "instructions":"Manage 1Password access through the local Keywarden broker. Call read, list, or field discovery directly; access is reused or requested automatically. Use field references returned by discovery. Use keywarden_request_access for a planned session with several operations. Metadata and errors are JSON in text and structuredContent. Keywarden identifies the MCP client from initialize metadata and shows it on phone approvals. Request phone approval for personal and work accounts. The agent account uses its existing local scope. Provide a task and reason for approval intent. Read values from structuredContent in code mode. Never print or persist secret values. Client metadata is display context and does not grant access."})
            }
            "ping" => json!({}),
            _ if !self.ready => {
                return Some(rpc_error(id, -32002, "Initialize the MCP session first"))
            }
            "tools/list" => {
                if params.get("cursor").is_some() {
                    return Some(rpc_error(id, -32602, "This tool list has no cursor"));
                }
                json!({"tools":catalog()})
            }
            "tools/call" => {
                let Some(name) = params["name"].as_str() else {
                    return Some(rpc_error(id, -32602, "Missing tool name"));
                };
                if !catalog()
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|tool| tool["name"] == name)
                {
                    return Some(rpc_error(id, -32602, "Unknown tool"));
                }
                let args = params.get("arguments").cloned().unwrap_or(json!({}));
                match self.call(name, args).await {
                    Ok(data) => {
                        let text = tool_text(name, &data);
                        json!({"content":[{"type":"text","text":text}],"structuredContent":data,"isError":false})
                    }
                    Err(error) => {
                        let details = error_with_delivery(&error).await;
                        tool_failure(details)
                    }
                }
            }
            _ => return Some(rpc_error(id, -32601, "Method not found")),
        };
        Some(json!({"jsonrpc":"2.0","id":id,"result":result}))
    }

    async fn call(&mut self, name: &str, args: Value) -> Result<Value> {
        match name {
            "keywarden_manage_request" => {
                let args: ManageArgs = parse(args)?;
                check_text(&args.request_id)?;
                if !["retry", "cancel"].contains(&args.action.as_str()) {
                    return Err(msg("Use action retry or cancel"));
                }
                cli::local(
                    "POST",
                    &format!(
                        "/v1/session-requests/{}/{}",
                        crate::url_escape(&args.request_id),
                        args.action
                    ),
                    Some(json!({})),
                )
                .await?;
                self.access_status(&args.request_id, 0).await
            }
            "keywarden_list_vaults" => {
                let args: VaultArgs = parse(args)?;
                check_wait(args.wait_seconds)?;
                args.page.validate()?;
                if !["agent", "personal", "work"].contains(&args.account.as_str()) {
                    return Err(msg("Invalid account"));
                }
                let body = json!({"account":args.account,"leaseId":args.lease_id});
                let result = cli::local("POST", "/v1/vaults", Some(body.clone())).await;
                let result = match result {
                    Ok(result) => result,
                    Err(error)
                        if args.request_if_needed
                            && args.lease_id == "active"
                            && error.to_string().starts_with("No active lease matches") =>
                    {
                        let status = Box::pin(self.call("keywarden_request_access", json!({"account":args.account,"allVaults":true,"operations":["list"],"reason":args.reason.unwrap_or_else(|| "Discover allowed 1Password vaults".into()),"task":args.task,"waitSeconds":args.wait_seconds}))).await?;
                        if status["status"] != "active" {
                            let id = status["requestId"].as_str().unwrap_or("");
                            let message = match status["status"].as_str() {
                                Some("pending") => "Approval is pending",
                                Some("denied") => "Approval was denied",
                                Some("cancelled") => "Approval was cancelled",
                                Some("expired") => "Approval expired",
                                _ => "Approval is unavailable",
                            };
                            return Err(msg(format!("{message}. requestId={id}.")));
                        }
                        cli::local("POST", "/v1/vaults", Some(body)).await?
                    }
                    Err(error) => return Err(error),
                };
                let page = paginate(
                    result["vaults"].clone(),
                    &args.page,
                    &format!("vaults:{}", args.account),
                )?;
                Ok(
                    json!({"account":args.account,"vaults":page["items"],"totalCount":page["totalCount"],"nextCursor":page["nextCursor"]}),
                )
            }
            "keywarden_request_access" => {
                let args: AccessArgs = parse(args)?;
                args.validate()?;
                if args.account == "agent" {
                    return self.direct_agent_access(&args);
                }
                let agent = args
                    .agent
                    .clone()
                    .filter(|value| value != "mcp-agent")
                    .unwrap_or_else(|| self.client.display_name.clone());
                let host = args
                    .host
                    .clone()
                    .filter(|value| value != "Mac")
                    .unwrap_or_else(|| self.client.host.clone());
                let mut client = self.client.clone();
                if let Some(session_name) = &args.session_name {
                    client.session_name = Some(session_name.clone());
                }
                if let Some(session_id) = &args.session_id {
                    client.session_id = Some(session_id.clone());
                }
                let status = cli::local("GET", "/v1/status", None).await?;
                let phone = status["phoneId"]
                    .as_str()
                    .filter(|id| !id.is_empty())
                    .ok_or_else(|| msg("Pair your phone first"))?;
                let pending = cli::local("POST", "/v1/session-requests", Some(json!({
                    "agent":agent,"host":host,"phoneId":phone,"reason":args.reason,
                    "intent":{"task":args.task,"reason":args.reason},
                    "client":client,
                    "scope":{"accounts":[args.account],"vaults":if args.all_vaults { vec!["*".to_owned()] } else { args.vaults },
                        "items":args.items.map_or(json!("all"), |items| json!(items)),"operations":args.operations},
                    "durationSeconds":args.duration_seconds,"idleTimeoutSeconds":args.idle_timeout_seconds
                }))).await?;
                let id = pending["request"]["id"]
                    .as_str()
                    .ok_or_else(|| msg("Broker returned no request ID"))?
                    .to_owned();
                self.last_request = Some(id.clone());
                self.access_status(&id, args.wait_seconds).await
            }
            "keywarden_access_status" => {
                let args: StatusArgs = parse(args)?;
                check_wait(args.wait_seconds)?;
                if args.check_provider {
                    if args.request_id.is_some() || args.wait_seconds != 0 {
                        return Err(msg(
                            "checkProvider cannot be combined with requestId or waitSeconds.",
                        ));
                    }
                    return cli::local(
                        "POST",
                        "/v1/access/check",
                        Some(json!({"account":args.account})),
                    )
                    .await;
                }
                if args.account.is_some() {
                    return Err(msg("account requires checkProvider=true."));
                }
                let Some(id) = args.request_id else {
                    return cli::local("GET", "/v1/access", None).await;
                };
                check_text(&id)?;
                if id == "direct-agent" {
                    return Ok(direct_agent_status());
                }
                self.access_status(&id, args.wait_seconds).await
            }
            "keywarden_read_secret" => {
                let args: ReadArgs = parse(args)?;
                check_wait(args.wait_seconds)?;
                let mut operation = secret_operation(&args.reference, &args.selection)?;
                self.select_or_request(
                    &mut operation,
                    args.request_if_needed,
                    args.reason.as_deref(),
                    args.task.as_deref(),
                    args.wait_seconds,
                )
                .await?;
                let result = cli::local(
                    "POST",
                    "/v1/operations",
                    Some(serde_json::to_value(operation)?),
                )
                .await?;
                // op stderr can include sensitive output. Do not forward it.
                if result["exitCode"] != 0 {
                    return Err(provider_failure(&result));
                }
                let value = result["stdout"]
                    .as_str()
                    .ok_or_else(|| msg("Broker returned invalid secret output"))?;
                Ok(json!({"reference":args.reference,"value":value}))
            }
            "keywarden_list_items" => {
                let args: ListArgs = parse(args)?;
                check_wait(args.wait_seconds)?;
                args.page.validate()?;
                args.selection.validate()?;
                check_text(&args.vault)?;
                let page_scope = format!("items:{}:{}", args.selection.account, args.vault);
                let mut operation = OperationRequest {
                    version: 1,
                    lease_id: args.selection.lease_id,
                    profile: args.selection.account,
                    operation: "list".into(),
                    vault: Some(args.vault.clone()),
                    item_id: None,
                    field: None,
                    args: vec![
                        "item".into(),
                        "list".into(),
                        "--vault".into(),
                        args.vault.clone(),
                        "--format=json".into(),
                    ],
                };
                command::target(&operation)?;
                self.select_or_request(
                    &mut operation,
                    args.request_if_needed,
                    args.reason.as_deref(),
                    args.task.as_deref(),
                    args.wait_seconds,
                )
                .await?;
                let result = cli::local(
                    "POST",
                    "/v1/operations",
                    Some(serde_json::to_value(operation)?),
                )
                .await?;
                if result["exitCode"] != 0 {
                    return Err(provider_failure(&result));
                }
                let items: Value = serde_json::from_str(result["stdout"].as_str().unwrap_or(""))
                    .map_err(|_| msg("Broker returned invalid item output"))?;
                if !items.is_array() {
                    return Err(msg("Broker returned invalid item output"));
                }
                let page = paginate(
                    crate::discovery::item_metadata(&items)?,
                    &args.page,
                    &page_scope,
                )?;
                Ok(
                    json!({"vault":args.vault,"items":page["items"],"totalCount":page["totalCount"],"nextCursor":page["nextCursor"]}),
                )
            }
            "keywarden_list_fields" => {
                let args: FieldsArgs = parse(args)?;
                check_wait(args.wait_seconds)?;
                args.selection.validate()?;
                check_text(&args.vault)?;
                check_text(&args.item)?;
                let mut operation = OperationRequest {
                    version: 1,
                    lease_id: args.selection.lease_id,
                    profile: args.selection.account,
                    operation: "read".into(),
                    vault: Some(args.vault.clone()),
                    item_id: Some(args.item.clone()),
                    field: None,
                    args: vec![
                        "item".into(),
                        "get".into(),
                        args.item.clone(),
                        "--vault".into(),
                        args.vault.clone(),
                        "--format=json".into(),
                    ],
                };
                command::target(&operation)?;
                self.select_or_request(
                    &mut operation,
                    args.request_if_needed,
                    args.reason.as_deref(),
                    args.task.as_deref(),
                    args.wait_seconds,
                )
                .await?;
                let result = cli::local(
                    "POST",
                    "/v1/operations",
                    Some(serde_json::to_value(operation)?),
                )
                .await?;
                if result["exitCode"] != 0 {
                    return Err(provider_failure(&result));
                }
                let item: Value = serde_json::from_str(result["stdout"].as_str().unwrap_or(""))
                    .map_err(|_| msg("Broker returned invalid item metadata"))?;
                let fields = field_metadata(&item, &args.vault, &args.item)?;
                Ok(json!({"vault":args.vault,"item":args.item,"fields":fields}))
            }
            _ => Err(msg("Unknown tool")),
        }
    }

    fn direct_agent_access(&mut self, args: &AccessArgs) -> Result<Value> {
        if args.all_vaults || args.vaults != ["agents"] {
            return Err(msg("The direct agent scope only covers the agents vault"));
        }
        if args.items.is_some() {
            return Err(msg("The direct agent scope covers all agents items"));
        }
        self.last_request = Some("direct-agent".into());
        let mut status = direct_agent_status_with_operations(&args.operations);
        let mut client = self.client.clone();
        if let Some(name) = &args.session_name {
            client.session_name = Some(name.clone());
        }
        if let Some(id) = &args.session_id {
            client.session_id = Some(id.clone());
        }
        status["client"] = serde_json::to_value(client)?;
        status["intent"] = json!({"task":args.task,"reason":args.reason});
        Ok(status)
    }

    async fn access_status(&mut self, id: &str, wait_seconds: u64) -> Result<Value> {
        let deadline = Instant::now() + Duration::from_secs(wait_seconds);
        loop {
            let response = cli::local(
                "GET",
                &format!("/v1/session-requests/{}", crate::url_escape(id)),
                None,
            )
            .await?;
            let mut status = response["session"]["status"]
                .as_str()
                .or(response["status"].as_str())
                .unwrap_or("unknown");
            if status == "pending"
                && response["request"]["expiresAt"]
                    .as_str()
                    .is_some_and(|expires| {
                        crate::timestamp(expires).is_ok_and(|date| date <= chrono::Utc::now())
                    })
            {
                status = "expired";
            }
            if status != "pending" || Instant::now() >= deadline {
                if status == "active" {
                    self.approvals.insert(id.to_owned(), response.clone());
                } else {
                    self.approvals.remove(id);
                }
                return Ok(
                    json!({"requestId":id,"status":status,"scope":response["request"]["scope"],
                    "leaseId":response["leaseId"],"expiresAt":response["session"]["expiresAt"],"idleUntil":response["session"]["idleUntil"],
                    "client":response["request"]["client"],"intent":response["request"]["intent"],"delivery":response["delivery"]}),
                );
            }
            sleep(Duration::from_millis(250)).await;
        }
    }

    async fn select_or_request(
        &mut self,
        operation: &mut OperationRequest,
        request_if_needed: bool,
        reason: Option<&str>,
        task: Option<&str>,
        wait_seconds: u64,
    ) -> Result<()> {
        match self.select_lease(operation) {
            Ok(()) => return Ok(()),
            Err(error) if !error.to_string().starts_with("No active lease matches") => {
                return Err(error)
            }
            Err(_) => {}
        }
        // The broker also holds leases approved through CLI or another MCP process.
        // Resolve those before creating a new phone request. Do not retry rejected
        // explicit or cached leases against another lease.
        match cli::local(
            "POST",
            "/v1/operations/resolve",
            Some(serde_json::to_value(&*operation)?),
        )
        .await
        {
            Ok(resolved) => {
                operation.lease_id = resolved["leaseId"]
                    .as_str()
                    .ok_or_else(|| msg("Broker returned no lease ID"))?
                    .into();
                operation.profile = resolved["account"]
                    .as_str()
                    .ok_or_else(|| msg("Broker returned no account"))?
                    .into();
                return Ok(());
            }
            Err(error)
                if request_if_needed
                    && error.to_string().starts_with("No active lease matches") => {}
            Err(error) => return Err(error),
        }
        self.request_for_operation(operation, reason, task, wait_seconds)
            .await?;
        self.select_lease(operation)
    }

    async fn request_for_operation(
        &mut self,
        operation: &OperationRequest,
        reason: Option<&str>,
        task: Option<&str>,
        wait_seconds: u64,
    ) -> Result<()> {
        check_wait(wait_seconds)?;
        let account =
            match operation.profile.as_str() {
                "personal" | "work" => operation.profile.clone(),
                "auto" => return Err(msg(
                    "Account is required for automatic approval. Supply account personal or work.",
                )),
                "agent" => {
                    return Err(msg(
                        "The agent scope should use the agents vault without approval.",
                    ))
                }
                _ => return Err(msg("Invalid account")),
            };
        let vault = operation
            .vault
            .clone()
            .ok_or_else(|| msg("Operation must name a vault"))?;
        let key = auto_request_key(operation);
        let mut request_id = self.auto_requests.get(&key).cloned();
        loop {
            if request_id.is_none() {
                let status = cli::local("GET", "/v1/status", None).await?;
                let phone = status["phoneId"]
                    .as_str()
                    .filter(|id| !id.is_empty())
                    .ok_or_else(|| msg("Pair your phone first"))?;
                let default_reason = match operation.operation.as_str() {
                    "list" => "List 1Password item metadata",
                    _ => "Read a requested 1Password field",
                };
                let request_reason = reason
                    .filter(|value| !value.trim().is_empty())
                    .unwrap_or(default_reason);
                check_text(request_reason)?;
                if let Some(value) = task {
                    check_text(value)?;
                }
                let pending = cli::local("POST", "/v1/session-requests", Some(json!({
                    "agent": self.client.display_name,
                    "host": self.client.host,
                    "phoneId": phone,
                    "reason": request_reason,
                    "intent": {"task": task.or(self.client.session_name.as_deref()).or(Some("Complete the current agent task")), "reason": request_reason},
                    "client": self.client,
                    "scope": {
                        "accounts": [account],
                        "vaults": [vault],
                        "items": if operation.operation == "read" { json!([operation.item_id.clone().ok_or_else(|| msg("Operation must name an item"))?]) } else { json!("all") },
                        "operations": [operation.operation.clone()]
                    },
                    "durationSeconds": AUTO_ACCESS_DURATION_SECONDS,
                    "idleTimeoutSeconds": AUTO_ACCESS_IDLE_TIMEOUT_SECONDS
                }))).await?;
                let id = pending["request"]["id"]
                    .as_str()
                    .ok_or_else(|| msg("Broker returned no request ID"))?
                    .to_owned();
                self.auto_requests.insert(key.clone(), id.clone());
                request_id = Some(id);
            }
            let id = request_id.clone().expect("automatic request ID is set");
            self.last_request = Some(id.clone());
            let response = match self.access_status(&id, wait_seconds).await {
                Ok(response) => response,
                Err(error) if error.to_string().contains("Unknown session request") => {
                    self.auto_requests.remove(&key);
                    request_id = None;
                    continue;
                }
                Err(error) => return Err(error),
            };
            match response["status"].as_str().unwrap_or("unknown") {
                "active" => {
                    self.auto_requests.remove(&key);
                    return Ok(());
                }
                "pending" => return Err(msg(format!("Approval is pending. requestId={id}. Approve on the phone, then repeat this tool call."))),
                "denied" => {
                    self.auto_requests.remove(&key);
                    return Err(msg(format!("Approval was denied. requestId={id}. Request access again if needed.")));
                }
                "cancelled" => {
                    self.auto_requests.remove(&key);
                    return Err(msg(format!("Approval was cancelled. requestId={id}.")));
                }
                "expired" => {
                    self.auto_requests.remove(&key);
                    return Err(msg(format!("Approval expired. requestId={id}. Request access again if needed.")));
                }
                status => return Err(msg(format!("Approval ended with status {status}. requestId={id}."))),
            }
        }
    }

    fn select_lease(&self, operation: &mut OperationRequest) -> Result<()> {
        if operation.lease_id != "active" {
            return Ok(());
        }
        let (_, item) = command::target(operation)?;
        let matches: Vec<&Value> = self
            .approvals
            .values()
            .filter(|approval| {
                let scope = &approval["request"]["scope"];
                let contains = |key: &str, needle: &str| {
                    scope[key]
                        .as_array()
                        .is_some_and(|values| values.iter().any(|value| value == needle))
                };
                (operation.profile == "auto" || contains("accounts", &operation.profile))
                    && contains("operations", &operation.operation)
                    && (contains("vaults", "*")
                        || contains("vaults", operation.vault.as_deref().unwrap_or("")))
                    && (scope["items"] == "all"
                        || item.as_ref().is_some_and(|item| contains("items", item)))
            })
            .collect();
        if matches.len() > 1 {
            return Err(msg("Multiple approvals match. Supply account or leaseId."));
        }
        if let Some(approval) = matches.first() {
            operation.lease_id = approval["leaseId"]
                .as_str()
                .ok_or_else(|| msg("Broker returned no lease ID"))?
                .to_owned();
        } else if operation.vault.as_deref() == Some("agents")
            && ["auto", "agent"].contains(&operation.profile.as_str())
        {
            operation.lease_id = "direct-agent".into();
            operation.profile = "agent".into();
        } else {
            return Err(msg("No active lease matches this operation. Request access for the account, vault, item, and operation first."));
        }
        // The broker checks expiry and revocation on every call. Never retry a
        // rejected cached lease against another lease automatically.
        Ok(())
    }
}

fn direct_agent_status() -> Value {
    direct_agent_status_with_operations(&["read".into(), "list".into()])
}

fn direct_agent_status_with_operations(operations: &[String]) -> Value {
    json!({
        "requestId":"direct-agent",
        "status":"active",
        "scope":{"accounts":["agent"],"vaults":["agents"],"items":"all","operations":operations},
        "leaseId":"direct-agent",
        "expiresAt":null,
        "idleUntil":null,
        "client":null,
        "intent":null
    })
}

fn secret_operation(reference: &str, selection: &Selection) -> Result<OperationRequest> {
    selection.validate()?;
    check_text(reference)?;
    let parts: Vec<&str> = reference
        .strip_prefix("op://")
        .ok_or_else(|| msg("Use an op://vault/item/field reference"))?
        .split('/')
        .collect();
    if !(3..=4).contains(&parts.len()) {
        return Err(msg(
            "Use an op://vault/item/field or op://vault/item/section/field reference",
        ));
    }
    let operation = OperationRequest {
        version: 1,
        lease_id: selection.lease_id.clone(),
        profile: selection.account.clone(),
        operation: "read".into(),
        vault: Some(parts[0].into()),
        item_id: Some(parts[1].into()),
        field: Some(parts[2..].join("/")),
        args: vec!["read".into(), reference.into(), "--no-newline".into()],
    };
    command::target(&operation)?;
    Ok(operation)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AccessArgs {
    account: String,
    #[serde(default)]
    all_vaults: bool,
    #[serde(default)]
    vaults: Vec<String>,
    items: Option<Vec<String>>,
    #[serde(default = "crate::default_session_operations")]
    operations: Vec<String>,
    #[serde(default = "duration")]
    duration_seconds: i64,
    #[serde(default = "idle")]
    idle_timeout_seconds: i64,
    reason: String,
    #[serde(default)]
    task: Option<String>,
    session_name: Option<String>,
    session_id: Option<String>,
    agent: Option<String>,
    host: Option<String>,
    #[serde(default)]
    wait_seconds: u64,
}

impl AccessArgs {
    fn validate(&self) -> Result<()> {
        if !["agent", "personal", "work"].contains(&self.account.as_str()) {
            return Err(msg("Invalid account"));
        }
        if (self.all_vaults && !self.vaults.is_empty())
            || (!self.all_vaults && self.vaults.is_empty())
        {
            return Err(msg("Supply allVaults or a nonempty vaults array"));
        }
        if self.vaults.iter().any(|vault| vault == "*") {
            return Err(msg("Use allVaults to request every allowed vault"));
        }
        check_text(&self.reason)?;
        if let Some(task) = &self.task {
            check_text(task)?;
        }
        if let Some(session_name) = &self.session_name {
            check_text(session_name)?;
        }
        if let Some(session_id) = &self.session_id {
            check_text(session_id)?;
        }
        if let Some(agent) = &self.agent {
            check_text(agent)?;
        }
        if let Some(host) = &self.host {
            check_text(host)?;
        }
        for vault in &self.vaults {
            check_text(vault)?;
        }
        if let Some(items) = &self.items {
            if items.is_empty() {
                return Err(msg("Items must not be empty"));
            }
            for item in items {
                check_text(item)?;
            }
        }
        if self.operations.is_empty()
            || self
                .operations
                .iter()
                .any(|op| !["read", "list", "write", "create", "delete"].contains(&op.as_str()))
        {
            return Err(msg("Invalid operations"));
        }
        if !(1..=86400).contains(&self.duration_seconds)
            || !(1..=self.duration_seconds).contains(&self.idle_timeout_seconds)
        {
            return Err(msg("Invalid duration. durationSeconds must be 1-86400 seconds and idleTimeoutSeconds must be 1-durationSeconds."));
        }
        check_wait(self.wait_seconds)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StatusArgs {
    request_id: Option<String>,
    #[serde(default)]
    wait_seconds: u64,
    #[serde(default)]
    check_provider: bool,
    account: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Selection {
    #[serde(default = "active")]
    lease_id: String,
    #[serde(default = "auto")]
    account: String,
}
impl Selection {
    fn validate(&self) -> Result<()> {
        if !["auto", "agent", "personal", "work"].contains(&self.account.as_str()) {
            return Err(msg("Invalid account"));
        }
        check_text(&self.lease_id)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReadArgs {
    reference: String,
    #[serde(flatten)]
    selection: Selection,
    #[serde(default = "request_if_needed")]
    request_if_needed: bool,
    reason: Option<String>,
    task: Option<String>,
    #[serde(default = "auto_wait")]
    wait_seconds: u64,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ListArgs {
    vault: String,
    #[serde(flatten)]
    selection: Selection,
    #[serde(default = "request_if_needed")]
    request_if_needed: bool,
    reason: Option<String>,
    task: Option<String>,
    #[serde(default = "auto_wait")]
    wait_seconds: u64,
    #[serde(flatten)]
    page: PageArgs,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct VaultArgs {
    #[serde(default = "agent_account")]
    account: String,
    #[serde(default = "active")]
    lease_id: String,
    #[serde(default = "request_if_needed")]
    request_if_needed: bool,
    reason: Option<String>,
    task: Option<String>,
    #[serde(default = "auto_wait")]
    wait_seconds: u64,
    #[serde(flatten)]
    page: PageArgs,
}
fn agent_account() -> String {
    "agent".into()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ManageArgs {
    request_id: String,
    action: String,
}

#[derive(Deserialize)]
struct PageArgs {
    query: Option<String>,
    cursor: Option<String>,
    #[serde(default = "page_limit")]
    limit: usize,
}
fn page_limit() -> usize {
    100
}
impl PageArgs {
    fn validate(&self) -> Result<()> {
        if !(1..=200).contains(&self.limit) {
            return Err(msg("Page limit must be 1-200"));
        }
        if let Some(query) = &self.query {
            check_text(query)?;
        }
        if let Some(cursor) = &self.cursor {
            check_text(cursor)?;
        }
        Ok(())
    }
}

fn paginate(items: Value, args: &PageArgs, scope: &str) -> Result<Value> {
    args.validate()?;
    let mut items = items
        .as_array()
        .ok_or_else(|| msg("Broker returned invalid metadata"))?
        .clone();
    let query = args.query.as_deref().unwrap_or("").to_lowercase();
    items.retain(|item| {
        ["title", "name", "id", "category"].iter().any(|key| {
            item[*key]
                .as_str()
                .is_some_and(|value| value.to_lowercase().contains(&query))
        })
    });
    items.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    let fingerprint = crate::encode(&Sha256::digest(
        json!([scope, query, items]).to_string().as_bytes(),
    ));
    let offset = match &args.cursor {
        None => 0,
        Some(cursor) => {
            let decoded: Value = crate::decode(cursor)
                .ok()
                .and_then(|bytes| serde_json::from_slice(&bytes).ok())
                .ok_or_else(|| msg("Invalid cursor. Restart discovery without cursor."))?;
            if decoded["fingerprint"] != fingerprint {
                return Err(msg(
                    "Invalid cursor. Results or scope changed; restart discovery without cursor.",
                ));
            }
            decoded["offset"]
                .as_u64()
                .and_then(|v| usize::try_from(v).ok())
                .filter(|v| *v <= items.len())
                .ok_or_else(|| msg("Invalid cursor. Restart discovery without cursor."))?
        }
    };
    let end = (offset + args.limit).min(items.len());
    let cursor = (end < items.len()).then(|| {
        crate::encode(
            json!({"fingerprint":fingerprint,"offset":end})
                .to_string()
                .as_bytes(),
        )
    });
    Ok(json!({"items":items[offset..end],"totalCount":items.len(),"nextCursor":cursor}))
}

fn provider_failure(result: &Value) -> crate::BrokerError {
    msg(crate::discovery::provider_message(
        result["errorCode"].as_str().unwrap_or("op_rejected"),
    ))
}

pub(crate) async fn error_with_delivery(error: &crate::BrokerError) -> Value {
    let mut details = error_details(error);
    if let Some(id) = details["error"]["requestId"].as_str() {
        if let Ok(status) = cli::local(
            "GET",
            &format!("/v1/session-requests/{}", crate::url_escape(id)),
            None,
        )
        .await
        {
            details["error"]["delivery"] = status["delivery"].clone();
        }
    }
    details
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FieldsArgs {
    vault: String,
    item: String,
    #[serde(flatten)]
    selection: Selection,
    #[serde(default = "request_if_needed")]
    request_if_needed: bool,
    reason: Option<String>,
    task: Option<String>,
    #[serde(default = "auto_wait")]
    wait_seconds: u64,
}

fn parse<T: serde::de::DeserializeOwned>(args: Value) -> Result<T> {
    serde_json::from_value(args)
        .map_err(|_| msg("Invalid tool arguments. Check the tool input schema."))
}

fn field_metadata(item: &Value, vault: &str, item_id: &str) -> Result<Value> {
    let fields = item["fields"]
        .as_array()
        .ok_or_else(|| msg("Broker returned invalid item metadata"))?;
    let result = fields
        .iter()
        .map(|field| {
            let mut value = serde_json::Map::new();
            for key in ["id", "label", "type", "purpose", "designation"] {
                if let Some(entry) = field.get(key) {
                    value.insert(key.into(), entry.clone());
                }
            }
            if let Some(section) = field["section"].as_object() {
                let mut safe_section = serde_json::Map::new();
                for key in ["id", "label"] {
                    if let Some(entry) = section.get(key) {
                        safe_section.insert(key.into(), entry.clone());
                    }
                }
                value.insert("section".into(), Value::Object(safe_section));
            }
            // Build a usable reference from IDs, never from field values.
            if let Some(id) = field["id"].as_str() {
                let section = field["section"]["id"].as_str();
                let suffix =
                    section.map_or_else(|| id.to_owned(), |section| format!("{section}/{id}"));
                let reference = format!("op://{vault}/{item_id}/{suffix}");
                let selection = Selection {
                    lease_id: active(),
                    account: auto(),
                };
                if secret_operation(&reference, &selection).is_ok() {
                    value.insert("reference".into(), json!(reference));
                }
            }
            Value::Object(value)
        })
        .collect::<Vec<_>>();
    Ok(Value::Array(result))
}

fn tool_text(name: &str, data: &Value) -> String {
    match name {
        "keywarden_read_secret" => {
            "Secret read completed. Use structuredContent.value in code mode.".into()
        }
        _ => data.to_string(),
    }
}

fn tool_failure(details: Value) -> Value {
    let pending = details["error"]["code"] == "approval_required";
    let data = if pending {
        json!({"status":"pending","requestId":details["error"]["requestId"],
            "delivery":details["error"]["delivery"],"retryAfterSeconds":2,
            "next":"Approve on your phone, then repeat the same tool call. Use keywarden_access_status with requestId to check approval."})
    } else {
        details
    };
    json!({"content":[{"type":"text","text":data.to_string()}],"structuredContent":data,"isError":!pending})
}

pub(crate) fn error_details(error: &crate::BrokerError) -> Value {
    let message = error.to_string();
    let request_id = message
        .split("requestId=")
        .nth(1)
        .and_then(|value| value.split_whitespace().next())
        .map(|value| value.trim_end_matches('.').to_owned());
    let (code, next) = if message.contains("No active lease matches") {
        ("lease_required", Some("Call keywarden_request_access for the account, vault, item, and operation. Then call keywarden_access_status."))
    } else if message.starts_with("Approval is pending") {
        (
            "approval_required",
            Some("Approve the request on the phone, then repeat the same tool call."),
        )
    } else if message.starts_with("Approval was denied") {
        (
            "approval_denied",
            Some("Request access again with a new reason if the task still needs access."),
        )
    } else if message.starts_with("Approval was cancelled") {
        (
            "approval_cancelled",
            Some("The request was cancelled. Request new access only if the task still needs it."),
        )
    } else if message.starts_with("Item not found") {
        (
            "item_not_found",
            Some("Call keywarden_list_items and use an item ID from the result."),
        )
    } else if message.starts_with("Field not found") {
        (
            "field_not_found",
            Some("Call keywarden_list_fields and use a returned reference."),
        )
    } else if message.starts_with("Vault not found") {
        (
            "vault_not_found",
            Some("Call keywarden_list_vaults for the account and use a returned vault ID."),
        )
    } else if message.starts_with("Vault name is ambiguous") {
        (
            "vault_ambiguous",
            Some("Use a vault ID from keywarden_list_vaults."),
        )
    } else if message.starts_with("1Password authentication failed") {
        ("authentication_failed", Some("Check the local service account profile. Phone approval cannot fix provider authentication."))
    } else if message.starts_with("1Password permission denied") {
        (
            "provider_permission_denied",
            Some("Check the service account vault permissions."),
        )
    } else if message.starts_with("Account profile unavailable") {
        (
            "account_unavailable",
            Some("Configure the personal or work service account profile on the Mac."),
        )
    } else if message.starts_with("Invalid cursor") {
        ("invalid_cursor", Some("Repeat discovery without cursor. Preserve account, vault, and query for later pages."))
    } else if message.starts_with("Page limit") {
        ("invalid_limit", Some("Use limit from 1 through 200."))
    } else if message.starts_with("Approval expired") {
        (
            "approval_expired",
            Some("Request access again. The previous approval request expired."),
        )
    } else if message.contains("Account is required") {
        (
            "account_required",
            Some("Supply account personal or work when requestIfNeeded is true."),
        )
    } else if message.contains("Unknown session lease") || message.contains("Lease is not known") {
        ("lease_not_found", Some("Use a leaseId returned by keywarden_access_status in this MCP connection, or request access again."))
    } else if message.contains("Session lease is revoked") {
        (
            "lease_revoked",
            Some("Access was revoked. Request new approval only if the task still needs access."),
        )
    } else if message.contains("Session lease expired")
        || message.contains("Session lease idle timeout")
    {
        (
            "lease_expired",
            Some("Call keywarden_request_access for a new approved session."),
        )
    } else if message.contains("outside the lease scope")
        || message.contains("outside the direct agent scope")
    {
        ("scope_denied", Some("Use the approved account, vault, item, and operation. Request new approval for additional scope."))
    } else if message.contains("Broker is unavailable") {
        (
            "broker_unavailable",
            Some("Run keywarden start, then repeat the call."),
        )
    } else if message.contains("Multiple approvals match")
        || message.contains("Multiple active leases match")
    {
        (
            "lease_ambiguous",
            Some("Supply account or leaseId to select one approved lease."),
        )
    } else if message.contains("Invalid duration") {
        (
            "invalid_duration",
            Some("durationSeconds must be 1-86400. idleTimeoutSeconds must be 1-durationSeconds."),
        )
    } else if message.contains("--wait must") {
        (
            "invalid_wait",
            Some("Use --wait with a whole number from 0 through 300."),
        )
    } else if message.contains("waitSeconds must") {
        (
            "invalid_wait",
            Some("waitSeconds must be 0-25. Repeat keywarden_access_status for longer waits."),
        )
    } else if message.contains("1Password rejected") {
        ("op_rejected", Some("Check the vault, item, field, and approved operation scope. Keywarden withheld command output."))
    } else {
        ("tool_error", None)
    };
    let mut details = serde_json::Map::new();
    details.insert("code".into(), Value::String(code.into()));
    details.insert("message".into(), Value::String(message));
    if let Some(request_id) = request_id {
        details.insert("requestId".into(), Value::String(request_id));
    }
    if let Some(next) = next {
        details.insert("next".into(), Value::String(next.into()));
    }
    json!({"error":Value::Object(details)})
}

fn check_text(value: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > 4096 || value.chars().any(char::is_control) {
        return Err(msg("Invalid text argument"));
    }
    Ok(())
}
fn check_wait(seconds: u64) -> Result<()> {
    if seconds > 25 {
        return Err(msg("waitSeconds must be between 0 and 25 seconds. Repeat keywarden_access_status for longer waits."));
    }
    Ok(())
}
fn request_if_needed() -> bool {
    true
}
fn auto_wait() -> u64 {
    AUTO_ACCESS_WAIT_SECONDS
}
fn auto_request_key(operation: &OperationRequest) -> String {
    format!(
        "{}|{}|{}|{}|{}",
        operation.profile,
        operation.operation,
        operation.vault.as_deref().unwrap_or(""),
        operation.item_id.as_deref().unwrap_or(""),
        operation.field.as_deref().unwrap_or("")
    )
}
fn duration() -> i64 {
    900
}
fn idle() -> i64 {
    300
}
fn active() -> String {
    "active".into()
}
fn auto() -> String {
    "auto".into()
}
fn rpc_error(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
}
fn catalog() -> Value {
    serde_json::from_str(include_str!("mcp-tools.json")).expect("embedded MCP tool schema")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_is_a_normal_result_but_denial_is_an_error() {
        let result = tool_failure(
            json!({"error":{"code":"approval_required","requestId":"request-test","delivery":{"phoneReceipt":"unconfirmed"}}}),
        );
        assert_eq!(result["isError"], false);
        assert_eq!(result["structuredContent"]["status"], "pending");
        assert_eq!(result["structuredContent"]["requestId"], "request-test");
        assert!(result["structuredContent"].get("error").is_none());
        assert_eq!(
            serde_json::from_str::<Value>(result["content"][0]["text"].as_str().unwrap()).unwrap(),
            result["structuredContent"]
        );
        for code in [
            "approval_denied",
            "lease_expired",
            "scope_denied",
            "op_rejected",
        ] {
            assert_eq!(
                tool_failure(json!({"error":{"code":code}}))["isError"],
                true
            );
        }
    }

    async fn ready() -> Server {
        let mut server = Server::default();
        let response = server.handle(json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":PROTOCOL_VERSION,"capabilities":{},"clientInfo":{"name":"test","version":"1"}}})).await.unwrap();
        assert_eq!(response["result"]["protocolVersion"], PROTOCOL_VERSION);
        assert_eq!(response["result"]["capabilities"], json!({"tools":{}}));
        assert!(server
            .handle(json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
            .await
            .is_none());
        server
    }

    #[tokio::test]
    async fn protocol_and_tool_discovery() {
        let mut server = ready().await;
        let response = server
            .handle(json!({"jsonrpc":"2.0","id":"tools","method":"tools/list"}))
            .await
            .unwrap();
        let tools = response["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 7);
        for tool in tools {
            assert_eq!(tool["outputSchema"]["type"], "object");
        }
        assert_eq!(
            server
                .handle(json!({"jsonrpc":"2.0","id":2,"method":"ping"}))
                .await
                .unwrap()["result"],
            json!({})
        );
        assert_eq!(
            server
                .handle(json!({"jsonrpc":"2.0","id":3,"method":"unknown"}))
                .await
                .unwrap()["error"]["code"],
            -32601
        );
        assert!(server
            .handle(
                json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":9}})
            )
            .await
            .is_none());
        assert_eq!(
            server.handle(json!([])).await.unwrap()["error"]["code"],
            -32600
        );
    }

    #[tokio::test]
    async fn invalid_arguments_are_not_echoed() {
        let mut server = ready().await;
        let response = server.handle(json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"keywarden_read_secret","arguments":{"reference":42,"secret":"sensitive-test-value"}}})).await.unwrap();
        assert_eq!(response["result"]["isError"], true);
        assert!(!response.to_string().contains("sensitive-test-value"));
        let wait = server.handle(json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"keywarden_list_items","arguments":{"vault":"agents","waitSeconds":30}}})).await.unwrap();
        assert_eq!(
            wait["result"]["structuredContent"]["error"]["code"],
            "invalid_wait"
        );
    }

    #[test]
    fn pages_search_metadata_and_bind_cursor_to_scope_and_results() {
        let items = json!([{"id":"b","title":"Beta"},{"id":"a","title":"Alpha"}]);
        let page: PageArgs = serde_json::from_value(json!({"limit":1})).unwrap();
        let first = paginate(items.clone(), &page, "agent:vault").unwrap();
        assert_eq!(first["items"][0]["id"], "a");
        assert_eq!(first["totalCount"], 2);
        let next: PageArgs =
            serde_json::from_value(json!({"limit":1,"cursor":first["nextCursor"]})).unwrap();
        let last = paginate(items.clone(), &next, "agent:vault").unwrap();
        assert_eq!(last["items"][0]["id"], "b");
        assert!(last["nextCursor"].is_null());
        assert!(paginate(items.clone(), &next, "personal:vault").is_err());
        assert!(paginate(json!([]), &next, "agent:vault").is_err());
        let search: PageArgs = serde_json::from_value(json!({"query":"ALP"})).unwrap();
        assert_eq!(
            paginate(items, &search, "agent:vault").unwrap()["items"],
            json!([{"id":"a","title":"Alpha"}])
        );
    }

    #[test]
    fn references_and_selection_use_the_same_command_rules_as_the_broker() {
        let args: ReadArgs =
            parse(json!({"reference":"op://Keywarden Personal/Example/section/password"})).unwrap();
        let operation = secret_operation(&args.reference, &args.selection).unwrap();
        assert_eq!(operation.lease_id, "active");
        assert_eq!(operation.profile, "auto");
        assert_eq!(operation.vault.as_deref(), Some("Keywarden Personal"));
        assert_eq!(operation.item_id.as_deref(), Some("Example"));
        assert_eq!(operation.field.as_deref(), Some("section/password"));
        assert_eq!(operation.args.last().unwrap(), "--no-newline");
        let explicit: ReadArgs =
            parse(json!({"reference":args.reference,"account":"personal","leaseId":"lease-1"}))
                .unwrap();
        assert_eq!(explicit.selection.lease_id, "lease-1");
        for bad in [
            "https://x/i/f",
            "op://x/i",
            "op://x//f",
            "op://x/i/f?x",
            "op://x%2fy/i/f",
            "op://x/i/f\n",
            "op://*/i/f",
        ] {
            assert!(secret_operation(bad, &args.selection).is_err(), "{bad}");
        }
        assert!(parse::<ReadArgs>(json!({"reference":"op://v/i/f","unrecognized":true})).is_err());
    }

    #[test]
    fn access_scope_is_explicit() {
        let input = json!({"account":"personal","allVaults":true,"operations":["read","list"],"reason":"test"});
        let args: AccessArgs = parse(input.clone()).unwrap();
        args.validate().unwrap();
        assert_eq!(args.duration_seconds, 900);
        for (key, value) in [
            ("vaults", json!(["vault"])),
            ("account", json!("bad")),
            ("operations", json!(["execute"])),
            ("waitSeconds", json!(26)),
            ("idleTimeoutSeconds", json!(901)),
            ("items", json!([])),
        ] {
            let mut invalid = input.clone();
            invalid[key] = value;
            assert!(parse::<AccessArgs>(invalid).unwrap().validate().is_err());
        }
    }

    #[test]
    fn session_default_scope_matches_cli_and_respects_explicit_operations() {
        let input = json!({"account":"personal","vaults":["Test vault"],"reason":"Test access"});
        let args: AccessArgs = parse(input.clone()).unwrap();
        args.validate().unwrap();
        assert_eq!(args.operations, crate::default_session_operations());
        assert_eq!(args.operations, vec!["read", "list"]);
        let tools: Value = serde_json::from_str(include_str!("mcp-tools.json")).unwrap();
        assert_eq!(
            tools[0]["inputSchema"]["properties"]["operations"]["default"],
            json!(["read", "list"])
        );
        for operation in ["read", "list", "write"] {
            let mut explicit = input.clone();
            explicit["operations"] = json!([operation]);
            let args: AccessArgs = parse(explicit).unwrap();
            assert_eq!(args.operations, vec![operation]);
        }
    }

    #[test]
    fn client_identity_maps_known_mcp_hosts() {
        assert_eq!(normalize_client("codex"), ("codex", "Codex"));
        assert_eq!(
            normalize_client("claude-code"),
            ("claude-code", "Claude Code")
        );
        assert_eq!(normalize_client("other-client"), ("mcp", "MCP client"));
        let metadata = client_metadata(
            &json!({"capabilities":{"roots":{},"sampling":{}},"clientInfo":{"name":"codex","version":"0.160.0","title":"Deploy API"}}),
            PROTOCOL_VERSION,
        ).unwrap();
        assert_eq!(metadata.display_name, "Codex");
        assert_eq!(metadata.product_version, "0.160.0");
        assert_eq!(metadata.session_name.as_deref(), Some("Deploy API"));
        assert_eq!(metadata.capabilities, vec!["roots", "sampling"]);
    }

    #[test]
    fn field_metadata_excludes_values() {
        let fields = field_metadata(&json!({"fields":[
            {"id":"username","label":"username","type":"STRING","value":"hidden-user"},
            {"id":"password","label":"password","type":"CONCEALED","value":"hidden-secret","section":{"id":"login","label":"Login"}}
        ]}), "vault", "item").unwrap();
        let output = fields.to_string();
        assert!(!output.contains("hidden-user"));
        assert!(!output.contains("hidden-secret"));
        assert_eq!(fields[1]["section"]["label"], "Login");
        assert_eq!(fields[0]["reference"], "op://vault/item/username");
        assert_eq!(fields[1]["reference"], "op://vault/item/login/password");
    }

    #[test]
    fn text_clients_receive_metadata_and_never_secret_values() {
        let metadata = json!({"vault":"v","items":[{"id":"i","title":"Example"}]});
        assert_eq!(
            serde_json::from_str::<Value>(&tool_text("keywarden_list_items", &metadata)).unwrap(),
            metadata
        );
        let pending = json!({"status":"pending","requestId":"request-1"});
        assert_eq!(
            serde_json::from_str::<Value>(&tool_text("keywarden_request_access", &pending))
                .unwrap(),
            pending
        );
        let secret = json!({"value":"secret-canary"});
        assert!(!tool_text("keywarden_read_secret", &secret).contains("secret-canary"));
    }

    #[test]
    fn errors_include_next_action_and_safe_ranges() {
        let lease = error_details(&msg("No active lease matches this operation"));
        assert_eq!(lease["error"]["code"], "lease_required");
        assert!(lease["error"]["next"]
            .as_str()
            .unwrap()
            .contains("keywarden_request_access"));
        let duration = error_details(&msg("Invalid duration. durationSeconds must be 1-86400 seconds and idleTimeoutSeconds must be 1-durationSeconds."));
        assert_eq!(duration["error"]["code"], "invalid_duration");
        assert!(duration["error"]["next"]
            .as_str()
            .unwrap()
            .contains("1-86400"));
        let pending = error_details(&msg("Approval is pending. requestId=req-123. Approve on the phone, then repeat this tool call."));
        assert_eq!(pending["error"]["code"], "approval_required");
        assert_eq!(pending["error"]["requestId"], "req-123");
        for (message, code) in [
            ("Session lease is revoked", "lease_revoked"),
            ("Session lease expired", "lease_expired"),
            ("Session lease idle timeout reached", "lease_expired"),
            ("Operation is outside the lease scope", "scope_denied"),
            ("Vault is outside the direct agent scope", "scope_denied"),
            (
                "Broker is unavailable. Run keywarden start.",
                "broker_unavailable",
            ),
        ] {
            let error = error_details(&msg(message));
            assert_eq!(error["error"]["code"], code);
            assert!(error["error"]["next"].is_string());
        }
    }

    #[test]
    fn automatic_access_defaults_wait_and_request() {
        let read: ReadArgs = parse(json!({"reference":"op://v/i/f"})).unwrap();
        assert!(read.request_if_needed);
        assert_eq!(read.wait_seconds, AUTO_ACCESS_WAIT_SECONDS);
        let list: ListArgs = parse(json!({"vault":"v"})).unwrap();
        assert!(list.request_if_needed);
        assert_eq!(list.wait_seconds, AUTO_ACCESS_WAIT_SECONDS);
    }

    #[test]
    fn agent_scope_uses_the_existing_local_access() {
        let server = Server::default();
        let mut operation = OperationRequest {
            version: 1,
            lease_id: "active".into(),
            profile: "auto".into(),
            operation: "read".into(),
            vault: Some("agents".into()),
            item_id: Some("item-1".into()),
            field: Some("password".into()),
            args: vec![
                "read".into(),
                "op://agents/item-1/password".into(),
                "--no-newline".into(),
            ],
        };
        server.select_lease(&mut operation).unwrap();
        assert_eq!(operation.lease_id, "direct-agent");
        assert_eq!(operation.profile, "agent");
        assert_eq!(direct_agent_status()["status"], "active");
    }
}
