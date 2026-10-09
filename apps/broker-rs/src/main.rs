use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Duration, Utc};
use flate2::{write::DeflateEncoder, Compression};
use p256::{
    ecdh,
    ecdsa::{Signature, SigningKey, VerifyingKey},
    elliptic_curve::sec1::ToEncodedPoint,
    PublicKey, SecretKey,
};
use rand_core::{OsRng, RngCore};
use reqwest::Client;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use signature::{Signer, Verifier};
use std::{
    collections::HashMap,
    env,
    io::{self, Write},
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    process::Command,
    sync::Mutex,
    time::{sleep, Duration as TokioDuration},
};
use uuid::Uuid;
mod cli;
mod client;
mod command;
mod config;
mod delivery;
mod discovery;
mod mcp;
mod provider;
mod push;
mod sandbox;
mod service;

fn default_session_operations() -> Vec<String> {
    vec!["read".into(), "list".into()]
}

const MAX_BODY_BYTES: usize = 1024 * 1024;
const MAX_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
const DEFAULT_RELAY_URL: &str = "http://127.0.0.1:8787";
const DEFAULT_RELAY_TOKEN_REF: &str = "op://agents/Keywarden Relay Token/password";

#[derive(Debug, Error)]
enum BrokerError {
    #[error("{0}")]
    Message(String),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

#[derive(Debug, Error)]
enum CryptoError {
    #[error("invalid key")]
    InvalidKey,
    #[error("invalid envelope")]
    InvalidEnvelope,
    #[error("encryption failed")]
    Encryption,
    #[error("signature is invalid")]
    Signature,
}

type Result<T> = std::result::Result<T, BrokerError>;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct EncryptedPayload {
    version: u8,
    algorithm: String,
    #[serde(rename = "ephemeralPublicKey")]
    ephemeral_public_key: Value,
    iv: String,
    ciphertext: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SignedEnvelope {
    version: u8,
    kind: String,
    body: EncryptedPayload,
    #[serde(rename = "senderPublicKey")]
    sender_public_key: Value,
    signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PhonePairing {
    #[serde(rename = "phoneId")]
    phone_id: String,
    #[serde(rename = "encryptionPublicJwk")]
    encryption_public_jwk: Value,
    #[serde(rename = "signingPublicJwk")]
    signing_public_jwk: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PairingSetup {
    version: u8,
    #[serde(rename = "type")]
    setup_type: String,
    #[serde(rename = "brokerId")]
    broker_id: String,
    #[serde(rename = "phoneId")]
    phone_id: String,
    #[serde(rename = "pairingToken")]
    pairing_token: String,
    #[serde(rename = "createdAt")]
    created_at: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct SessionScope {
    accounts: Vec<String>,
    vaults: Vec<String>,
    items: ItemsScope,
    operations: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
enum ItemsScope {
    All(String),
    Values(Vec<String>),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct OpenSessionRequest {
    version: u8,
    #[serde(rename = "type")]
    request_type: String,
    id: String,
    agent: String,
    host: String,
    #[serde(rename = "phoneId")]
    phone_id: String,
    reason: String,
    intent: ApprovalIntent,
    client: ClientMetadata,
    scope: SessionScope,
    #[serde(rename = "durationSeconds")]
    duration_seconds: i64,
    #[serde(rename = "idleTimeoutSeconds")]
    idle_timeout_seconds: i64,
    #[serde(rename = "createdAt")]
    created_at: String,
    #[serde(rename = "expiresAt")]
    expires_at: String,
    nonce: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApprovalIntent {
    task: Option<String>,
    reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClientMetadata {
    product: String,
    client_name: String,
    display_name: String,
    product_version: String,
    protocol_version: String,
    transport: String,
    session_id: Option<String>,
    session_name: Option<String>,
    host: String,
    project: Option<String>,
    pid: Option<u32>,
    capabilities: Vec<String>,
}

impl ClientMetadata {
    fn manual(agent: &str, host: &str) -> Self {
        Self {
            product: "manual".into(),
            client_name: agent.into(),
            display_name: agent.into(),
            product_version: "unknown".into(),
            protocol_version: "unknown".into(),
            transport: "local".into(),
            session_id: None,
            session_name: None,
            host: host.into(),
            project: None,
            pid: None,
            capabilities: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ApprovalDecision {
    version: u8,
    #[serde(rename = "type")]
    decision_type: String,
    #[serde(rename = "requestId")]
    request_id: String,
    #[serde(rename = "requestHash")]
    request_hash: String,
    decision: String,
    #[serde(rename = "decidedAt")]
    decided_at: String,
    nonce: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SessionLease {
    version: u8,
    id: String,
    #[serde(rename = "requestId")]
    request_id: String,
    #[serde(rename = "requestHash")]
    request_hash: String,
    agent: String,
    host: String,
    scope: SessionScope,
    #[serde(rename = "issuedAt")]
    issued_at: String,
    #[serde(rename = "expiresAt")]
    expires_at: String,
    #[serde(rename = "idleUntil")]
    idle_until: String,
    #[serde(rename = "idleTimeoutSeconds")]
    idle_timeout_seconds: i64,
    status: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct OperationRequest {
    version: u8,
    #[serde(rename = "leaseId")]
    lease_id: String,
    profile: String,
    operation: String,
    vault: Option<String>,
    #[serde(rename = "itemId")]
    item_id: Option<String>,
    field: Option<String>,
    args: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct OpResult {
    #[serde(rename = "exitCode")]
    exit_code: i32,
    stdout: String,
    stderr: String,
    #[serde(rename = "errorCode", skip_serializing_if = "Option::is_none")]
    error_code: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PendingResponse {
    request: OpenSessionRequest,
    #[serde(rename = "requestHash")]
    request_hash: String,
    status: String,
    #[serde(rename = "leaseId", skip_serializing_if = "Option::is_none")]
    lease_id: Option<String>,
}

#[derive(Clone, Debug)]
struct Pending {
    request: OpenSessionRequest,
    request_hash: String,
    status: String,
    lease_id: Option<String>,
}

struct SessionStore {
    requests: HashMap<String, Pending>,
    leases: HashMap<String, SessionLease>,
    vault_aliases: HashMap<String, Vec<discovery::Vault>>,
}

impl SessionStore {
    fn new() -> Self {
        Self {
            requests: HashMap::new(),
            leases: HashMap::new(),
            vault_aliases: HashMap::new(),
        }
    }

    fn create(&mut self, input: SessionInput) -> Result<(Pending, bool)> {
        let scope = normalize_scope(input.scope.clone())?;
        if let Some(existing) = self.reusable_request(&input, &scope) {
            return Ok((existing, false));
        }
        let duration = input.duration_seconds.clamp(1, 24 * 60 * 60);
        let idle = input.idle_timeout_seconds.clamp(1, duration);
        let now = Utc::now();
        let request = OpenSessionRequest {
            version: 1,
            request_type: "open_session".into(),
            id: id("request"),
            agent: input.agent,
            host: input.host,
            phone_id: input.phone_id,
            reason: input.reason,
            intent: input.intent,
            client: input.client,
            scope,
            duration_seconds: duration,
            idle_timeout_seconds: idle,
            created_at: now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            expires_at: (now + Duration::seconds(duration))
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            nonce: id("nonce"),
        };
        let request_hash = hash_request(&request)?;
        let pending = Pending {
            request: request.clone(),
            request_hash,
            status: "pending".into(),
            lease_id: None,
        };
        self.requests.insert(request.id.clone(), pending.clone());
        Ok((pending, true))
    }

    fn reusable_request(
        &mut self,
        input: &SessionInput,
        requested_scope: &SessionScope,
    ) -> Option<Pending> {
        let now = Utc::now();
        let expired: Vec<String> = self
            .requests
            .iter()
            .filter_map(|(id, pending)| {
                (pending.status == "pending"
                    && timestamp(&pending.request.expires_at).is_ok_and(|expires| expires <= now))
                .then_some(id.clone())
            })
            .collect();
        for id in expired {
            if let Some(pending) = self.requests.get_mut(&id) {
                pending.status = "expired".into();
            }
        }
        let mut active = self
            .requests
            .values()
            .filter_map(|pending| {
                let request = &pending.request;
                if request.phone_id != input.phone_id
                    || request.agent != input.agent
                    || request.host != input.host
                {
                    return None;
                }
                match pending.status.as_str() {
                    "approved" => {
                        let lease_id = pending.lease_id.as_ref()?;
                        let lease = self.leases.get(lease_id)?;
                        let active = lease.status == "active"
                            && timestamp(&lease.expires_at).is_ok_and(|expires| expires > now)
                            && timestamp(&lease.idle_until).is_ok_and(|idle| idle > now)
                            && scope_covers(&lease.scope, requested_scope);
                        active.then(|| pending.clone())
                    }
                    _ => None,
                }
            })
            .collect::<Vec<_>>();
        active.sort_by(|left, right| {
            let left_exact = left.request.scope == *requested_scope;
            let right_exact = right.request.scope == *requested_scope;
            right_exact
                .cmp(&left_exact)
                .then_with(|| right.request.created_at.cmp(&left.request.created_at))
        });
        if let Some(existing) = active.into_iter().next() {
            return Some(existing);
        }
        self.requests
            .values()
            .filter(|pending| {
                pending.status == "pending"
                    && pending.request.phone_id == input.phone_id
                    && pending.request.agent == input.agent
                    && pending.request.host == input.host
                    && pending.request.scope == *requested_scope
            })
            .max_by(|left, right| left.request.created_at.cmp(&right.request.created_at))
            .cloned()
    }

    fn approve(&mut self, request_id: &str, decision: &ApprovalDecision) -> Result<SessionLease> {
        let pending = self
            .requests
            .get_mut(request_id)
            .ok_or_else(|| msg("Unknown session request"))?;
        if pending.status != "pending" {
            return Err(msg(format!("Request is already {}", pending.status)));
        }
        if timestamp(&pending.request.expires_at)? <= Utc::now() {
            pending.status = "expired".into();
            return Err(msg("Session request expired"));
        }
        let accepted_hash = if decision.request_hash == pending.request_hash {
            decision.request_hash.clone()
        } else if decision.request_hash == hash_request_legacy(&pending.request)? {
            decision.request_hash.clone()
        } else if decision.request_hash == hash_request_ios(&pending.request)? {
            decision.request_hash.clone()
        } else {
            return Err(msg("Approval does not match request"));
        };
        if decision.decision != "approve" {
            pending.status = "denied".into();
            return Err(msg("Session request denied"));
        }
        let now = Utc::now();
        let lease = SessionLease {
            version: 1,
            id: id("lease"),
            request_id: request_id.into(),
            request_hash: accepted_hash,
            agent: pending.request.agent.clone(),
            host: pending.request.host.clone(),
            scope: pending.request.scope.clone(),
            issued_at: now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            expires_at: (now + Duration::seconds(pending.request.duration_seconds))
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            idle_until: (now + Duration::seconds(pending.request.idle_timeout_seconds))
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            idle_timeout_seconds: pending.request.idle_timeout_seconds,
            status: "active".into(),
        };
        pending.status = "approved".into();
        pending.lease_id = Some(lease.id.clone());
        self.leases.insert(lease.id.clone(), lease.clone());
        Ok(lease)
    }

    fn deny(&mut self, request_id: &str) -> Result<()> {
        let pending = self
            .requests
            .get_mut(request_id)
            .ok_or_else(|| msg("Unknown session request"))?;
        if pending.status != "pending" {
            return Err(msg(format!("Request is already {}", pending.status)));
        }
        pending.status = "denied".into();
        Ok(())
    }

    fn revoke(&mut self, lease_id: &str) {
        if let Some(lease) = self.leases.get_mut(lease_id) {
            lease.status = "revoked".into();
        }
    }

    fn status(&mut self, pending: &Pending) -> Value {
        let lease = pending
            .lease_id
            .as_ref()
            .and_then(|id| self.leases.get_mut(id));
        if let Some(lease) = lease {
            if lease.status == "active"
                && (timestamp(&lease.expires_at).unwrap_or(Utc::now()) <= Utc::now()
                    || timestamp(&lease.idle_until).unwrap_or(Utc::now()) <= Utc::now())
            {
                lease.status = "expired".into();
            }
            serde_json::json!({"version":1,"type":"session_status","requestId":pending.request.id,"requestHash":lease.request_hash,"status":lease.status,"issuedAt":lease.issued_at,"expiresAt":lease.expires_at,"idleUntil":lease.idle_until,"observedAt":now()})
        } else {
            serde_json::json!({"version":1,"type":"session_status","requestId":pending.request.id,"requestHash":pending.request_hash,"status":pending.status,"observedAt":now()})
        }
    }

    fn authorize(&mut self, operation: &OperationRequest) -> Result<()> {
        let resolved = self.resolve_operation(operation)?;
        if resolved.lease_id == "direct-agent" {
            if resolved.profile != "agent" {
                return Err(msg("Account is outside the direct agent scope"));
            }
            if !["read", "list", "write", "create", "delete"].contains(&resolved.operation.as_str())
            {
                return Err(msg("Operation is outside the direct agent scope"));
            }
            if !self.vault_matches("agent", resolved.vault.as_deref().unwrap_or(""), "agents") {
                return Err(msg("Vault is outside the direct agent scope"));
            }
            command::target(&resolved)?;
            return Ok(());
        }
        let vault_aliases = self.vault_aliases.clone();
        let lease = self
            .leases
            .get_mut(&resolved.lease_id)
            .ok_or_else(|| msg("Unknown session lease"))?;
        let now = Utc::now();
        if lease.status != "active" {
            return Err(msg(format!("Session lease is {}", lease.status)));
        }
        if timestamp(&lease.expires_at)? <= now {
            lease.status = "expired".into();
            return Err(msg("Session lease expired"));
        }
        if timestamp(&lease.idle_until)? <= now {
            lease.status = "expired".into();
            return Err(msg("Session lease idle timeout reached"));
        }
        if !lease
            .scope
            .accounts
            .iter()
            .any(|item| item == &resolved.profile)
        {
            return Err(msg("Account is outside the lease scope"));
        }
        if !lease
            .scope
            .operations
            .iter()
            .any(|item| item == &resolved.operation)
        {
            return Err(msg("Operation is outside the lease scope"));
        }
        let vault = resolved
            .vault
            .as_ref()
            .ok_or_else(|| msg("Operation must name a vault"))?;
        if !lease.scope.vaults.iter().any(|item| {
            item == "*" || discovery::vault_matches(&vault_aliases, &resolved.profile, item, vault)
        }) {
            return Err(msg("Vault is outside the lease scope"));
        }
        let (_, target_item) = command::target(&resolved)?;
        if let ItemsScope::Values(items) = &lease.scope.items {
            let item = target_item
                .as_ref()
                .ok_or_else(|| msg("Operation must name an item"))?;
            if !items.iter().any(|value| value == item) {
                return Err(msg("Item is outside the lease scope"));
            }
        }
        lease.idle_until = (now + Duration::seconds(lease.idle_timeout_seconds))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        Ok(())
    }

    fn resolve_operation(&self, operation: &OperationRequest) -> Result<OperationRequest> {
        if operation.lease_id == "direct-agent" {
            let mut resolved = operation.clone();
            if resolved.profile == "auto" {
                resolved.profile = "agent".into();
            }
            return Ok(resolved);
        }
        if operation.lease_id != "active" {
            let lease = self
                .leases
                .get(&operation.lease_id)
                .ok_or_else(|| msg("Unknown session lease"))?;
            return Self::with_account(operation, lease);
        }
        if ["agent", "auto"].contains(&operation.profile.as_str())
            && self.vault_matches("agent", operation.vault.as_deref().unwrap_or(""), "agents")
        {
            let mut resolved = operation.clone();
            resolved.lease_id = "direct-agent".into();
            resolved.profile = "agent".into();
            return Ok(resolved);
        }
        let (_, target_item) = command::target(operation)?;
        let now = Utc::now();
        let candidates: Vec<&SessionLease> = self
            .leases
            .values()
            .filter(|lease| {
                if lease.status != "active"
                    || timestamp(&lease.expires_at)
                        .map(|value| value <= now)
                        .unwrap_or(true)
                    || timestamp(&lease.idle_until)
                        .map(|value| value <= now)
                        .unwrap_or(true)
                {
                    return false;
                }
                if operation.profile != "auto"
                    && !lease
                        .scope
                        .accounts
                        .iter()
                        .any(|account| account == &operation.profile)
                {
                    return false;
                }
                if !lease
                    .scope
                    .operations
                    .iter()
                    .any(|allowed| allowed == &operation.operation)
                {
                    return false;
                }
                let Some(vault) = operation.vault.as_ref() else {
                    return false;
                };
                if !lease.scope.vaults.iter().any(|allowed| {
                    allowed == "*"
                        || lease
                            .scope
                            .accounts
                            .iter()
                            .any(|account| self.vault_matches(account, allowed, vault))
                }) {
                    return false;
                }
                if let ItemsScope::Values(items) = &lease.scope.items {
                    if target_item
                        .as_ref()
                        .is_none_or(|item| !items.iter().any(|allowed| allowed == item))
                    {
                        return false;
                    }
                }
                true
            })
            .collect();
        if candidates.is_empty() {
            return Err(msg("No active lease matches this operation"));
        }
        if candidates.len() > 1 {
            return Err(msg("Multiple active leases match; specify --lease"));
        }
        Self::with_account(operation, candidates[0])
    }

    fn with_account(
        operation: &OperationRequest,
        lease: &SessionLease,
    ) -> Result<OperationRequest> {
        let profile = if operation.profile == "auto" {
            if lease.scope.accounts.len() != 1 {
                return Err(msg("Active lease has multiple accounts; specify --profile"));
            }
            lease.scope.accounts[0].clone()
        } else {
            operation.profile.clone()
        };
        let mut resolved = operation.clone();
        resolved.lease_id = lease.id.clone();
        resolved.profile = profile;
        Ok(resolved)
    }
}

struct SessionInput {
    agent: String,
    host: String,
    phone_id: String,
    reason: String,
    intent: ApprovalIntent,
    client: ClientMetadata,
    scope: SessionScope,
    duration_seconds: i64,
    idle_timeout_seconds: i64,
}

struct Identity {
    broker_id: String,
    signing_private: SecretKey,
    signing_public: Value,
    encryption_private: SecretKey,
    encryption_public: Value,
    state_dir: PathBuf,
}

struct Broker {
    push: Mutex<Option<push::PushSender>>,
    last_push: Mutex<Option<String>>,
    delivery: Mutex<HashMap<String, Value>>,
    vault_cache: Mutex<HashMap<String, discovery::VaultCache>>,
    identity: Identity,
    token: Option<String>,
    relay: Option<RelayClient>,
    pairing: Arc<Mutex<Option<PhonePairing>>>,
    pairing_setup: Arc<Mutex<Option<PairingSetup>>>,
    store: Arc<Mutex<SessionStore>>,
}

#[derive(Clone)]
struct RelayClient {
    client: Client,
    base_url: String,
    token: String,
}

impl RelayClient {
    async fn session_envelope(
        &self,
        broker_id: &str,
        request_id: &str,
        field: &str,
        envelope: Option<&SignedEnvelope>,
    ) -> Result<Option<SignedEnvelope>> {
        let url = format!(
            "{}/v1/brokers/{}/requests/{}/{}",
            self.base_url,
            url_escape(broker_id),
            url_escape(request_id),
            field
        );
        let request = if let Some(envelope) = envelope {
            self.client.post(url).json(envelope)
        } else {
            self.client.get(url)
        };
        let response = request.bearer_auth(&self.token).send().await?;
        if envelope.is_none() && response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !response.status().is_success() {
            return Err(msg(format!(
                "Relay session update failed with HTTP {}",
                response.status()
            )));
        }
        if envelope.is_some() {
            return Ok(None);
        }
        #[derive(Deserialize)]
        struct Body {
            envelope: SignedEnvelope,
        }
        Ok(Some(response.json::<Body>().await?.envelope))
    }
    async fn submit_request(
        &self,
        broker_id: &str,
        request: &OpenSessionRequest,
        envelope: &SignedEnvelope,
    ) -> Result<()> {
        let response = self.client.post(format!("{}/v1/brokers/{}/requests", self.base_url, url_escape(broker_id)))
            .bearer_auth(&self.token)
            .json(&serde_json::json!({"brokerId": broker_id, "requestId": request.id, "phoneId": request.phone_id, "expiresAt": request.expires_at, "envelope": envelope}))
            .send().await?;
        if !response.status().is_success() {
            return Err(msg(format!(
                "Relay request failed with HTTP {}",
                response.status()
            )));
        }
        Ok(())
    }

    async fn decision(&self, broker_id: &str, request_id: &str) -> Result<Option<SignedEnvelope>> {
        let response = self
            .client
            .get(format!(
                "{}/v1/brokers/{}/decisions/{}",
                self.base_url,
                url_escape(broker_id),
                url_escape(request_id)
            ))
            .bearer_auth(&self.token)
            .send()
            .await?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !response.status().is_success() {
            return Err(msg(format!(
                "Relay decision failed with HTTP {}",
                response.status()
            )));
        }
        #[derive(Deserialize)]
        struct Body {
            envelope: SignedEnvelope,
        }
        Ok(Some(response.json::<Body>().await?.envelope))
    }

    async fn pairing(&self, broker_id: &str, phone_id: &str) -> Result<Option<SignedEnvelope>> {
        let response = self
            .client
            .get(format!(
                "{}/v1/brokers/{}/pairing/{}",
                self.base_url,
                url_escape(broker_id),
                url_escape(phone_id)
            ))
            .bearer_auth(&self.token)
            .send()
            .await?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !response.status().is_success() {
            return Err(msg(format!(
                "Relay pairing lookup failed with HTTP {}",
                response.status()
            )));
        }
        #[derive(Deserialize)]
        struct Body {
            envelope: SignedEnvelope,
        }
        Ok(Some(response.json::<Body>().await?.envelope))
    }

    async fn acknowledge_pairing(&self, broker_id: &str, phone_id: &str) -> Result<()> {
        let response = self
            .client
            .post(format!(
                "{}/v1/brokers/{}/pairing/{}/ack",
                self.base_url,
                url_escape(broker_id),
                url_escape(phone_id)
            ))
            .bearer_auth(&self.token)
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(msg(format!(
                "Relay pairing acknowledgement failed with HTTP {}",
                response.status()
            )));
        }
        Ok(())
    }
}

impl Broker {
    async fn create() -> Result<Arc<Self>> {
        let state_dir = env::var("KEYWARDEN_STATE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                PathBuf::from(env::var("HOME").unwrap_or_else(|_| ".".into()))
                    .join("Library/Application Support/Keywarden")
            });
        tokio::fs::create_dir_all(&state_dir).await?;
        let identity = load_identity(&state_dir).await?;
        let pairing = load_pairing(&state_dir).await?;
        let pairing_setup = load_pairing_setup(&state_dir).await?;
        let relay = match (
            env::var("KEYWARDEN_RELAY_URL"),
            env::var("KEYWARDEN_RELAY_TOKEN")
                .ok()
                .or(RELAY_TOKEN.lock().await.clone()),
        ) {
            (Ok(base_url), Some(token)) => Some(RelayClient {
                client: Client::builder()
                    .timeout(std::time::Duration::from_secs(10))
                    .build()?,
                base_url: base_url.trim_end_matches('/').into(),
                token,
            }),
            _ => None,
        };
        let token = BROKER_TOKEN.lock().await.clone();
        let opgate_configured = [
            "KEYWARDEN_OPGATE_PROFILE",
            "KEYWARDEN_OPGATE_PERSONAL_PROFILE",
            "KEYWARDEN_OPGATE_WORK_PROFILE",
        ]
        .iter()
        .any(|name| env::var(name).is_ok());
        if token.is_none() && !opgate_configured {
            return Err(msg("Broker service token is not loaded"));
        }
        Ok(Arc::new(Self {
            identity,
            token,
            relay,
            push: Mutex::new(None),
            last_push: Mutex::new(None),
            delivery: Mutex::new(HashMap::new()),
            vault_cache: Mutex::new(HashMap::new()),
            pairing: Arc::new(Mutex::new(pairing)),
            pairing_setup: Arc::new(Mutex::new(pairing_setup)),
            store: Arc::new(Mutex::new(SessionStore::new())),
        }))
    }

    async fn create_session(self: &Arc<Self>, input: SessionInput) -> Result<Pending> {
        self.refresh_pairing().await?;
        let (pending, created) = self.store.lock().await.create(input)?;
        if created {
            if let Some(relay) = &self.relay {
                let pairing = self
                    .pairing
                    .lock()
                    .await
                    .clone()
                    .ok_or_else(|| msg("No phone pairing is configured"))?;
                if pairing.phone_id != pending.request.phone_id {
                    return Err(msg("Requested phone is not paired"));
                }
                let body = encrypt_for_public_key(
                    &serde_json::to_string(&pending.request)?,
                    &pairing.encryption_public_jwk,
                )?;
                let envelope = sign_envelope(
                    "session_request",
                    body,
                    &self.identity.signing_private,
                    &self.identity.signing_public,
                )?;
                if let Err(error) = relay
                    .submit_request(&self.identity.broker_id, &pending.request, &envelope)
                    .await
                {
                    self.store.lock().await.requests.remove(&pending.request.id);
                    return Err(error);
                }
                self.delivery.lock().await.insert(
                    pending.request.id.clone(),
                    serde_json::json!({
                        "relay":{"state":"accepted","acceptedAt":now()},
                        "phoneReceipt":"unconfirmed",
                        "poll":{"state":"waiting"}
                    }),
                );
                self.send_notification(&pending.request.id).await;
                let broker = Arc::clone(self);
                let request_id = pending.request.id.clone();
                tokio::spawn(async move {
                    if let Err(error) = broker.wait_for_decision(request_id).await {
                        eprintln!("keywarden: approval wait failed: {error}");
                    }
                });
            }
        }
        Ok(pending)
    }

    async fn refresh_pairing(&self) -> Result<()> {
        let Some(relay) = &self.relay else {
            return Ok(());
        };
        let setup = {
            let mut current = self.pairing_setup.lock().await;
            *current = load_pairing_setup(&self.identity.state_dir).await?;
            current.clone()
        };
        let Some(setup) = setup else {
            return Ok(());
        };
        if Utc::now() - timestamp(&setup.created_at)? > Duration::minutes(15) {
            if self.pairing.lock().await.is_some() {
                return Ok(());
            }
            return Err(msg("Setup QR expired. Create a fresh QR."));
        }
        let Some(envelope) = relay.pairing(&setup.broker_id, &setup.phone_id).await? else {
            return Ok(());
        };
        if envelope.kind != "phone_pairing" || !verify_envelope(&envelope)? {
            return Err(msg("Invalid phone pairing signature"));
        }
        let clear: Value = serde_json::from_str(&decrypt_with_private_key(
            &envelope.body,
            &self.identity.encryption_private,
        )?)?;
        let received: PhonePairing = serde_json::from_value(clear.clone())?;
        if received.phone_id != setup.phone_id
            || clear["pairingToken"] != setup.pairing_token
            || canonical(&received.signing_public_jwk) != canonical(&envelope.sender_public_key)
        {
            return Err(msg("Pairing does not match setup QR"));
        }
        save_pairing(&self.identity.state_dir, &received).await?;
        if self
            .pairing
            .lock()
            .await
            .as_ref()
            .map(|pairing| &pairing.phone_id)
            != Some(&received.phone_id)
        {
            for lease in self.store.lock().await.leases.values_mut() {
                lease.status = "revoked".into();
            }
        }
        *self.pairing.lock().await = Some(received.clone());
        relay
            .acknowledge_pairing(&setup.broker_id, &setup.phone_id)
            .await?;
        clear_pairing_setup(&self.identity.state_dir).await?;
        Ok(())
    }

    async fn wait_for_decision(self: Arc<Self>, request_id: String) -> Result<()> {
        let Some(relay) = &self.relay else {
            return Ok(());
        };
        loop {
            let pending = self.store.lock().await.requests.get(&request_id).cloned();
            let Some(pending) = pending else {
                return Ok(());
            };
            if pending.status != "pending" || timestamp(&pending.request.expires_at)? <= Utc::now()
            {
                if pending.status == "pending" {
                    self.store
                        .lock()
                        .await
                        .requests
                        .get_mut(&request_id)
                        .map(|item| item.status = "expired".into());
                }
                return Ok(());
            }
            match relay.decision(&self.identity.broker_id, &request_id).await {
                Ok(Some(envelope)) => {
                    match self.accept_decision(request_id.clone(), envelope).await {
                        Ok(()) => {
                            self.set_delivery(&request_id, "poll", serde_json::json!({"state":"decision_received","checkedAt":now()})).await;
                            self.sync_session(&request_id).await;
                            return Ok(());
                        }
                        Err(_) => self.set_delivery(&request_id, "poll", serde_json::json!({"state":"decision_rejected","checkedAt":now(),"errorCode":"invalid_decision"})).await,
                    }
                }
                Ok(None) => {
                    self.set_delivery(
                        &request_id,
                        "poll",
                        serde_json::json!({"state":"waiting","checkedAt":now()}),
                    )
                    .await
                }
                Err(_) => {
                    self.set_delivery(&request_id, "poll", serde_json::json!({"state":"retrying","checkedAt":now(),"errorCode":"relay_unavailable"})).await;
                    sleep(TokioDuration::from_secs(1)).await;
                }
            }
            sleep(TokioDuration::from_millis(250)).await;
        }
    }

    async fn accept_decision(&self, request_id: String, envelope: SignedEnvelope) -> Result<()> {
        let pairing = self
            .pairing
            .lock()
            .await
            .clone()
            .ok_or_else(|| msg("No phone pairing is configured"))?;
        if canonical(&envelope.sender_public_key) != canonical(&pairing.signing_public_jwk) {
            return Err(msg("Decision signer is not the paired phone"));
        }
        if !verify_envelope(&envelope)? || envelope.kind != "approval_decision" {
            return Err(msg("Invalid approval decision"));
        }
        let clear = decrypt_with_private_key(&envelope.body, &self.identity.encryption_private)?;
        let decision: ApprovalDecision = serde_json::from_str(&clear)?;
        if decision.request_id != request_id {
            return Err(msg("Decision request ID does not match"));
        }
        let pending = self
            .store
            .lock()
            .await
            .requests
            .get(&request_id)
            .cloned()
            .ok_or_else(|| msg("Unknown session request"))?;
        if decision.version != 1
            || decision.decision_type != "approval_decision"
            || !request_hash_matches(
                &pending.request,
                &pending.request_hash,
                &decision.request_hash,
            )?
        {
            return Err(msg("Invalid approval decision"));
        }
        if decision.decision == "deny" {
            self.store.lock().await.deny(&request_id)?;
        } else {
            self.store.lock().await.approve(&request_id, &decision)?;
        }
        Ok(())
    }

    async fn sync_session(&self, request_id: &str) {
        let Some(relay) = &self.relay else {
            return;
        };
        let Some(pairing) = self.pairing.lock().await.clone() else {
            return;
        };
        let Some(pending) = self.store.lock().await.requests.get(request_id).cloned() else {
            return;
        };
        let request_hash = {
            let store = self.store.lock().await;
            pending
                .lease_id
                .as_ref()
                .and_then(|id| store.leases.get(id))
                .map(|lease| lease.request_hash.clone())
                .unwrap_or_else(|| pending.request_hash.clone())
        };
        let deadline = Utc::now() + Duration::seconds(pending.request.duration_seconds + 60);
        while Utc::now() < deadline {
            let result: Result<bool> = async {
                if let Some(envelope) = relay
                    .session_envelope(&self.identity.broker_id, request_id, "revocation", None)
                    .await?
                {
                    if canonical(&envelope.sender_public_key)
                        != canonical(&pairing.signing_public_jwk)
                        || envelope.kind != "session_revoke"
                        || !verify_envelope(&envelope)?
                    {
                        return Err(msg("Invalid revocation signature"));
                    }
                    let clear: Value = serde_json::from_str(&decrypt_with_private_key(
                        &envelope.body,
                        &self.identity.encryption_private,
                    )?)?;
                    if clear["version"] != 1
                        || clear["type"] != "session_revoke"
                        || clear["requestId"] != request_id
                        || clear["requestHash"] != request_hash
                    {
                        return Err(msg("Invalid revocation request"));
                    }
                    if let Some(id) = &pending.lease_id {
                        self.store.lock().await.revoke(id);
                    }
                }
                let status = self.store.lock().await.status(&pending);
                let body = encrypt_for_public_key(
                    &serde_json::to_string(&status)?,
                    &pairing.encryption_public_jwk,
                )?;
                let envelope = sign_envelope(
                    "session_status",
                    body,
                    &self.identity.signing_private,
                    &self.identity.signing_public,
                )?;
                relay
                    .session_envelope(
                        &self.identity.broker_id,
                        request_id,
                        "status",
                        Some(&envelope),
                    )
                    .await?;
                Ok(status["status"] == "active")
            }
            .await;
            match result {
                Ok(false) => return,
                Ok(true) => (),
                Err(_) => {
                    if let Some(id) = &pending.lease_id {
                        self.store.lock().await.revoke(id);
                    }
                }
            }
            sleep(TokioDuration::from_secs(3)).await;
        }
    }

    async fn run_operation(&self, operation: OperationRequest) -> Result<OpResult> {
        self.prepare_vault_aliases(&operation.profile, &operation.lease_id)
            .await?;
        let operation = {
            let mut store = self.store.lock().await;
            let resolved = store.resolve_operation(&operation)?;
            store.authorize(&resolved)?;
            resolved
        };
        let operation = self.pin_operation_vault(operation).await?;
        let mut result = self
            .run_provider(&operation.profile, &operation.args)
            .await?;
        if result.exit_code == 0 && operation.operation == "list" {
            let items: Value = serde_json::from_str(&result.stdout)
                .map_err(|_| msg("Broker returned invalid item output"))?;
            result.stdout = discovery::item_metadata(&items)?.to_string();
        }
        Ok(result)
    }

    async fn run_provider(&self, profile: &str, args: &[String]) -> Result<OpResult> {
        for argument in args {
            if argument.contains('\0') {
                return Err(msg("Operation contains a NUL byte"));
            }
        }
        let configured_opgate = env::var("KEYWARDEN_OPGATE_PROFILE")
            .ok()
            .or_else(|| env::var("KEYWARDEN_OPGATE_PERSONAL_PROFILE").ok())
            .or_else(|| env::var("KEYWARDEN_OPGATE_WORK_PROFILE").ok());
        let opgate_profile = opgate_profile_for_account(profile);
        let opgate_mode = configured_opgate.is_some();
        if !opgate_mode && profile != "agent" {
            return Err(msg("Personal and work accounts need opgate profiles"));
        }
        let binary = env::var("KEYWARDEN_OP_BIN").unwrap_or_else(|_| {
            if opgate_mode {
                "opgate".into()
            } else {
                "op".into()
            }
        });
        let mut command = Command::new(binary);
        if opgate_mode {
            command.args(["op", "--profile", opgate_profile.as_str(), "--"]);
        }
        command
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for key in env::vars()
            .map(|(key, _)| key)
            .filter(|key| key.starts_with("KEYWARDEN_"))
        {
            command.env_remove(key);
        }
        if !opgate_mode {
            command.env(
                "OP_SERVICE_ACCOUNT_TOKEN",
                self.token
                    .as_deref()
                    .ok_or_else(|| msg("Broker service token is not loaded"))?,
            );
        }
        let output = provider::output(command, TokioDuration::from_secs(45)).await?;
        if output.stdout.len() + output.stderr.len() > MAX_OUTPUT_BYTES {
            return Err(msg("opgate output exceeded the broker limit"));
        }
        Ok(OpResult {
            exit_code: output.status.code().unwrap_or(1),
            stdout: String::from_utf8_lossy(&output.stdout).into(),
            stderr: String::from_utf8_lossy(&output.stderr).into(),
            error_code: (!output.status.success()).then(|| {
                discovery::provider_error_code(&String::from_utf8_lossy(&output.stderr)).to_owned()
            }),
        })
    }
}

static BROKER_TOKEN: tokio::sync::Mutex<Option<String>> = tokio::sync::Mutex::const_new(None);
static RELAY_TOKEN: tokio::sync::Mutex<Option<String>> = tokio::sync::Mutex::const_new(None);

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("serve") => {
            if args.iter().any(|arg| arg == "--opgate") {
                let (url, token) = resolve_relay_config(&args).await?;
                *RELAY_TOKEN.lock().await = Some(token);
                env::set_var("KEYWARDEN_RELAY_URL", url);
                env::set_var("KEYWARDEN_OPGATE_PROFILE", "agent");
            }
            if args.iter().any(|arg| arg == "--token-stdin") {
                read_token_stdin().await?;
            }
            let broker = Broker::create().await?;
            let socket = env::var("KEYWARDEN_SOCKET")
                .unwrap_or_else(|_| "/Users/Shared/Keywarden/broker.sock".into());
            serve(broker, Path::new(&socket)).await
        }
        Some("identity") => {
            let state_dir = env::var("KEYWARDEN_STATE_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|_| {
                    PathBuf::from(env::var("HOME").unwrap_or_else(|_| ".".into()))
                        .join("Library/Application Support/Keywarden")
                });
            tokio::fs::create_dir_all(&state_dir).await?;
            let identity = load_identity(&state_dir).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &serde_json::json!({"brokerId": identity.broker_id, "signingPublicJwk": identity.signing_public, "encryptionPublicJwk": identity.encryption_public})
                )?
            );
            Ok(())
        }
        Some("pairing-qr") => {
            let (relay_url, relay_token) = resolve_relay_config(&args).await?;
            let state_dir = env::var("KEYWARDEN_STATE_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|_| {
                    PathBuf::from(env::var("HOME").unwrap_or_else(|_| ".".into()))
                        .join("Library/Application Support/Keywarden")
                });
            tokio::fs::create_dir_all(&state_dir).await?;
            let identity = load_identity(&state_dir).await?;
            let setup = PairingSetup {
                version: 1,
                setup_type: "keywarden_setup".into(),
                broker_id: identity.broker_id.clone(),
                phone_id: id("phone"),
                pairing_token: id("pair"),
                created_at: now(),
            };
            save_pairing_setup(&state_dir, &setup).await?;
            let payload = serde_json::json!({
                "r": relay_url,
                "t": relay_token,
                "b": setup.broker_id,
                "p": setup.phone_id,
                "q": setup.pairing_token,
                "s": compact_public_key(&identity.signing_public)?,
                "e": compact_public_key(&identity.encryption_public)?,
            });
            let qr_payload = if args.iter().any(|arg| arg == "--legacy") {
                let legacy_payload = serde_json::json!({
                    "version": 1,
                    "type": "keywarden_setup",
                    "relayURL": payload["r"],
                    "relayToken": payload["t"],
                    "brokerId": payload["b"],
                    "phoneId": payload["p"],
                    "pairingToken": payload["q"],
                    "brokerSigningPublicJWK": identity.signing_public,
                    "brokerEncryptionPublicJWK": identity.encryption_public,
                });
                format!(
                    "kw1:{}",
                    encode(serde_json::to_string(&legacy_payload)?.as_bytes())
                )
            } else {
                let mut compressed = DeflateEncoder::new(Vec::new(), Compression::best());
                compressed.write_all(serde_json::to_string(&payload)?.as_bytes())?;
                let compressed = compressed.finish()?;
                format!("kw2:{}", encode(&compressed))
            };
            let output = flag_value(&args, "--output").unwrap_or_else(|| {
                format!(
                    "{}/keywarden-pairing.png",
                    env::var("TMPDIR").unwrap_or_else(|_| "/tmp".into())
                )
            });
            let installed_script = env::current_exe()?
                .parent()
                .unwrap_or(Path::new("."))
                .join("../share/keywarden/keywarden-qr.swift");
            let script = env::var("KEYWARDEN_QR_SCRIPT").unwrap_or_else(|_| {
                if installed_script.exists() {
                    installed_script.to_string_lossy().into_owned()
                } else {
                    "scripts/keywarden-qr.swift".into()
                }
            });
            let terminal = !args.iter().any(|arg| arg == "--no-terminal");
            if terminal {
                println!("Pairing QR:");
            }
            let mut command = Command::new("swift");
            command
                .args([script.as_str(), output.as_str()])
                .stdin(Stdio::piped());
            if terminal {
                command.arg("--terminal");
            }
            let mut child = command.spawn()?;
            if let Some(mut input) = child.stdin.take() {
                input.write_all(qr_payload.as_bytes()).await?;
            }
            let status = child.wait().await?;
            if !status.success() {
                return Err(msg("Could not create pairing QR"));
            }
            println!("Pairing QR written to {output}");
            Ok(())
        }
        _ => cli::run(&args).await,
    }
}

fn compact_public_key(value: &Value) -> Result<Value> {
    let object = value
        .as_object()
        .ok_or_else(|| msg("Broker public key is invalid"))?;
    let x = object
        .get("x")
        .and_then(Value::as_str)
        .ok_or_else(|| msg("Broker public key is invalid"))?;
    let y = object
        .get("y")
        .and_then(Value::as_str)
        .ok_or_else(|| msg("Broker public key is invalid"))?;
    Ok(serde_json::json!([x, y]))
}

async fn read_token_stdin() -> Result<()> {
    let mut token = String::new();
    tokio::io::stdin().read_to_string(&mut token).await?;
    let token = token.trim().to_owned();
    if token.is_empty() {
        return Err(msg("Empty service token on stdin"));
    }
    *BROKER_TOKEN.lock().await = Some(token);
    Ok(())
}

async fn serve(broker: Arc<Broker>, socket_path: &Path) -> Result<()> {
    if let Some(parent) = socket_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    prepare_socket(socket_path).await?;
    let listener = UnixListener::bind(socket_path)?;
    use std::os::unix::fs::PermissionsExt;
    tokio::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600)).await?;
    println!("keywarden broker listening on {}", socket_path.display());
    let admin_path = socket_path.with_extension("admin.sock");
    prepare_socket(&admin_path).await?;
    let admin_listener = UnixListener::bind(&admin_path)?;
    tokio::fs::set_permissions(&admin_path, std::fs::Permissions::from_mode(0o600)).await?;
    let admin_broker = Arc::clone(&broker);
    tokio::spawn(async move {
        while let Ok((stream, _)) = admin_listener.accept().await {
            let broker = Arc::clone(&admin_broker);
            tokio::spawn(async move {
                let _ = handle_connection(stream, broker, true).await;
            });
        }
    });
    loop {
        let (stream, _) = listener.accept().await?;
        let broker = Arc::clone(&broker);
        tokio::spawn(async move {
            if let Err(error) = handle_connection(stream, broker, false).await {
                eprintln!("keywarden: {error}");
            }
        });
    }
}

async fn prepare_socket(path: &Path) -> Result<()> {
    use std::os::unix::fs::FileTypeExt;
    match tokio::fs::symlink_metadata(path).await {
        Ok(metadata) => {
            if !metadata.file_type().is_socket() {
                return Err(msg("Refusing to replace a non-socket file"));
            }
            if UnixStream::connect(path).await.is_ok() {
                return Err(msg("Broker socket is already in use"));
            }
            tokio::fs::remove_file(path).await?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

async fn handle_connection(mut stream: UnixStream, broker: Arc<Broker>, admin: bool) -> Result<()> {
    let request = tokio::time::timeout(TokioDuration::from_secs(10), read_http(&mut stream))
        .await
        .map_err(|_| msg("Local request timed out"))??;
    if request.path == "/v1/notification-credentials" {
        let result: Result<()> = if admin && request.method == "POST" {
            match json_body::<push::Credentials>(&request.body).and_then(push::PushSender::new) {
                Ok(sender) => {
                    *broker.push.lock().await = Some(sender);
                    Ok(())
                }
                Err(_) => Err(msg("Invalid push credentials")),
            }
        } else {
            Err(msg("Use the trusted local notification setup command"))
        };
        return write_http(
            &mut stream,
            if result.is_ok() { 200 } else { 403 },
            if result.is_ok() {
                b"{\"ok\":true}"
            } else {
                b"{\"error\":\"Notification setup rejected\"}"
            },
        )
        .await;
    }
    let (status, body) = route(&broker, request).await;
    write_http(&mut stream, status, &serde_json::to_vec(&body)?).await?;
    Ok(())
}

#[derive(Debug)]
struct HttpRequest {
    method: String,
    path: String,
    body: Vec<u8>,
}

async fn read_http(stream: &mut UnixStream) -> Result<HttpRequest> {
    let mut data = Vec::new();
    let header_end;
    loop {
        let mut chunk = [0_u8; 4096];
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(msg("Request ended before headers"));
        }
        data.extend_from_slice(&chunk[..read]);
        if data.len() > MAX_BODY_BYTES {
            return Err(msg("Request body is too large"));
        }
        if let Some(index) = data.windows(4).position(|window| window == b"\r\n\r\n") {
            header_end = index + 4;
            break;
        }
    }
    let header = String::from_utf8_lossy(&data[..header_end]);
    let mut lines = header.split("\r\n");
    let request_line = lines.next().ok_or_else(|| msg("Missing request line"))?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts
        .next()
        .ok_or_else(|| msg("Missing method"))?
        .to_owned();
    let path = request_parts
        .next()
        .ok_or_else(|| msg("Missing path"))?
        .to_owned();
    let content_length = lines
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            (name.eq_ignore_ascii_case("content-length"))
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    if content_length > MAX_BODY_BYTES {
        return Err(msg("Request body is too large"));
    }
    while data.len() < header_end + content_length {
        let mut chunk = [0_u8; 4096];
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(msg("Request ended before body"));
        }
        data.extend_from_slice(&chunk[..read]);
    }
    Ok(HttpRequest {
        method,
        path,
        body: data[header_end..header_end + content_length].to_vec(),
    })
}

async fn write_http(stream: &mut UnixStream, status: u16, body: &[u8]) -> Result<()> {
    let reason = match status {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "Error",
    };
    let header = format!("HTTP/1.1 {status} {reason}\r\ncontent-type: application/json; charset=utf-8\r\ncontent-length: {}\r\nconnection: close\r\n\r\n", body.len());
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.shutdown().await?;
    Ok(())
}

async fn route(broker: &Arc<Broker>, request: HttpRequest) -> (u16, Value) {
    match route_inner(broker, request).await {
        Ok(value) => (200, value),
        Err(error) => (400, serde_json::json!({"error": error.to_string()})),
    }
}

async fn route_inner(broker: &Arc<Broker>, request: HttpRequest) -> Result<Value> {
    let path = request.path.split('?').next().unwrap_or(&request.path);
    if request.method == "GET" && path == "/health" {
        return Ok(serde_json::json!({"ok": true}));
    }
    if request.method == "GET" && path == "/v1/status" {
        broker.refresh_pairing().await?;
        let phone = broker
            .pairing
            .lock()
            .await
            .clone()
            .map(|pairing| pairing.phone_id);
        let requests: Vec<_> = broker.store.lock().await.requests.values()
            .filter(|pending| pending.status == "pending" && timestamp(&pending.request.expires_at).is_ok_and(|at| at > Utc::now()))
            .map(|pending| serde_json::json!({"requestId":pending.request.id,"expiresAt":pending.request.expires_at,"agent":pending.request.agent})).collect();
        let accepted = broker.last_push.lock().await.clone();
        return Ok(
            serde_json::json!({"ok":true,"brokerId":broker.identity.broker_id,"phoneId":phone,"relay":broker.relay.is_some(),"notifications":broker.push.lock().await.is_some(),"lastPushAt":accepted,"lastAppleAcceptedAt":accepted,"phoneDelivery":"unconfirmed","pendingRequests":requests}),
        );
    }
    if request.method == "GET" && path == "/v1/identity" {
        return Ok(
            serde_json::json!({"brokerId": broker.identity.broker_id, "signingPublicJwk": broker.identity.signing_public, "encryptionPublicJwk": broker.identity.encryption_public}),
        );
    }
    if request.method == "POST" && path == "/v1/operations/resolve" {
        let operation: OperationRequest = json_body(&request.body)?;
        broker
            .prepare_vault_aliases(&operation.profile, &operation.lease_id)
            .await?;
        // Resolve existing access without executing 1Password or renewing idle time.
        // The execution path still performs the final scope and expiry checks.
        let resolved = broker.store.lock().await.resolve_operation(&operation)?;
        return Ok(serde_json::json!({"leaseId":resolved.lease_id,"account":resolved.profile}));
    }
    if request.method == "POST" && path == "/v1/vaults" {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct VaultQuery {
            account: String,
            lease_id: String,
        }
        let query: VaultQuery = json_body(&request.body)?;
        return broker
            .discover_vaults(&query.account, &query.lease_id)
            .await;
    }
    if request.method == "POST" && path == "/v1/session-requests" {
        let input: SessionInputWire = json_body(&request.body)?;
        let pending = broker
            .create_session(SessionInput::try_from(input)?)
            .await?;
        return broker.request_status(&pending.request.id).await;
    }
    if request.method == "GET" && path.starts_with("/v1/session-requests/") {
        let request_id = path.trim_start_matches("/v1/session-requests/");
        return broker.request_status(request_id).await;
    }
    if request.method == "POST" && path.starts_with("/v1/session-requests/") {
        if let Some((id, action)) = path
            .trim_start_matches("/v1/session-requests/")
            .split_once('/')
        {
            return broker.manage_request(id, action).await;
        }
    }
    if request.method == "POST" && path.starts_with("/v1/leases/") && path.ends_with("/revoke") {
        let lease_id = path
            .trim_start_matches("/v1/leases/")
            .trim_end_matches("/revoke")
            .trim_end_matches('/');
        broker.store.lock().await.revoke(lease_id);
        return Ok(serde_json::json!({"ok": true}));
    }
    if request.method == "POST" && path == "/v1/operations" {
        let operation: OperationRequest = json_body(&request.body)?;
        return Ok(serde_json::to_value(
            broker.run_operation(operation).await?,
        )?);
    }
    if request.method == "POST" && path == "/v1/phone-pairing" {
        if env::var("KEYWARDEN_DEV_MODE").as_deref() != Ok("1") {
            return Err(msg("Use QR pairing outside development mode"));
        }
        let pairing: PhonePairing = json_body(&request.body)?;
        save_pairing(&broker.identity.state_dir, &pairing).await?;
        *broker.pairing.lock().await = Some(pairing.clone());
        return Ok(serde_json::json!({"ok": true, "phoneId": pairing.phone_id}));
    }
    if request.method == "POST" && path == "/v1/dev/approve" {
        if env::var("KEYWARDEN_DEV_MODE").as_deref() != Ok("1") {
            return Err(msg("Development approval is disabled"));
        }
        let body: DevApproval = json_body(&request.body)?;
        let pending = broker
            .store
            .lock()
            .await
            .requests
            .get(&body.request_id)
            .cloned()
            .ok_or_else(|| msg("Unknown session request"))?;
        let decision = ApprovalDecision {
            version: 1,
            decision_type: "approval_decision".into(),
            request_id: body.request_id.clone(),
            request_hash: pending.request_hash,
            decision: "approve".into(),
            decided_at: now(),
            nonce: id("dev_nonce"),
        };
        broker
            .store
            .lock()
            .await
            .approve(&body.request_id, &decision)?;
        return Ok(serde_json::json!({"ok": true}));
    }
    Err(msg("Not found"))
}

#[derive(Deserialize)]
struct SessionInputWire {
    agent: String,
    host: String,
    #[serde(rename = "phoneId")]
    phone_id: String,
    reason: String,
    #[serde(default)]
    intent: Option<ApprovalIntent>,
    #[serde(default)]
    client: Option<ClientMetadata>,
    scope: SessionScope,
    #[serde(rename = "durationSeconds")]
    duration_seconds: i64,
    #[serde(rename = "idleTimeoutSeconds")]
    idle_timeout_seconds: i64,
}

impl TryFrom<SessionInputWire> for SessionInput {
    type Error = BrokerError;
    fn try_from(value: SessionInputWire) -> Result<Self> {
        let intent = value.intent.unwrap_or_else(|| ApprovalIntent {
            task: None,
            reason: value.reason.clone(),
        });
        if intent.reason != value.reason {
            return Err(msg("Approval intent reason must match reason"));
        }
        let client = value
            .client
            .unwrap_or_else(|| ClientMetadata::manual(&value.agent, &value.host));
        Ok(Self {
            agent: value.agent,
            host: value.host,
            phone_id: value.phone_id,
            reason: value.reason,
            intent,
            client,
            scope: value.scope,
            duration_seconds: value.duration_seconds,
            idle_timeout_seconds: value.idle_timeout_seconds,
        })
    }
}

#[derive(Deserialize)]
struct DevApproval {
    #[serde(rename = "requestId")]
    request_id: String,
}

impl From<Pending> for PendingResponse {
    fn from(value: Pending) -> Self {
        Self {
            request: value.request,
            request_hash: value.request_hash,
            status: value.status,
            lease_id: value.lease_id,
        }
    }
}

fn json_body<T: DeserializeOwned>(body: &[u8]) -> Result<T> {
    Ok(serde_json::from_slice(body)?)
}

fn normalize_scope(mut scope: SessionScope) -> Result<SessionScope> {
    dedup(&mut scope.accounts);
    scope.vaults = scope
        .vaults
        .into_iter()
        .map(|item| item.trim().to_owned())
        .filter(|item| !item.is_empty())
        .collect();
    dedup(&mut scope.vaults);
    dedup(&mut scope.operations);
    if scope.accounts.is_empty() {
        return Err(msg("A session needs an account"));
    }
    if scope.vaults.is_empty() {
        return Err(msg("A session needs a vault scope"));
    }
    if scope.operations.is_empty() {
        return Err(msg("A session needs an operation scope"));
    }
    if scope.operations.iter().any(|operation| {
        !["read", "list", "write", "create", "delete"].contains(&operation.as_str())
    }) {
        return Err(msg("Unsupported operation scope"));
    }
    match &scope.items {
        ItemsScope::All(value) if value != "all" => return Err(msg("Invalid item scope")),
        ItemsScope::Values(values) if values.is_empty() => return Err(msg("Invalid item scope")),
        _ => (),
    }
    if let ItemsScope::Values(values) = &mut scope.items {
        dedup(values);
    }
    Ok(scope)
}

fn scope_covers(granted: &SessionScope, requested: &SessionScope) -> bool {
    let contains_all = |granted: &[String], requested: &[String]| {
        requested.iter().all(|item| {
            granted
                .iter()
                .any(|allowed| allowed == item || allowed == "*")
        })
    };
    let items_cover = match (&granted.items, &requested.items) {
        (ItemsScope::All(_), _) => true,
        (ItemsScope::Values(granted), ItemsScope::Values(requested)) => {
            contains_all(granted, requested)
        }
        (ItemsScope::Values(_), ItemsScope::All(_)) => false,
    };
    contains_all(&granted.accounts, &requested.accounts)
        && contains_all(&granted.vaults, &requested.vaults)
        && contains_all(&granted.operations, &requested.operations)
        && items_cover
}

fn dedup(values: &mut Vec<String>) {
    let mut seen = std::collections::HashSet::new();
    values.retain(|value| seen.insert(value.clone()));
}

async fn load_identity(state_dir: &Path) -> Result<Identity> {
    let path = state_dir.join("broker-identity.json");
    if let Ok(bytes) = tokio::fs::read(&path).await {
        let stored: StoredIdentity = serde_json::from_slice(&bytes)?;
        return Identity::from_stored(stored, state_dir.to_owned());
    }
    let signing_private = SecretKey::random(&mut OsRng);
    let encryption_private = SecretKey::random(&mut OsRng);
    let stored = StoredIdentity {
        broker_id: id("broker"),
        signing_private_jwk: private_jwk(&signing_private, "sign"),
        signing_public_jwk: public_jwk(&signing_private, "verify"),
        encryption_private_jwk: private_jwk(&encryption_private, "deriveKey"),
        encryption_public_jwk: public_jwk(&encryption_private, "deriveKey"),
    };
    tokio::fs::write(&path, serde_json::to_vec_pretty(&stored)?).await?;
    use std::os::unix::fs::PermissionsExt;
    tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).await?;
    Identity::from_stored(stored, state_dir.to_owned())
}

#[derive(Serialize, Deserialize)]
struct StoredIdentity {
    #[serde(rename = "brokerId")]
    broker_id: String,
    #[serde(rename = "signingPrivateJwk")]
    signing_private_jwk: Value,
    #[serde(rename = "signingPublicJwk")]
    signing_public_jwk: Value,
    #[serde(rename = "encryptionPrivateJwk")]
    encryption_private_jwk: Value,
    #[serde(rename = "encryptionPublicJwk")]
    encryption_public_jwk: Value,
}

impl Identity {
    fn from_stored(stored: StoredIdentity, state_dir: PathBuf) -> Result<Self> {
        Ok(Self {
            broker_id: stored.broker_id,
            signing_private: secret_from_jwk(&stored.signing_private_jwk)?,
            signing_public: stored.signing_public_jwk,
            encryption_private: secret_from_jwk(&stored.encryption_private_jwk)?,
            encryption_public: stored.encryption_public_jwk,
            state_dir,
        })
    }
}

async fn load_pairing(state_dir: &Path) -> Result<Option<PhonePairing>> {
    if let (Ok(phone_id), Ok(encryption), Ok(signing)) = (
        env::var("KEYWARDEN_PHONE_ID"),
        env::var("KEYWARDEN_PHONE_ENCRYPTION_PUBLIC_JWK"),
        env::var("KEYWARDEN_PHONE_SIGNING_PUBLIC_JWK"),
    ) {
        return Ok(Some(PhonePairing {
            phone_id,
            encryption_public_jwk: serde_json::from_str(&encryption)?,
            signing_public_jwk: serde_json::from_str(&signing)?,
        }));
    }
    match tokio::fs::read(state_dir.join("phone-pairing.json")).await {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

async fn load_pairing_setup(state_dir: &Path) -> Result<Option<PairingSetup>> {
    match tokio::fs::read(state_dir.join("pairing-setup.json")).await {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

async fn save_pairing_setup(state_dir: &Path, setup: &PairingSetup) -> Result<()> {
    let path = state_dir.join("pairing-setup.json");
    tokio::fs::write(&path, serde_json::to_vec_pretty(setup)?).await?;
    use std::os::unix::fs::PermissionsExt;
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).await?;
    Ok(())
}

async fn clear_pairing_setup(state_dir: &Path) -> Result<()> {
    match tokio::fs::remove_file(state_dir.join("pairing-setup.json")).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

async fn save_pairing(state_dir: &Path, pairing: &PhonePairing) -> Result<()> {
    let path = state_dir.join("phone-pairing.json");
    tokio::fs::write(&path, serde_json::to_vec_pretty(pairing)?).await?;
    use std::os::unix::fs::PermissionsExt;
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).await?;
    Ok(())
}

fn secret_from_jwk(jwk: &Value) -> Result<SecretKey> {
    let d = jwk
        .get("d")
        .and_then(Value::as_str)
        .ok_or(CryptoError::InvalidKey)?;
    SecretKey::from_slice(&decode(d)?).map_err(|_| CryptoError::InvalidKey.into())
}

fn public_key_from_jwk(jwk: &Value) -> Result<PublicKey> {
    let x = decode(
        jwk.get("x")
            .and_then(Value::as_str)
            .ok_or(CryptoError::InvalidKey)?,
    )?;
    let y = decode(
        jwk.get("y")
            .and_then(Value::as_str)
            .ok_or(CryptoError::InvalidKey)?,
    )?;
    let mut encoded = vec![4_u8];
    encoded.extend_from_slice(&x);
    encoded.extend_from_slice(&y);
    PublicKey::from_sec1_bytes(&encoded).map_err(|_| CryptoError::InvalidKey.into())
}

fn private_jwk(secret: &SecretKey, operation: &str) -> Value {
    let mut value = public_jwk(secret, operation);
    value
        .as_object_mut()
        .unwrap()
        .insert("d".into(), Value::String(encode(&secret.to_bytes())));
    value
}

fn public_jwk(secret: &SecretKey, operation: &str) -> Value {
    let point = secret.public_key().to_encoded_point(false);
    serde_json::json!({"kty":"EC","crv":"P-256","x":encode(point.x().unwrap()),"y":encode(point.y().unwrap()),"ext":true,"key_ops":[operation]})
}

fn encrypt_for_public_key(plaintext: &str, recipient_jwk: &Value) -> Result<EncryptedPayload> {
    let recipient = public_key_from_jwk(recipient_jwk)?;
    let ephemeral = SecretKey::random(&mut OsRng);
    let shared = ecdh::diffie_hellman(ephemeral.to_nonzero_scalar(), recipient.as_affine());
    let cipher = Aes256Gcm::new_from_slice(shared.raw_secret_bytes().as_slice())
        .map_err(|_| CryptoError::Encryption)?;
    let iv = rand_bytes::<12>();
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&iv), plaintext.as_bytes())
        .map_err(|_| CryptoError::Encryption)?;
    Ok(EncryptedPayload {
        version: 1,
        algorithm: "ECDH-P256-AES-256-GCM".into(),
        ephemeral_public_key: public_jwk(&ephemeral, "deriveKey"),
        iv: encode(&iv),
        ciphertext: encode(&ciphertext),
    })
}

fn decrypt_with_private_key(payload: &EncryptedPayload, private: &SecretKey) -> Result<String> {
    if payload.version != 1 || payload.algorithm != "ECDH-P256-AES-256-GCM" {
        return Err(CryptoError::InvalidEnvelope.into());
    }
    let ephemeral = public_key_from_jwk(&payload.ephemeral_public_key)?;
    let shared = ecdh::diffie_hellman(private.to_nonzero_scalar(), ephemeral.as_affine());
    let cipher = Aes256Gcm::new_from_slice(shared.raw_secret_bytes().as_slice())
        .map_err(|_| CryptoError::Encryption)?;
    let iv = decode(&payload.iv)?;
    if iv.len() != 12 {
        return Err(CryptoError::InvalidEnvelope.into());
    }
    let clear = cipher
        .decrypt(
            Nonce::from_slice(&iv),
            decode(&payload.ciphertext)?.as_ref(),
        )
        .map_err(|_| CryptoError::Encryption)?;
    String::from_utf8(clear).map_err(|_| CryptoError::InvalidEnvelope.into())
}

fn sign_envelope(
    kind: &str,
    body: EncryptedPayload,
    private: &SecretKey,
    public: &Value,
) -> Result<SignedEnvelope> {
    let unsigned =
        serde_json::json!({"version":1,"kind":kind,"body":body,"senderPublicKey":public});
    let signing = SigningKey::from_bytes((&private.to_bytes()).into())
        .map_err(|_| CryptoError::InvalidKey)?;
    let signature: Signature = signing.sign(canonical(&unsigned).as_bytes());
    Ok(SignedEnvelope {
        version: 1,
        kind: kind.into(),
        body: serde_json::from_value(
            unsigned
                .get("body")
                .cloned()
                .ok_or(CryptoError::InvalidEnvelope)?,
        )?,
        sender_public_key: public.clone(),
        signature: encode(&signature.to_bytes()),
    })
}

fn verify_envelope(envelope: &SignedEnvelope) -> Result<bool> {
    if envelope.version != 1 {
        return Ok(false);
    }
    let public = public_key_from_jwk(&envelope.sender_public_key)?;
    let verifying = VerifyingKey::from(public);
    let unsigned = serde_json::json!({"version":envelope.version,"kind":envelope.kind,"body":envelope.body,"senderPublicKey":envelope.sender_public_key});
    let signature =
        Signature::from_slice(&decode(&envelope.signature)?).map_err(|_| CryptoError::Signature)?;
    Ok(verifying
        .verify(canonical(&unsigned).as_bytes(), &signature)
        .is_ok())
}

fn hash_request(request: &OpenSessionRequest) -> Result<String> {
    Ok(encode(&Sha256::digest(
        canonical(&serde_json::to_value(request)?).as_bytes(),
    )))
}

fn hash_request_legacy(request: &OpenSessionRequest) -> Result<String> {
    // Build 7 decoded requests before intent and client metadata existed.
    // Keep this compatibility hash bound to every access-bearing field.
    let mut value = serde_json::to_value(request)?;
    if let Some(object) = value.as_object_mut() {
        object.remove("client");
        object.remove("intent");
    }
    Ok(encode(&Sha256::digest(canonical(&value).as_bytes())))
}

fn hash_request_ios(request: &OpenSessionRequest) -> Result<String> {
    let value = omit_nulls(serde_json::to_value(request)?);
    Ok(encode(&Sha256::digest(canonical(&value).as_bytes())))
}

fn omit_nulls(value: Value) -> Value {
    match value {
        Value::Object(object) => Value::Object(
            object
                .into_iter()
                .filter_map(|(key, value)| (!value.is_null()).then(|| (key, omit_nulls(value))))
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.into_iter().map(omit_nulls).collect()),
        value => value,
    }
}

fn request_hash_matches(
    request: &OpenSessionRequest,
    expected_hash: &str,
    decision_hash: &str,
) -> Result<bool> {
    Ok(decision_hash == expected_hash
        || decision_hash == hash_request_legacy(request)?
        || decision_hash == hash_request_ios(request)?)
}

fn canonical(value: &Value) -> String {
    match value {
        Value::Null => "null".into(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::String(value) => serde_json::to_string(value).unwrap(),
        Value::Array(values) => format!(
            "[{}]",
            values.iter().map(canonical).collect::<Vec<_>>().join(",")
        ),
        Value::Object(values) => {
            let mut keys: Vec<_> = values.keys().collect();
            keys.sort();
            format!(
                "{{{}}}",
                keys.into_iter()
                    .map(|key| format!(
                        "{}:{}",
                        serde_json::to_string(key).unwrap(),
                        canonical(&values[key])
                    ))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        }
    }
}

fn timestamp(value: &str) -> Result<DateTime<Utc>> {
    Ok(DateTime::parse_from_rfc3339(value)
        .map_err(|_| msg("Invalid timestamp"))?
        .with_timezone(&Utc))
}
fn now() -> String {
    Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}
fn id(prefix: &str) -> String {
    format!("{}_{}", prefix, encode(Uuid::new_v4().as_bytes()))
}
fn encode(value: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(value)
}
fn decode(value: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| CryptoError::InvalidEnvelope.into())
}
fn rand_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0_u8; N];
    OsRng.fill_bytes(&mut bytes);
    bytes
}
fn url_escape(value: &str) -> String {
    value
        .replace('%', "%25")
        .replace('/', "%2F")
        .replace(' ', "%20")
}
fn msg(value: impl Into<String>) -> BrokerError {
    BrokerError::Message(value.into())
}
fn flag_value(args: &[String], flag: &str) -> Option<String> {
    args.windows(2)
        .find(|pair| pair[0] == flag)
        .map(|pair| pair[1].clone())
}

fn opgate_profile_for_account(account: &str) -> String {
    match account {
        "agent" => env::var("KEYWARDEN_OPGATE_PROFILE").unwrap_or_else(|_| "agent".into()),
        "personal" => env::var("KEYWARDEN_OPGATE_PERSONAL_PROFILE")
            .unwrap_or_else(|_| "keywarden-personal".into()),
        "work" => env::var("KEYWARDEN_OPGATE_WORK_PROFILE")
            .unwrap_or_else(|_| "keywarden-work".into()),
        _ => account.into(),
    }
}

async fn resolve_relay_config(args: &[String]) -> Result<(String, String)> {
    let relay_url = flag_value(args, "--relay-url")
        .or_else(|| env::var("KEYWARDEN_RELAY_URL").ok())
        .or(config::load()?.relay_url)
        .unwrap_or_else(|| DEFAULT_RELAY_URL.to_owned());
    if let Ok(relay_token) = env::var("KEYWARDEN_RELAY_TOKEN") {
        if !relay_token.is_empty() {
            return Ok((relay_url, relay_token));
        }
    }
    let profile = flag_value(args, "--opgate-profile")
        .or_else(|| env::var("KEYWARDEN_OPGATE_PROFILE").ok())
        .unwrap_or_else(|| "agent".to_owned());
    let reference = flag_value(args, "--relay-token-ref")
        .or_else(|| env::var("KEYWARDEN_RELAY_TOKEN_REF").ok())
        .unwrap_or_else(|| DEFAULT_RELAY_TOKEN_REF.to_owned());

    let mut command = Command::new("opgate");
    command.args([
        "op",
        "--profile",
        profile.as_str(),
        "--",
        "read",
        "--cache=false",
        reference.as_str(),
    ]);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    for key in env::vars()
        .map(|(key, _)| key)
        .filter(|key| key.starts_with("KEYWARDEN_"))
    {
        command.env_remove(key);
    }
    let output = provider::output(command, TokioDuration::from_secs(15)).await?;
    if !output.status.success() {
        return Err(msg(format!(
            "Could not read the relay token through opgate profile '{profile}'"
        )));
    }
    let relay_token = String::from_utf8(output.stdout)
        .map_err(|_| msg("opgate returned an invalid relay token"))?
        .trim()
        .to_owned();
    if relay_token.is_empty() {
        return Err(msg(format!(
            "Could not read the relay token through opgate profile '{profile}'"
        )));
    }
    Ok((relay_url, relay_token))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_command_scope_cases() {
        let cases: Value =
            serde_json::from_str(include_str!("../../../protocol/test/command-cases.json"))
                .unwrap();
        for case in cases.as_array().unwrap() {
            let operation: OperationRequest =
                serde_json::from_value(case["operation"].clone()).unwrap();
            assert_eq!(
                command::target(&operation).is_ok(),
                case["valid"].as_bool().unwrap(),
                "{}",
                case["name"]
            );
        }
    }

    #[test]
    fn canonical_json_sorts_keys() {
        assert_eq!(
            canonical(&serde_json::json!({"b":2,"a":1})),
            "{\"a\":1,\"b\":2}"
        );
    }

    #[test]
    fn rust_crypto_round_trip() {
        let recipient = SecretKey::random(&mut OsRng);
        let payload =
            encrypt_for_public_key("local secret", &public_jwk(&recipient, "deriveKey")).unwrap();
        assert_eq!(
            decrypt_with_private_key(&payload, &recipient).unwrap(),
            "local secret"
        );
    }

    #[test]
    fn legacy_phone_hash_is_accepted_and_returned_in_status() {
        let mut store = SessionStore::new();
        let (pending, created) = store
            .create(SessionInput {
                agent: "Codex".into(),
                host: "Mac".into(),
                phone_id: "phone-1".into(),
                reason: "Read metadata".into(),
                intent: ApprovalIntent {
                    task: Some("Inspect items".into()),
                    reason: "Read metadata".into(),
                },
                client: ClientMetadata::manual("Codex", "Mac"),
                scope: SessionScope {
                    accounts: vec!["personal".into()],
                    vaults: vec!["Vault".into()],
                    items: ItemsScope::All("all".into()),
                    operations: vec!["list".into()],
                },
                duration_seconds: 300,
                idle_timeout_seconds: 60,
            })
            .unwrap();
        assert!(created);
        let legacy_hash = hash_request_legacy(&pending.request).unwrap();
        assert_ne!(legacy_hash, pending.request_hash);
        let lease = store
            .approve(
                &pending.request.id,
                &ApprovalDecision {
                    version: 1,
                    decision_type: "approval_decision".into(),
                    request_id: pending.request.id.clone(),
                    request_hash: legacy_hash.clone(),
                    decision: "approve".into(),
                    decided_at: now(),
                    nonce: "legacy".into(),
                },
            )
            .unwrap();
        assert_eq!(lease.request_hash, legacy_hash);
        let approved = store.requests.get(&pending.request.id).cloned().unwrap();
        let status = store.status(&approved);
        assert_eq!(status["requestHash"], legacy_hash);
    }

    #[test]
    fn ios_hash_without_null_optional_fields_is_accepted() {
        let mut store = SessionStore::new();
        let (pending, created) = store
            .create(SessionInput {
                agent: "Codex".into(),
                host: "Mac".into(),
                phone_id: "phone-1".into(),
                reason: "Read metadata".into(),
                intent: ApprovalIntent {
                    task: Some("Inspect items".into()),
                    reason: "Read metadata".into(),
                },
                client: ClientMetadata::manual("Codex", "Mac"),
                scope: SessionScope {
                    accounts: vec!["personal".into()],
                    vaults: vec!["Vault".into()],
                    items: ItemsScope::All("all".into()),
                    operations: vec!["list".into()],
                },
                duration_seconds: 300,
                idle_timeout_seconds: 60,
            })
            .unwrap();
        assert!(created);
        let ios_hash = hash_request_ios(&pending.request).unwrap();
        assert_ne!(ios_hash, pending.request_hash);
        let lease = store
            .approve(
                &pending.request.id,
                &ApprovalDecision {
                    version: 1,
                    decision_type: "approval_decision".into(),
                    request_id: pending.request.id.clone(),
                    request_hash: ios_hash.clone(),
                    decision: "approve".into(),
                    decided_at: now(),
                    nonce: "ios".into(),
                },
            )
            .unwrap();
        assert_eq!(lease.request_hash, ios_hash);
    }
}
