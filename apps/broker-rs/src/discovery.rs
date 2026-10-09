//! Metadata-only discovery. Resolve aliases only inside already approved account scopes.
use crate::{msg, Broker, OperationRequest, Result, SessionStore, Value};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct Vault {
    pub id: String,
    pub name: String,
}

pub(crate) struct VaultCache {
    records: Vec<Vault>,
    fetched: Instant,
}

pub(crate) fn vault_matches(
    aliases: &HashMap<String, Vec<Vault>>,
    account: &str,
    left: &str,
    right: &str,
) -> bool {
    if left == right {
        return true;
    }
    let Some(records) = aliases.get(account) else {
        return false;
    };
    let resolve = |name: &str| {
        let matches: Vec<_> = records
            .iter()
            .filter(|v| v.id == name || v.name == name)
            .collect();
        (matches.len() == 1).then(|| matches[0].id.as_str())
    };
    matches!((resolve(left), resolve(right)), (Some(a), Some(b)) if a == b)
}

impl SessionStore {
    pub(crate) fn vault_matches(&self, account: &str, left: &str, right: &str) -> bool {
        vault_matches(&self.vault_aliases, account, left, right)
    }

    fn discovery_scopes(
        &self,
        account: &str,
        lease_id: &str,
        list_only: bool,
    ) -> Result<HashMap<String, Vec<String>>> {
        if !["auto", "agent", "personal", "work"].contains(&account) {
            return Err(msg("Invalid account"));
        }
        let mut scopes: HashMap<String, Vec<String>> = HashMap::new();
        if ["active", "direct-agent"].contains(&lease_id) && ["auto", "agent"].contains(&account) {
            scopes.insert("agent".into(), vec!["agents".into()]);
        }
        if lease_id == "direct-agent" {
            if scopes.is_empty() {
                return Err(msg("Account is outside the direct agent scope"));
            }
            return Ok(scopes);
        }
        if lease_id != "active" && !self.leases.contains_key(lease_id) {
            return Err(msg("Unknown session lease"));
        }
        for lease in self.leases.values() {
            if lease_id != "active" && lease.id != lease_id {
                continue;
            }
            let live = lease.status == "active"
                && crate::timestamp(&lease.expires_at).is_ok_and(|at| at > chrono::Utc::now())
                && crate::timestamp(&lease.idle_until).is_ok_and(|at| at > chrono::Utc::now());
            if !live {
                if lease_id != "active" {
                    return Err(msg(if lease.status == "revoked" {
                        "Session lease is revoked"
                    } else {
                        "Session lease expired"
                    }));
                }
                continue;
            }
            if list_only && !lease.scope.operations.iter().any(|op| op == "list") {
                continue;
            }
            for allowed_account in &lease.scope.accounts {
                if account != "auto" && account != allowed_account {
                    continue;
                }
                scopes
                    .entry(allowed_account.clone())
                    .or_default()
                    .extend(lease.scope.vaults.clone());
            }
        }
        for vaults in scopes.values_mut() {
            vaults.sort();
            vaults.dedup();
        }
        Ok(scopes)
    }
}

impl Broker {
    async fn load_vaults(&self, account: &str, target: &str) -> Result<Vec<Vault>> {
        let key = format!("{account}:{target}");
        if let Some(cache) = self.vault_cache.lock().await.get(&key) {
            if cache.fetched.elapsed() < Duration::from_secs(60) {
                return Ok(cache.records.clone());
            }
        }
        let args = if target == "*" {
            vec!["vault".into(), "list".into(), "--format=json".into()]
        } else {
            vec![
                "vault".into(),
                "get".into(),
                target.into(),
                "--format=json".into(),
            ]
        };
        let output = self.run_provider(account, &args).await?;
        if output.exit_code != 0 {
            return Err(msg(provider_message(
                output.error_code.as_deref().unwrap_or("op_rejected"),
            )));
        }
        let data: Value = serde_json::from_str(&output.stdout)
            .map_err(|_| msg("Broker returned invalid vault metadata"))?;
        let records: Vec<Vault> = if target == "*" {
            serde_json::from_value(data)
        } else {
            serde_json::from_value(data).map(|v| vec![v])
        }
        .map_err(|_| msg("Broker returned invalid vault metadata"))?;
        if records.iter().any(|v| v.id.is_empty() || v.name.is_empty()) {
            return Err(msg("Broker returned invalid vault metadata"));
        }
        if target != "*"
            && (records.len() != 1 || (records[0].id != target && records[0].name != target))
        {
            return Err(msg("Vault metadata does not match the requested scope"));
        }
        self.vault_cache.lock().await.insert(
            key,
            VaultCache {
                records: records.clone(),
                fetched: Instant::now(),
            },
        );
        Ok(records)
    }

    pub(crate) async fn prepare_vault_aliases(&self, account: &str, lease: &str) -> Result<()> {
        let scopes = self
            .store
            .lock()
            .await
            .discovery_scopes(account, lease, false)?;
        for (account, targets) in scopes {
            let mut records = Vec::new();
            for target in targets {
                records.extend(self.load_vaults(&account, &target).await?);
            }
            records.sort_by(|a, b| a.id.cmp(&b.id));
            records.dedup_by(|a, b| a.id == b.id);
            self.store
                .lock()
                .await
                .vault_aliases
                .insert(account, records);
        }
        Ok(())
    }

    pub(crate) async fn pin_operation_vault(
        &self,
        mut operation: OperationRequest,
    ) -> Result<OperationRequest> {
        crate::command::target(&operation)?;
        let store = self.store.lock().await;
        let target = operation.vault.as_deref().unwrap_or("");
        let records = store
            .vault_aliases
            .get(&operation.profile)
            .ok_or_else(|| msg("Vault not found in approved scope"))?;
        let matches: Vec<_> = records
            .iter()
            .filter(|v| v.id == target || v.name == target)
            .collect();
        if matches.len() > 1 {
            return Err(msg("Vault name is ambiguous. Supply the vault ID."));
        }
        let vault = matches
            .first()
            .ok_or_else(|| msg("Vault not found in approved scope"))?;
        if operation.args.first().map(String::as_str) == Some("read") {
            let index = operation
                .args
                .iter()
                .position(|arg| arg.starts_with("op://"))
                .ok_or_else(|| msg("Read needs one secret reference"))?;
            let reference = operation.args[index]
                .strip_prefix(&format!("op://{target}/"))
                .ok_or_else(|| msg("Vault does not match command"))?;
            operation.args[index] = format!("op://{}/{reference}", vault.id);
        } else {
            for index in 0..operation.args.len() {
                if operation.args[index] == "--vault" {
                    operation.args[index + 1] = vault.id.clone();
                } else if operation.args[index].starts_with("--vault=") {
                    operation.args[index] = format!("--vault={}", vault.id);
                }
            }
        }
        operation.vault = Some(vault.id.clone());
        crate::command::target(&operation)?;
        Ok(operation)
    }

    pub(crate) async fn discover_vaults(&self, account: &str, lease: &str) -> Result<Value> {
        if account == "auto" {
            return Err(msg(
                "Supply account agent, personal, or work for vault discovery",
            ));
        }
        let scopes = self
            .store
            .lock()
            .await
            .discovery_scopes(account, lease, true)?;
        let targets = scopes
            .get(account)
            .ok_or_else(|| msg("No active lease matches this operation"))?;
        let mut records = Vec::new();
        for target in targets {
            records.extend(self.load_vaults(account, target).await?);
        }
        // Recheck after network IO. Revocation and expiry can occur during lookup.
        let current = self
            .store
            .lock()
            .await
            .discovery_scopes(account, lease, true)?;
        let allowed = current
            .get(account)
            .ok_or_else(|| msg("No active lease matches this operation"))?;
        records.retain(|v| {
            allowed
                .iter()
                .any(|name| name == "*" || name == &v.id || name == &v.name)
        });
        records.sort_by(|a, b| a.id.cmp(&b.id));
        records.dedup_by(|a, b| a.id == b.id);
        Ok(json!({"account":account,"vaults":records}))
    }
}

pub(crate) fn item_metadata(items: &Value) -> Result<Value> {
    let items = items
        .as_array()
        .ok_or_else(|| msg("Broker returned invalid item output"))?;
    Ok(Value::Array(
        items
            .iter()
            .map(|item| {
                let mut safe = serde_json::Map::new();
                for key in ["id", "title", "category"] {
                    if let Some(value) = item[key].as_str() {
                        safe.insert(key.into(), json!(value));
                    }
                }
                Value::Object(safe)
            })
            .collect(),
    ))
}

pub(crate) fn provider_error_code(stderr: &str) -> &'static str {
    let text = stderr.to_lowercase();
    if text.contains("isn't an item in")
        || text.contains("item not found")
        || text.contains("could not find item")
    {
        "item_not_found"
    } else if text.contains("could not find field")
        || text.contains("field not found")
        || text.contains("does not have a field")
    {
        "field_not_found"
    } else if text.contains("isn't a vault") || text.contains("vault not found") {
        "vault_not_found"
    } else if text.contains("not signed in")
        || text.contains("authentication failed")
        || text.contains("invalid service account token")
    {
        "authentication_failed"
    } else if text.contains("permission denied")
        || text.contains("not authorized")
        || text.contains("forbidden")
    {
        "provider_permission_denied"
    } else if text.contains("profile")
        && (text.contains("not found") || text.contains("does not exist"))
    {
        "account_unavailable"
    } else {
        "op_rejected"
    }
}

pub(crate) fn provider_message(code: &str) -> &'static str {
    match code {
        "item_not_found" => "Item not found. List items in the approved vault and use an item ID.",
        "field_not_found" => {
            "Field not found. Discover fields for the item and use a returned reference."
        }
        "vault_not_found" => {
            "Vault not found in the account. Discover approved vaults and use a vault ID."
        }
        "authentication_failed" => {
            "1Password authentication failed. Check the account service profile on the Mac."
        }
        "provider_permission_denied" => {
            "1Password permission denied. Check the service account vault permissions."
        }
        "account_unavailable" => {
            "Account profile unavailable. Configure the account service profile on the Mac."
        }
        _ => "1Password rejected the operation. The broker withheld command output.",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn metadata_excludes_notes_usernames_and_fields() {
        assert_eq!(item_metadata(&json!([{"id":"i","title":"t","category":"LOGIN","additional_information":"canary","fields":[{"value":"secret"}],"vault":{"id":"v"}}])).unwrap(), json!([{"id":"i","title":"t","category":"LOGIN"}]));
    }
    #[test]
    fn aliases_are_account_scoped_and_reject_ambiguous_names() {
        let mut aliases = HashMap::new();
        aliases.insert(
            "agent".into(),
            vec![Vault {
                id: "id-1".into(),
                name: "agents".into(),
            }],
        );
        assert!(vault_matches(&aliases, "agent", "agents", "id-1"));
        assert!(!vault_matches(&aliases, "personal", "agents", "id-1"));
        aliases.get_mut("agent").unwrap().push(Vault {
            id: "id-2".into(),
            name: "agents".into(),
        });
        assert!(!vault_matches(&aliases, "agent", "agents", "id-1"));
    }
    #[test]
    fn provider_errors_never_echo_provider_output() {
        for (text, code) in [
            ("secret isn't an item in vault", "item_not_found"),
            ("could not find field secret", "field_not_found"),
            ("permission denied secret", "provider_permission_denied"),
            ("unexpected secret", "op_rejected"),
        ] {
            assert_eq!(provider_error_code(text), code);
            assert!(!provider_message(code).contains("secret"));
        }
    }

    #[test]
    fn aliases_cannot_bypass_lease_scope_expiry_or_revocation() {
        let mut store = SessionStore::new();
        store.vault_aliases.insert(
            "personal".into(),
            vec![Vault {
                id: "vault-id".into(),
                name: "Approved".into(),
            }],
        );
        let future = (chrono::Utc::now() + chrono::Duration::minutes(5)).to_rfc3339();
        store.leases.insert(
            "lease".into(),
            crate::SessionLease {
                version: 1,
                id: "lease".into(),
                request_id: "request".into(),
                request_hash: "hash".into(),
                agent: "Codex".into(),
                host: "Mac".into(),
                scope: crate::SessionScope {
                    accounts: vec!["personal".into()],
                    vaults: vec!["Approved".into()],
                    items: crate::ItemsScope::All("all".into()),
                    operations: vec!["list".into()],
                },
                issued_at: crate::now(),
                expires_at: future.clone(),
                idle_until: future,
                idle_timeout_seconds: 60,
                status: "active".into(),
            },
        );
        let mut operation = OperationRequest {
            version: 1,
            lease_id: "lease".into(),
            profile: "personal".into(),
            operation: "list".into(),
            vault: Some("vault-id".into()),
            item_id: None,
            field: None,
            args: vec![
                "item".into(),
                "list".into(),
                "--vault".into(),
                "vault-id".into(),
                "--format=json".into(),
            ],
        };
        store.authorize(&operation).unwrap();
        operation.vault = Some("other-id".into());
        operation.args[3] = "other-id".into();
        assert!(store.authorize(&operation).is_err());
        operation.vault = Some("vault-id".into());
        operation.args[3] = "vault-id".into();
        store.leases.get_mut("lease").unwrap().idle_until =
            (chrono::Utc::now() - chrono::Duration::seconds(1)).to_rfc3339();
        assert!(store
            .authorize(&operation)
            .unwrap_err()
            .to_string()
            .contains("idle timeout"));
        store.leases.get_mut("lease").unwrap().status = "revoked".into();
        assert!(store
            .authorize(&operation)
            .unwrap_err()
            .to_string()
            .contains("revoked"));
        assert!(store
            .discovery_scopes("personal", "active", true)
            .unwrap()
            .is_empty());
        assert_eq!(
            store.discovery_scopes("agent", "active", true).unwrap()["agent"],
            vec!["agents"]
        );
    }
}
