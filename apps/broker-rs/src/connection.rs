use crate::{
    discovery::{provider_message, Vault},
    msg, now, Broker, Result, TokioDuration,
};
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CheckQuery {
    pub account: Option<String>,
}

impl CheckQuery {
    pub fn validate(&self) -> Result<()> {
        if self
            .account
            .as_deref()
            .is_some_and(|a| !["agent", "personal", "work"].contains(&a))
        {
            return Err(msg("Invalid account. Use agent, personal, or work."));
        }
        Ok(())
    }
}

impl Broker {
    pub(crate) async fn check_connections(&self, query: CheckQuery) -> Result<Value> {
        query.validate()?;
        let mut checks = Vec::new();
        for account in ["agent", "personal", "work"] {
            if query
                .account
                .as_deref()
                .is_some_and(|selected| selected != account)
            {
                continue;
            }
            checks.push((account, self.check_connection(account).await));
        }
        // Report current permissions after network calls. Checks never renew idle limits.
        let mut overview = self.store.lock().await.access_overview();
        overview["providerCheck"] = json!("completed");
        for account in overview["accounts"].as_array_mut().unwrap() {
            account["providerCheck"] = checks
                .iter()
                .find(|(name, _)| account["account"] == *name)
                .map(|(_, result)| result.clone())
                .unwrap_or_else(|| json!({"status":"not_performed"}));
        }
        Ok(overview)
    }

    async fn check_connection(&self, account: &str) -> Value {
        let targets = self
            .store
            .lock()
            .await
            .discovery_scopes(account, "active", true);
        let target = targets
            .ok()
            .and_then(|scopes| scopes.get(account).and_then(|v| v.first()).cloned());
        let Some(target) = target else {
            return json!({"status":"skipped","code":"list_access_required",
                "next":"Use existing list access, or request list approval separately. This check never requests approval."});
        };
        // Always call the provider. A discovery cache cannot prove current connectivity.
        let args = if target == "*" {
            vec!["vault".into(), "list".into(), "--format=json".into()]
        } else {
            vec![
                "vault".into(),
                "get".into(),
                target.clone(),
                "--format=json".into(),
            ]
        };
        let result = self
            .run_provider_with_timeout(account, &args, TokioDuration::from_secs(8))
            .await;
        let still_allowed = self
            .store
            .lock()
            .await
            .discovery_scopes(account, "active", true)
            .ok()
            .and_then(|scopes| scopes.get(account).cloned())
            .is_some_and(|targets| targets.contains(&target) || targets.iter().any(|v| v == "*"));
        if !still_allowed {
            return json!({"status":"skipped","code":"access_changed","checkedAt":now(),
                "next":"Access expired or was revoked during the check. Check access status."});
        }
        match result {
            Ok(output) if output.exit_code == 0 => {
                let valid = if target == "*" {
                    serde_json::from_str::<Vec<Vault>>(&output.stdout)
                        .is_ok_and(|vaults| vaults.iter().all(|v| !v.id.is_empty() && !v.name.is_empty()))
                } else {
                    serde_json::from_str::<Vault>(&output.stdout)
                        .is_ok_and(|v| !v.id.is_empty() && !v.name.is_empty() && (v.id == target || v.name == target))
                };
                if valid {
                    json!({"status":"ok","checkedAt":now(),"operation":"vault_metadata",
                        "note":"The provider answered within approved list scope. This does not verify field reads or writes."})
                } else { failed("invalid_provider_response", "1Password returned invalid vault metadata.") }
            }
            Ok(output) => {
                let code = output.error_code.as_deref().unwrap_or("op_rejected");
                failed(code, provider_message(code))
            }
            Err(error) if error.to_string().contains("timed out") =>
                failed("provider_timeout", "1Password did not respond within the check timeout. Retry the check."),
            Err(_) => failed("provider_unavailable", "Could not run 1Password. Check the local provider installation and account profile."),
        }
    }
}

fn failed(code: &str, message: &str) -> Value {
    json!({"status":"failed","code":code,"message":message,"checkedAt":now()})
}
