use crate::{msg, now, Broker, PendingResponse, Result, Value};
use serde_json::json;

impl Broker {
    pub(crate) async fn set_delivery(&self, id: &str, key: &str, value: Value) {
        let mut delivery = self.delivery.lock().await;
        delivery
            .entry(id.into())
            .or_insert_with(|| json!({"phoneReceipt":"unconfirmed"}))[key] = value;
    }

    pub(crate) async fn send_notification(&self, id: &str) {
        let status = match self.notify_phone(id).await {
            Ok(status) => status,
            Err(_) => json!({"state":"failed","attemptedAt":now(),"errorCode":"push_unavailable",
                "next":"Open Keywarden to review the request. Retry the notification after checking phone registration."}),
        };
        self.set_delivery(id, "push", status).await;
    }

    pub(crate) async fn request_status(&self, id: &str) -> Result<Value> {
        let mut store = self.store.lock().await;
        if let Some(pending) = store.requests.get_mut(id) {
            if pending.status == "pending"
                && crate::timestamp(&pending.request.expires_at)? <= chrono::Utc::now()
            {
                pending.status = "expired".into();
            }
        }
        let pending = store
            .requests
            .get(id)
            .cloned()
            .ok_or_else(|| msg("Unknown session request"))?;
        let session = store.status(&pending);
        let mut body = serde_json::to_value(PendingResponse::from(pending))?;
        body["session"] = session;
        drop(store);
        body["delivery"] = self.delivery.lock().await.get(id).cloned().unwrap_or_else(|| json!({
            "relay":{"state":"unavailable"},"push":{"state":"not_attempted"},"phoneReceipt":"unconfirmed"
        }));
        body["delivery"]["note"] = json!(
            "Apple acceptance does not confirm phone delivery. Open Keywarden if no alert appears."
        );
        Ok(body)
    }

    pub(crate) async fn manage_request(&self, id: &str, action: &str) -> Result<Value> {
        {
            let mut store = self.store.lock().await;
            let pending = store
                .requests
                .get_mut(id)
                .ok_or_else(|| msg("Unknown session request"))?;
            if pending.status != "pending" {
                return Err(msg("Only a pending request can be retried or cancelled"));
            }
            if crate::timestamp(&pending.request.expires_at)? <= chrono::Utc::now() {
                pending.status = "expired".into();
                return Err(msg("Approval expired. Request access again."));
            }
            if action == "cancel" {
                pending.status = "cancelled".into();
            } else if action != "retry" {
                return Err(msg("Use action retry or cancel"));
            }
        }
        if action == "retry" {
            let mut statuses = self.delivery.lock().await;
            let delivery = statuses
                .entry(id.into())
                .or_insert_with(|| json!({"phoneReceipt":"unconfirmed"}));
            if delivery["lastRetryAt"]
                .as_str()
                .and_then(|at| crate::timestamp(at).ok())
                .is_some_and(|at| chrono::Utc::now() - at < chrono::Duration::seconds(30))
            {
                return Err(msg(
                    "Notification retry is limited to once every 30 seconds",
                ));
            }
            delivery["lastRetryAt"] = json!(now());
            drop(statuses);
            self.send_notification(id).await;
        } else {
            self.set_delivery(id, "poll", json!({"state":"cancelled","checkedAt":now()}))
                .await;
            // Publish the signed terminal state. The broker rejects any later decision.
            self.sync_session(id).await;
        }
        self.request_status(id).await
    }
}
