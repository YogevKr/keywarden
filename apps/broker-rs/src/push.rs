use crate::{encode, msg, now, Broker, CryptoError, Result, SignedEnvelope, Value};
use p256::{
    ecdsa::{Signature, SigningKey},
    pkcs8::DecodePrivateKey,
};
use serde::Deserialize;
use signature::Signer;

#[derive(Deserialize)]
pub struct Credentials {
    pub key_id: String,
    pub team_id: String,
    pub private_key: String,
}

pub struct PushSender {
    key_id: String,
    team_id: String,
    key: SigningKey,
}

impl PushSender {
    pub fn new(credentials: Credentials) -> Result<Self> {
        if credentials.team_id.len() != 10
            || !credentials
                .team_id
                .bytes()
                .all(|value| value.is_ascii_uppercase() || value.is_ascii_digit())
            || credentials.key_id.is_empty()
        {
            return Err(msg("Unexpected Apple push credentials"));
        }
        let key = SigningKey::from_pkcs8_pem(&credentials.private_key)
            .map_err(|_| msg("Invalid Apple push key"))?;
        Ok(Self {
            key_id: credentials.key_id,
            team_id: credentials.team_id,
            key,
        })
    }

    fn token(&self) -> String {
        let header = serde_json::json!({"alg":"ES256","kid":self.key_id});
        let claims = serde_json::json!({"iss":self.team_id,"iat":chrono::Utc::now().timestamp()});
        let unsigned = format!(
            "{}.{}",
            encode(header.to_string().as_bytes()),
            encode(claims.to_string().as_bytes())
        );
        let signature: Signature = self.key.sign(unsigned.as_bytes());
        format!("{unsigned}.{}", encode(&signature.to_bytes()))
    }
}

impl Broker {
    pub async fn notify_phone(&self, request_id: &str) -> Result<Value> {
        let token = {
            let sender = self.push.lock().await;
            let Some(sender) = sender.as_ref() else {
                return Ok(
                    serde_json::json!({"state":"disabled","next":"Run keywarden notifications enable on the Mac."}),
                );
            };
            sender.token()
        };
        let Some(relay) = &self.relay else {
            return Ok(serde_json::json!({"state":"relay_unavailable"}));
        };
        let Some(pairing) = self.pairing.lock().await.clone() else {
            return Ok(serde_json::json!({"state":"phone_unpaired"}));
        };
        let response = relay
            .client
            .get(format!(
                "{}/v1/brokers/{}/phones/{}/push",
                relay.base_url,
                crate::url_escape(&self.identity.broker_id),
                crate::url_escape(&pairing.phone_id)
            ))
            .bearer_auth(&relay.token)
            .send()
            .await?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(
                serde_json::json!({"state":"not_registered","next":"Open Keywarden on the phone and check notification permission."}),
            );
        }
        if !response.status().is_success() {
            return Err(msg("Push registration is unavailable"));
        }
        #[derive(Deserialize)]
        struct Body {
            envelope: SignedEnvelope,
        }
        let envelope = response.json::<Body>().await?.envelope;
        if crate::canonical(&envelope.sender_public_key)
            != crate::canonical(&pairing.signing_public_jwk)
            || envelope.kind != "push_registration"
            || !crate::verify_envelope(&envelope)?
        {
            return Err(CryptoError::Signature.into());
        }
        let payload: Value = serde_json::from_str(&crate::decrypt_with_private_key(
            &envelope.body,
            &self.identity.encryption_private,
        )?)?;
        let device_token = payload["deviceToken"]
            .as_str()
            .ok_or_else(|| msg("Invalid device token"))?;
        if payload["version"] != 1
            || payload["phoneId"] != pairing.phone_id
            || payload["type"] != "push_registration"
            || device_token.len() < 32
            || device_token.len() > 256
            || !device_token.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(msg("Invalid push registration"));
        }
        let host = match payload["environment"].as_str() {
            Some("production") => "api.push.apple.com",
            Some("development") => "api.sandbox.push.apple.com",
            _ => return Err(msg("Invalid push environment")),
        };
        let expiry = {
            let store = self.store.lock().await;
            let pending = store
                .requests
                .get(request_id)
                .ok_or_else(|| msg("Unknown session request"))?;
            if pending.status != "pending" {
                return Ok(serde_json::json!({"state":"not_pending"}));
            }
            crate::timestamp(&pending.request.expires_at)?.timestamp()
        };
        let response = notification_request(
            &relay.client,
            host,
            device_token,
            &token,
            request_id,
            expiry,
        )
        .send()
        .await?;
        if !response.status().is_success() {
            let http_status = response.status().as_u16();
            let body: Value = response.json().await.unwrap_or(Value::Null);
            let reason = match body["reason"].as_str() {
                Some(
                    reason @ ("BadDeviceToken"
                    | "DeviceTokenNotForTopic"
                    | "Unregistered"
                    | "ExpiredProviderToken"
                    | "InvalidProviderToken"
                    | "TooManyRequests"
                    | "ServiceUnavailable"
                    | "BadTopic"
                    | "TopicDisallowed"),
                ) => reason,
                _ => "AppleRejected",
            };
            return Ok(
                serde_json::json!({"state":"rejected","attemptedAt":now(),"httpStatus":http_status,"errorCode":reason,
                "next":"Open Keywarden and check notification permission. Refresh push credentials for provider-token errors."}),
            );
        }
        let accepted = now();
        *self.last_push.lock().await = Some(accepted.clone());
        Ok(
            serde_json::json!({"state":"apple_accepted","acceptedAt":accepted,"phoneDelivery":"unconfirmed"}),
        )
    }
}

fn notification_request(
    client: &reqwest::Client,
    host: &str,
    device_token: &str,
    token: &str,
    request_id: &str,
    expiry: i64,
) -> reqwest::RequestBuilder {
    client.post(format!("https://{host}/3/device/{device_token}"))
        .bearer_auth(token).header("apns-topic","ai.sawmills.keywarden").header("apns-push-type","alert")
        .header("apns-priority","10").header("apns-expiration",expiry.to_string()).header("apns-collapse-id",request_id)
        .json(&serde_json::json!({"aps":{"alert":{"title":"Approval requested","body":"Tap to review the access request."},"sound":"default","category":"KEYWARDEN_APPROVAL","mutable-content":1},"requestId":request_id}))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn offline_alert_lives_until_request_expiry_and_only_collapses_its_own_retries() {
        let client = reqwest::Client::new();
        let first = notification_request(
            &client,
            "api.push.apple.com",
            "synthetic-device",
            "synthetic-token",
            "request-one",
            1800000000,
        )
        .build()
        .unwrap();
        let second = notification_request(
            &client,
            "api.push.apple.com",
            "synthetic-device",
            "synthetic-token",
            "request-two",
            1800000030,
        )
        .build()
        .unwrap();
        assert_eq!(first.headers()["apns-expiration"], "1800000000");
        assert_eq!(first.headers()["apns-collapse-id"], "request-one");
        assert_ne!(
            first.headers()["apns-collapse-id"],
            second.headers()["apns-collapse-id"]
        );
        let body: Value =
            serde_json::from_slice(first.body().unwrap().as_bytes().unwrap()).unwrap();
        assert_eq!(body["requestId"], "request-one");
        assert_eq!(body["aps"]["mutable-content"], 1);
        assert_eq!(body["aps"]["alert"]["title"], "Approval requested");
        assert!(body.get("vault").is_none());
        assert!(body.get("value").is_none());
    }
}
