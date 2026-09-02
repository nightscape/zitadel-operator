use crate::{schema::ActionCondition, Error, OperatorContext, Result};
use reqwest::{Method, StatusCode};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use tracing::debug;

/// Zitadel's Actions v2 service, which the `zitadel` crate does not generate a
/// client for. The operator's gRPC credentials carry over: the interceptor's
/// access token is a plain bearer token for the REST gateway too.
pub struct ActionsApi {
    http: reqwest::Client,
    base_url: String,
    token: String,
    custom_headers: HashMap<String, String>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Target {
    pub id: String,
    pub name: String,
    pub endpoint: String,
}

impl ActionsApi {
    pub async fn new(ctx: &OperatorContext) -> Result<Self> {
        Ok(Self {
            http: reqwest::Client::new(),
            base_url: ctx.zitadel.url().trim_end_matches('/').to_string(),
            token: ctx.zitadel.access_token().await.map_err(Error::Other)?,
            custom_headers: ctx.custom_headers.clone(),
        })
    }

    async fn call(&self, method: Method, path: &str, body: Option<Value>) -> Result<Option<Value>> {
        let mut request = self
            .http
            .request(method, format!("{}{path}", self.base_url))
            .bearer_auth(&self.token);
        for (key, value) in &self.custom_headers {
            request = request.header(key, value);
        }
        if let Some(body) = body {
            request = request.json(&body);
        }

        let response = request.send().await?;
        let status = response.status();
        let text = response.text().await?;

        if status == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !status.is_success() {
            return Err(Error::Other(format!(
                "Zitadel actions API {path} returned HTTP {status}: {text}"
            )));
        }
        serde_json::from_str(&text)
            .map(Some)
            .map_err(|e| Error::Other(format!("Zitadel actions API {path} returned {text}: {e}")))
    }

    /// Creates a REST target and returns its id together with the signing key
    /// Zitadel hands out exactly once.
    pub async fn create_target(
        &self,
        name: &str,
        endpoint: &str,
        wait_for_body: bool,
    ) -> Result<(String, String)> {
        let body = self
            .call(
                Method::POST,
                "/v2beta/actions/targets",
                Some(target_body(name, endpoint, wait_for_body)),
            )
            .await?
            .ok_or_else(|| Error::Other("create target returned no body".to_string()))?;
        let id = string_field(&body, "id")?;
        let signing_key = string_field(&body, "signingKey")?;
        debug!("created action target {name} ({id})");
        Ok((id, signing_key))
    }

    pub async fn update_target(&self, id: &str, name: &str, endpoint: &str, wait_for_body: bool) -> Result<()> {
        self.call(
            Method::POST,
            &format!("/v2beta/actions/targets/{id}"),
            Some(target_body(name, endpoint, wait_for_body)),
        )
        .await?;
        Ok(())
    }

    /// Replaces the target's signing key immediately and returns the new one.
    /// The only way back to a key the operator lost, which is the state every
    /// restart leaves it in.
    pub async fn rotate_signing_key(&self, id: &str) -> Result<String> {
        let body = self
            .call(
                Method::POST,
                &format!("/v2beta/actions/targets/{id}"),
                Some(json!({ "expirationSigningKey": "0s" })),
            )
            .await?
            .ok_or_else(|| Error::Other("rotate signing key returned no body".to_string()))?;
        string_field(&body, "signingKey")
    }

    pub async fn get_target(&self, id: &str) -> Result<Option<Target>> {
        let Some(body) = self
            .call(Method::GET, &format!("/v2beta/actions/targets/{id}"), None)
            .await?
        else {
            return Ok(None);
        };
        serde_json::from_value(body["target"].clone())
            .map(Some)
            .map_err(|e| Error::Other(format!("unexpected target: {e}")))
    }

    pub async fn find_target_by_name(&self, name: &str) -> Result<Option<Target>> {
        let body = self
            .call(
                Method::POST,
                "/v2beta/actions/targets/search",
                Some(json!({
                    "filters": [{ "targetNameFilter": { "targetName": name, "method": "TEXT_FILTER_METHOD_EQUALS" } }]
                })),
            )
            .await?
            .ok_or_else(|| Error::Other("target search returned no body".to_string()))?;
        let targets: Vec<Target> = serde_json::from_value(body["targets"].clone())
            .map_err(|e| Error::Other(format!("unexpected target search result: {e}")))?;
        match targets.len() {
            0 => Ok(None),
            1 => Ok(targets.into_iter().next()),
            n => Err(Error::Other(format!("found {n} action targets named {name}"))),
        }
    }

    pub async fn delete_target(&self, id: &str) -> Result<()> {
        self.call(Method::DELETE, &format!("/v2beta/actions/targets/{id}"), None)
            .await?;
        Ok(())
    }

    /// Points a condition at a set of targets. An empty set removes the
    /// execution, which is how a handler withdraws.
    pub async fn set_execution(&self, condition: &ActionCondition, targets: &[String]) -> Result<()> {
        self.call(
            Method::PUT,
            "/v2beta/actions/executions",
            Some(json!({ "condition": condition, "targets": targets })),
        )
        .await?;
        Ok(())
    }
}

fn target_body(name: &str, endpoint: &str, wait_for_body: bool) -> Value {
    // interruptOnError stays off: a handler that fails must leave the call it
    // hooked alone rather than break it.
    let target_type = if wait_for_body {
        json!({ "restCall": { "interruptOnError": false } })
    } else {
        json!({ "restWebhook": { "interruptOnError": false } })
    };
    let mut body = json!({ "name": name, "endpoint": endpoint, "timeout": "10s" });
    body.as_object_mut()
        .unwrap()
        .extend(target_type.as_object().unwrap().clone());
    body
}

fn string_field(body: &Value, field: &str) -> Result<String> {
    body[field]
        .as_str()
        .map(String::from)
        .ok_or_else(|| Error::Other(format!("Zitadel actions API returned no {field} in {body}")))
}
