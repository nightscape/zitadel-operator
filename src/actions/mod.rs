mod handler;
mod jq;
mod keys;
mod rest;
mod server;
mod signature;

use std::{
    collections::HashMap,
    env,
    sync::{Arc, RwLock},
};

pub use keys::{load as load_signing_key, store as store_signing_key};
pub use rest::ActionsApi;
pub use server::run;

const DEFAULT_PORT: u16 = 8090;

pub fn port() -> u16 {
    env::var("ACTION_HANDLER_PORT")
        .ok()
        .map(|v| v.parse().unwrap_or_else(|_| panic!("invalid ACTION_HANDLER_PORT: {v}")))
        .unwrap_or(DEFAULT_PORT)
}

/// URL under which Zitadel reaches this operator, e.g.
/// `http://zitadel-operator.zitadel.svc.cluster.local:8090`.
pub fn base_url() -> Result<String, String> {
    env::var("ACTION_HANDLER_URL")
        .map(|url| url.trim_end_matches('/').to_string())
        .map_err(|_| {
            "ACTION_HANDLER_URL is unset, so Zitadel has no address to call this handler on"
                .to_string()
        })
}

pub fn endpoint(namespace: &str, name: &str) -> Result<String, String> {
    Ok(format!("{}/handlers/{namespace}/{name}", base_url()?))
}

/// Name the target carries in Zitadel. Zitadel's namespace for targets is the
/// whole instance, so the Kubernetes coordinates go into the name.
pub fn target_name(namespace: &str, name: &str) -> String {
    format!("k8s/{namespace}/{name}")
}

/// In-process cache of the signing keys Zitadel issued for the operator's own
/// targets. The durable copy is a Secret beside each handler; this only spares
/// the login path an API read.
#[derive(Clone, Default)]
pub struct SigningKeys(Arc<RwLock<HashMap<String, String>>>);

impl SigningKeys {
    pub fn get(&self, namespace: &str, name: &str) -> Option<String> {
        self.0.read().unwrap().get(&key(namespace, name)).cloned()
    }

    pub fn set(&self, namespace: &str, name: &str, signing_key: String) {
        self.0.write().unwrap().insert(key(namespace, name), signing_key);
    }

    pub fn remove(&self, namespace: &str, name: &str) {
        self.0.write().unwrap().remove(&key(namespace, name));
    }
}

fn key(namespace: &str, name: &str) -> String {
    format!("{namespace}/{name}")
}
