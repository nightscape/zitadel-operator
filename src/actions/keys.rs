use crate::{schema::ActionHandler, Error, OperatorContext, Result};
use k8s_openapi::api::core::v1::Secret;
use kube::{
    api::{ObjectMeta, Patch, PatchParams},
    Api, Resource,
};
use std::collections::BTreeMap;

const SECRET_FIELD: &str = "signingKey";

/// Secret holding the signing key Zitadel issued for a handler's target.
pub fn secret_name(handler: &str) -> String {
    format!("{handler}-action-handler")
}

/// The signing key for a handler, from the cache if it is warm and from the
/// Secret if it is not.
///
/// Zitadel reveals a target's signing key only when it mints one, so losing it
/// costs a rotation. The Secret is what makes a restart free, and reading it on
/// a cache miss is what stops a fresh process from serving unverified calls
/// until its first reconcile.
pub async fn load(ctx: &OperatorContext, namespace: &str, name: &str) -> Result<Option<String>> {
    if let Some(cached) = ctx.signing_keys.get(namespace, name) {
        return Ok(Some(cached));
    }

    let secrets = Api::<Secret>::namespaced(ctx.k8s.clone(), namespace);
    let Some(secret) = secrets.get_opt(&secret_name(name)).await? else {
        return Ok(None);
    };
    let Some(bytes) = secret.data.and_then(|mut d| d.remove(SECRET_FIELD)) else {
        return Err(Error::Other(format!(
            "secret {} holds no {SECRET_FIELD}",
            secret_name(name)
        )));
    };
    let signing_key = String::from_utf8(bytes.0)
        .map_err(|e| Error::Other(format!("signing key is not valid UTF-8: {e}")))?;

    ctx.signing_keys.set(namespace, name, signing_key.clone());
    Ok(Some(signing_key))
}

/// Writes the key to its Secret and warms the cache. The Secret is owned by the
/// handler, so deleting the handler takes it along.
pub async fn store(ctx: &OperatorContext, ah: &ActionHandler, signing_key: String) -> Result<()> {
    let namespace = ah.metadata.namespace.as_ref().unwrap();
    let name = ah.metadata.name.as_ref().unwrap();
    let secret_name = secret_name(name);

    let secret = Secret {
        metadata: ObjectMeta {
            name: Some(secret_name.clone()),
            namespace: Some(namespace.clone()),
            owner_references: Some(vec![ah.controller_owner_ref(&()).unwrap()]),
            ..Default::default()
        },
        string_data: Some(BTreeMap::from([(
            SECRET_FIELD.to_string(),
            signing_key.clone(),
        )])),
        ..Default::default()
    };

    Api::<Secret>::namespaced(ctx.k8s.clone(), namespace)
        .patch(
            &secret_name,
            &PatchParams::apply("cntrlr").force(),
            &Patch::Apply(&secret),
        )
        .await?;

    ctx.signing_keys.set(namespace, name, signing_key);
    Ok(())
}
