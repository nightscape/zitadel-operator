use crate::util::{GetStatus, IsReady};
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[kube(kind = "IdentityProvider", group = "zitadel.org", version = "v1alpha", namespaced)]
#[kube(status = "IdentityProviderStatus")]
#[kube(shortname = "idp")]
#[serde(rename_all = "camelCase")]
pub struct IdentityProviderSpec {
    /// Display name, shown to users on the login screen
    #[schemars(length(min = 1, max = 200))]
    pub name: String,
    /// Reference to the owning Organization by metadata.name
    pub organization_name: String,
    /// Create a Zitadel user on first login instead of requiring an existing one.
    /// Leave off where the organization already holds the user population, or
    /// federation builds a second one beside it.
    #[serde(default)]
    pub auto_register: bool,
    /// Offer this provider on the organization's login screen.
    ///
    /// Zitadel keeps provider configuration and login-screen membership apart,
    /// so a provider that is not on the login policy is configured correctly
    /// and still invisible. Defaulting this on makes that state something you
    /// have to ask for rather than something you fall into.
    #[serde(default = "yes")]
    pub show_on_login_screen: bool,
    #[serde(flatten)]
    pub(crate) inner: IdentityProviderInnerSpec,
}

fn yes() -> bool {
    true
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) enum IdentityProviderInnerSpec {
    Jwt(IdentityProviderJwtSpec),
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct IdentityProviderJwtSpec {
    /// Expected `iss` claim. A String rather than a Url because Zitadel compares
    /// it to the token byte for byte, and Url would normalise `https://host`
    /// into `https://host/`.
    #[schemars(length(min = 1, max = 200))]
    pub issuer: String,
    /// Where Zitadel sends the browser to obtain a token
    pub jwt_endpoint: Url,
    /// Where Zitadel fetches the signing keys, server to server
    pub keys_endpoint: Url,
    /// Request header carrying the token on the callback. A browser cannot set
    /// headers on a navigation, so something at the edge must put it there.
    #[schemars(length(min = 1, max = 200))]
    pub header_name: String,
}

#[derive(Deserialize, Serialize, Clone, Default, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct IdentityProviderStatus {
    pub id: String,
    pub organization_id: String,
    #[serde(default)]
    pub phase: IdentityProviderPhase,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq)]
pub enum IdentityProviderPhase {
    Ready,
}

impl Default for IdentityProviderPhase {
    fn default() -> Self {
        Self::Ready
    }
}

impl IsReady for IdentityProvider {
    fn is_ready(&self) -> bool {
        if let Some(status) = &self.status {
            status.phase == IdentityProviderPhase::Ready
        } else {
            false
        }
    }
}

impl GetStatus for IdentityProvider {
    type Status = IdentityProviderStatus;
    fn get_status(&self) -> &Option<Self::Status> {
        &self.status
    }
}
