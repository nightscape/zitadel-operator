use crate::util::{schema_list_is_set, GetStatus, IsReady};
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use url::Url;

#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[kube(kind = "Application", group = "zitadel.org", version = "v1alpha", namespaced)]
#[kube(status = "ApplicationStatus")]
#[serde(rename_all = "camelCase")]
pub struct ApplicationSpec {
    #[schemars(length(min = 1, max = 200))]
    pub name: String,
    pub project_name: String,
    pub project_namespace: Option<String>,
    #[serde(flatten)]
    pub(crate) inner: ApplicationInnerSpec,
}
#[derive(Deserialize, Serialize, Clone, Default, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationStatus {
    pub id: String,
    pub project_id: String,
    pub organization_id: String,
    #[serde(default)]
    pub phase: ApplicationPhase,
}
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq)]
pub enum ApplicationPhase {
    Ready,
}
impl Default for ApplicationPhase {
    fn default() -> Self {
        Self::Ready
    }
}
impl IsReady for Application {
    fn is_ready(&self) -> bool {
        if let Some(status) = &self.status {
            status.phase == ApplicationPhase::Ready
        } else {
            false
        }
    }
}
impl GetStatus for Application {
    type Status = ApplicationStatus;
    fn get_status(&self) -> &Option<Self::Status> {
        &self.status
    }
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) enum ApplicationInnerSpec {
    Oidc(ApplicationOidcSpec),
    Api(ApplicationApiSpec),
}
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq)]
pub(crate) enum ResponseType {
    Code,
    IdToken,
    IdTokenToken,
}
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq)]
pub(crate) enum GrantType {
    AuthorizationCode,
    Implicit,
    RefreshToken,
    DeviceCode,
    TokenExchange,
}
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq)]
pub(crate) enum AppType {
    Web,
    UserAgent,
    Native,
}
impl AppType {
    pub fn web() -> Self {
        AppType::Web
    }
}
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq)]
pub(crate) enum OidcAuthMethodType {
    Basic,
    Post,
    None,
    PrivateKeyJwt,
}
impl OidcAuthMethodType {
    pub fn basic() -> Self {
        OidcAuthMethodType::Basic
    }
}
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq)]
pub(crate) enum OidcVersion {
    V1_0,
}
impl Default for OidcVersion {
    fn default() -> Self {
        OidcVersion::V1_0
    }
}
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq)]
pub(crate) enum OidcTokenType {
    Bearer,
    Jwt,
}
impl OidcTokenType {
    pub fn bearer() -> Self {
        OidcTokenType::Bearer
    }
}
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ApplicationOidcSpec {
    pub redirect_uris: Vec<Url>,
    pub response_types: Vec<ResponseType>,
    pub grant_types: Vec<GrantType>,
    #[serde(default = "AppType::web")]
    pub app_type: AppType,
    #[serde(default = "OidcAuthMethodType::basic")]
    pub auth_method: OidcAuthMethodType,
    #[serde(default)]
    pub post_logout_redirect_uris: Vec<Url>,
    #[serde(default)]
    pub version: OidcVersion,
    #[serde(default)]
    pub dev_mode: bool,
    #[serde(default = "OidcTokenType::bearer")]
    pub access_token_type: OidcTokenType,
    #[serde(default)]
    pub access_token_role_assertion: bool,
    #[serde(default)]
    pub id_token_role_assertion: bool,
    #[serde(default)]
    pub id_token_userinfo_assertion: bool,
    #[serde(default)]
    pub clock_skew: Option<Duration>,
    #[schemars(schema_with = "schema_list_is_set::<Url>")]
    #[serde(default)]
    pub additional_origins: Vec<Url>,
    #[serde(default)]
    pub skip_native_app_success_page: bool,
    #[serde(default)]
    pub backchannel_logout_uri: String,
}

#[derive(Deserialize, Serialize, Clone, Copy, Debug, JsonSchema)]
pub(crate) enum ApiAuthMethodType {
    Basic,
    PrivateKeyJwt,
}
impl ApiAuthMethodType {
    pub fn basic() -> Self {
        ApiAuthMethodType::Basic
    }
}
impl From<ApiAuthMethodType> for zitadel::api::zitadel::app::v1::ApiAuthMethodType {
    fn from(value: ApiAuthMethodType) -> Self {
        match value {
            ApiAuthMethodType::Basic => Self::Basic,
            ApiAuthMethodType::PrivateKeyJwt => Self::PrivateKeyJwt,
        }
    }
}
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ApplicationApiSpec {
    #[serde(default = "ApiAuthMethodType::basic")]
    pub method: ApiAuthMethodType,
}
