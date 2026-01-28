use crate::util::{GetStatus, IsReady};
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[kube(kind = "UserGrant", group = "zitadel.org", version = "v1alpha", namespaced)]
#[kube(status = "UserGrantStatus")]
#[kube(shortname = "ugrant")]
#[serde(rename_all = "camelCase")]
pub struct UserGrantSpec {
    /// Reference to HumanUser by metadata.name
    pub user_name: String,
    /// Namespace of HumanUser (defaults to same namespace)
    #[serde(default)]
    pub user_namespace: Option<String>,
    /// Reference to Project by metadata.name
    pub project_name: String,
    /// Namespace of Project (defaults to same namespace)
    #[serde(default)]
    pub project_namespace: Option<String>,
    /// Role keys to grant (must exist as ProjectRole in Zitadel)
    pub role_keys: Vec<String>,
}

#[derive(Deserialize, Serialize, Clone, Default, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct UserGrantStatus {
    pub id: String,
    pub user_id: String,
    pub project_id: String,
    pub organization_id: String,
    pub phase: UserGrantPhase,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq)]
pub enum UserGrantPhase {
    Ready,
}

impl Default for UserGrantPhase {
    fn default() -> Self {
        Self::Ready
    }
}

impl IsReady for UserGrant {
    fn is_ready(&self) -> bool {
        if let Some(status) = &self.status {
            status.phase == UserGrantPhase::Ready
        } else {
            false
        }
    }
}

impl GetStatus for UserGrant {
    type Status = UserGrantStatus;
    fn get_status(&self) -> &Option<Self::Status> {
        &self.status
    }
}
