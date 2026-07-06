use crate::util::{GetStatus, IsReady};
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

fn default_manager_roles() -> Vec<String> {
    vec!["ORG_USER_MANAGER".to_string()]
}

fn default_secret_key() -> String {
    "key.json".to_string()
}

#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[kube(kind = "MachineUser", group = "zitadel.org", version = "v1alpha", namespaced)]
#[kube(status = "MachineUserStatus")]
#[kube(shortname = "muser")]
#[serde(rename_all = "camelCase")]
pub struct MachineUserSpec {
    /// Username / login name of the service account
    #[schemars(length(min = 1, max = 200))]
    pub username: String,
    /// Human-readable name of the service account
    #[schemars(length(min = 1, max = 200))]
    pub name: String,
    /// Description (optional)
    #[serde(default)]
    pub description: Option<String>,
    /// Reference to parent Organization by metadata.name
    pub organization_name: String,
    /// Zitadel org manager roles to grant (defaults to ORG_USER_MANAGER).
    /// e.g. ["ORG_USER_MANAGER"], ["ORG_OWNER"].
    #[serde(default = "default_manager_roles")]
    pub manager_roles: Vec<String>,
    /// Name of the K8s Secret the minted machine key is written into
    /// (same namespace as this MachineUser).
    pub secret_name: String,
    /// Key within the Secret that holds the key JSON (defaults to "key.json").
    #[serde(default = "default_secret_key")]
    pub secret_key: String,
    /// Optional key expiry in days. NOTE: expiry/rotation is not yet wired
    /// (kept for forward compatibility); keys are currently minted without
    /// an expiration.
    #[serde(default)]
    pub key_expiry_days: Option<i64>,
}

#[derive(Deserialize, Serialize, Clone, Default, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct MachineUserStatus {
    pub id: String,
    pub organization_id: String,
    /// Id of the currently-delivered machine key (the one whose JSON is in the Secret).
    #[serde(default)]
    pub key_id: String,
    pub phase: MachineUserPhase,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq)]
pub enum MachineUserPhase {
    Ready,
}

impl Default for MachineUserPhase {
    fn default() -> Self {
        Self::Ready
    }
}

impl IsReady for MachineUser {
    fn is_ready(&self) -> bool {
        if let Some(status) = &self.status {
            status.phase == MachineUserPhase::Ready
        } else {
            false
        }
    }
}

impl GetStatus for MachineUser {
    type Status = MachineUserStatus;
    fn get_status(&self) -> &Option<Self::Status> {
        &self.status
    }
}
