use crate::util::{GetStatus, IsReady};
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[kube(kind = "ProjectRole", group = "zitadel.org", version = "v1alpha", namespaced)]
#[kube(status = "ProjectRoleStatus")]
#[kube(shortname = "prole")]
#[serde(rename_all = "camelCase")]
pub struct ProjectRoleSpec {
    /// Role key - must be unique within project (e.g., "tenant:admin")
    #[schemars(length(min = 1, max = 200))]
    pub key: String,
    /// Human-readable display name
    #[schemars(length(min = 1, max = 200))]
    pub display_name: String,
    /// Optional group for organizing roles in ZITADEL console UI
    #[serde(default)]
    pub group: Option<String>,
    /// Reference to parent Project by metadata.name
    pub project_name: String,
    /// Namespace of parent Project (defaults to same namespace)
    #[serde(default)]
    pub project_namespace: Option<String>,
}

#[derive(Deserialize, Serialize, Clone, Default, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProjectRoleStatus {
    pub project_id: String,
    pub organization_id: String,
    pub phase: ProjectRolePhase,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq)]
pub enum ProjectRolePhase {
    Ready,
}

impl Default for ProjectRolePhase {
    fn default() -> Self {
        Self::Ready
    }
}

impl IsReady for ProjectRole {
    fn is_ready(&self) -> bool {
        if let Some(status) = &self.status {
            status.phase == ProjectRolePhase::Ready
        } else {
            false
        }
    }
}

impl GetStatus for ProjectRole {
    type Status = ProjectRoleStatus;
    fn get_status(&self) -> &Option<Self::Status> {
        &self.status
    }
}
