use crate::util::{GetStatus, IsReady};
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[kube(kind = "Project", group = "zitadel.org", version = "v1alpha", namespaced)]
#[kube(status = "ProjectStatus")]
#[serde(rename_all = "camelCase")]
pub struct ProjectSpec {
    #[schemars(length(min = 1, max = 200))]
    pub name: String,
    pub organization_name: String,
    #[serde(default)]
    pub project_role_assertion: bool,
}
#[derive(Deserialize, Serialize, Clone, Default, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ProjectStatus {
    pub id: String,
    pub organization_id: String,
    pub phase: ProjectPhase,
}
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq)]
pub enum ProjectPhase {
    Ready,
}
impl Default for ProjectPhase {
    fn default() -> Self {
        Self::Ready
    }
}
impl IsReady for Project {
    fn is_ready(&self) -> bool {
        if let Some(status) = &self.status {
            status.phase == ProjectPhase::Ready
        } else {
            false
        }
    }
}
impl GetStatus for Project {
    type Status = ProjectStatus;
    fn get_status(&self) -> &Option<Self::Status> {
        &self.status
    }
}
