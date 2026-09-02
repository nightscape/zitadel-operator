use crate::util::{GetStatus, IsReady};
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A hook into Zitadel's Actions v2. The operator registers a Target pointing at
/// its own HTTP server plus an Execution for the condition, then serves the
/// calls itself: it runs `transform` over the payload Zitadel sends and hands
/// back what Zitadel should use in place of the original.
#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[kube(kind = "ActionHandler", group = "zitadel.org", version = "v1alpha", namespaced)]
#[kube(status = "ActionHandlerStatus")]
#[kube(shortname = "ahandler")]
#[serde(rename_all = "camelCase")]
pub struct ActionHandlerSpec {
    /// When Zitadel calls the handler. Set exactly one member.
    pub condition: ActionCondition,
    /// jq predicate over the payload deciding whether the handler applies. A
    /// handler without one applies to every call matching the condition.
    #[serde(default)]
    pub when: Option<String>,
    /// jq program mapping the payload Zitadel sent to the payload it should use.
    #[serde(default)]
    pub transform: Option<String>,
    /// Grant a project role to the user named by the payload.
    #[serde(default)]
    pub grant_roles: Option<GrantRoles>,
}

/// Zitadel's execution condition. Exactly one member must be set; the operator
/// rejects the resource otherwise.
///
/// Modelled as four optional fields rather than an enum because Kubernetes
/// structural schemas take a plain object far better than a `oneOf`, and the
/// serialised form is the same either way.
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq, Default)]
#[serde(rename_all = "camelCase")]
pub struct ActionCondition {
    /// Before the call, with the chance to rewrite the request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<MethodCondition>,
    /// After the call, with the chance to rewrite the response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response: Option<MethodCondition>,
    /// On an event. Zitadel ignores whatever the handler returns.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event: Option<EventCondition>,
    /// On one of Zitadel's named extension points.
    ///
    /// UNTESTED. Zitadel's payload for a function execution is shaped by the
    /// function, and the operator has never seen one: it answers with the whole
    /// transform output rather than a member of it, which is a guess.
    ///
    /// Request and response conditions carry unit tests over recorded payload
    /// shapes; no condition has yet been observed against a running Zitadel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function: Option<FunctionCondition>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MethodCondition {
    /// Full gRPC method, e.g. `/zitadel.user.v2.UserService/AddHumanUser`
    #[schemars(length(min = 1, max = 1000))]
    pub method: String,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EventCondition {
    /// Event type, e.g. `user.human.added`
    #[schemars(length(min = 1, max = 1000))]
    pub event: String,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FunctionCondition {
    #[schemars(length(min = 1, max = 1000))]
    pub name: String,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ConditionKind {
    Request,
    Response,
    Event,
    Function,
}

impl ActionHandlerSpec {
    /// The condition's kind, once the spec is known to be coherent.
    pub fn validate(&self) -> Result<ConditionKind, String> {
        let kind = self.condition.kind()?;
        if self.grant_roles.is_some() && kind == ConditionKind::Request {
            return Err("grantRoles needs a user to grant to, and a request condition \
                        fires before the user exists; move it to a response or event \
                        condition"
                .to_string());
        }
        Ok(kind)
    }
}

impl ActionCondition {
    /// Fails unless exactly one member is set.
    pub fn kind(&self) -> Result<ConditionKind, String> {
        let set: Vec<ConditionKind> = [
            self.request.is_some().then_some(ConditionKind::Request),
            self.response.is_some().then_some(ConditionKind::Response),
            self.event.is_some().then_some(ConditionKind::Event),
            self.function.is_some().then_some(ConditionKind::Function),
        ]
        .into_iter()
        .flatten()
        .collect();
        match set[..] {
            [kind] => Ok(kind),
            [] => Err("condition sets none of request, response, event, function".to_string()),
            _ => Err(format!("condition sets {} of request, response, event, function", set.len())),
        }
    }
}

/// The one side effect a handler may have. Zitadel refuses a token to a user
/// without a grant on a project with `projectRoleCheck`, which is exactly the
/// state a freshly auto-registered federated user is in.
///
/// Belongs on a `response` or `event` condition. On a `request` condition the
/// user does not exist yet and the call carries no id to grant to, so the
/// operator rejects that combination rather than letting it fail per login.
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GrantRoles {
    /// Reference to Project by metadata.name. The grant is written in the
    /// organization that owns the project.
    pub project_name: String,
    /// Namespace of Project (defaults to the handler's namespace)
    #[serde(default)]
    pub project_namespace: Option<String>,
    /// Role keys to grant (must exist as ProjectRole in Zitadel)
    pub role_keys: Vec<String>,
    /// jq expression yielding the id of the user to grant. The default reads the
    /// id a user-creating call returns.
    #[serde(default = "default_user_id_from")]
    pub user_id_from: String,
}

fn default_user_id_from() -> String {
    ".response.userId".to_string()
}

#[derive(Deserialize, Serialize, Clone, Default, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ActionHandlerStatus {
    pub target_id: String,
    /// The condition currently registered in Zitadel. Kept so that a changed
    /// spec can clear the execution it replaces.
    pub condition: ActionCondition,
    pub phase: ActionHandlerPhase,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq)]
pub enum ActionHandlerPhase {
    Ready,
}

impl Default for ActionHandlerPhase {
    fn default() -> Self {
        Self::Ready
    }
}

impl IsReady for ActionHandler {
    fn is_ready(&self) -> bool {
        if let Some(status) = &self.status {
            status.phase == ActionHandlerPhase::Ready
        } else {
            false
        }
    }
}

impl GetStatus for ActionHandler {
    type Status = ActionHandlerStatus;
    fn get_status(&self) -> &Option<Self::Status> {
        &self.status
    }
}
