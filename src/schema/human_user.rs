use crate::util::{GetStatus, IsReady};
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[kube(kind = "HumanUser", group = "zitadel.org", version = "v1alpha", namespaced)]
#[kube(status = "HumanUserStatus")]
#[kube(shortname = "huser")]
#[serde(rename_all = "camelCase")]
pub struct HumanUserSpec {
    /// Username (typically email address)
    #[schemars(length(min = 1, max = 200))]
    pub username: String,
    /// User profile information
    pub profile: HumanUserProfile,
    /// Email configuration
    pub email: HumanUserEmail,
    /// Phone configuration (optional)
    #[serde(default)]
    pub phone: Option<HumanUserPhone>,
    /// Reference to a K8s Secret containing the initial password
    /// Secret must have a key matching the user's metadata.name
    #[serde(default)]
    pub password_secret_ref: Option<SecretKeySelector>,
    /// Reference to parent Organization by metadata.name
    pub organization_name: String,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HumanUserProfile {
    /// Given/first name
    #[schemars(length(min = 1, max = 200))]
    pub given_name: String,
    /// Family/last name
    #[schemars(length(min = 1, max = 200))]
    pub family_name: String,
    /// Nickname (optional)
    #[serde(default)]
    pub nick_name: Option<String>,
    /// Display name (optional, defaults to "GivenName FamilyName")
    #[serde(default)]
    pub display_name: Option<String>,
    /// Preferred language (BCP 47 tag, e.g., "en", "de", "sv")
    #[serde(default)]
    pub preferred_language: Option<String>,
    /// Gender (optional)
    #[serde(default)]
    pub gender: Option<Gender>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq)]
pub enum Gender {
    Unspecified,
    Female,
    Male,
    Diverse,
}

impl Default for Gender {
    fn default() -> Self {
        Self::Unspecified
    }
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HumanUserEmail {
    /// Email address
    pub email: String,
    /// Whether the email is pre-verified (skip verification email)
    #[serde(default)]
    pub is_verified: bool,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HumanUserPhone {
    /// Phone number (E.164 format recommended)
    pub phone: String,
    /// Whether the phone is pre-verified
    #[serde(default)]
    pub is_verified: bool,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SecretKeySelector {
    /// Name of the Secret
    pub name: String,
    /// Key within the Secret (defaults to the HumanUser's metadata.name)
    #[serde(default)]
    pub key: Option<String>,
}

#[derive(Deserialize, Serialize, Clone, Default, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HumanUserStatus {
    pub id: String,
    pub organization_id: String,
    pub phase: HumanUserPhase,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq)]
pub enum HumanUserPhase {
    Ready,
}

impl Default for HumanUserPhase {
    fn default() -> Self {
        Self::Ready
    }
}

impl IsReady for HumanUser {
    fn is_ready(&self) -> bool {
        if let Some(status) = &self.status {
            status.phase == HumanUserPhase::Ready
        } else {
            false
        }
    }
}

impl GetStatus for HumanUser {
    type Status = HumanUserStatus;
    fn get_status(&self) -> &Option<Self::Status> {
        &self.status
    }
}
