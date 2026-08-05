use crate::util::{GetStatus, IsReady};
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

fn default_true() -> bool {
    true
}

#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
// Cluster-scoped: a Zitadel instance has one set of email providers, so binding the
// CR to a namespace would misrepresent what it controls.
#[kube(kind = "EmailProviderSmtp", group = "zitadel.org", version = "v1alpha")]
#[kube(status = "EmailProviderSmtpStatus")]
#[kube(shortname = "smtp")]
#[serde(rename_all = "camelCase")]
pub struct EmailProviderSmtpSpec {
    /// Human-readable description shown in the Zitadel console
    #[schemars(length(min = 1, max = 200))]
    pub description: String,
    /// SMTP endpoint as `host:port`
    pub host: String,
    /// SMTP username
    pub user: String,
    /// Reference to a K8s Secret containing the SMTP password
    #[serde(default)]
    pub password_secret_ref: Option<NamespacedSecretKeySelector>,
    /// Use STARTTLS when talking to the SMTP host
    pub tls: bool,
    /// Address used in the `From` header
    pub sender_address: String,
    /// Display name used in the `From` header
    pub sender_name: String,
    /// Address used in the `Reply-To` header
    #[serde(default)]
    pub reply_to_address: Option<String>,
    /// Make this the active email provider of the Zitadel instance
    #[serde(default = "default_true")]
    pub set_active: bool,
    /// What happens to the Zitadel provider when this resource is deleted
    #[serde(default)]
    pub deletion_policy: DeletionPolicy,
}

/// Secret reference for a cluster-scoped resource, which has no namespace of its own
/// to fall back on.
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct NamespacedSecretKeySelector {
    /// Name of the Secret
    pub name: String,
    /// Namespace holding the Secret
    pub namespace: String,
    /// Key within the Secret (defaults to the EmailProviderSmtp's metadata.name)
    #[serde(default)]
    pub key: Option<String>,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq)]
pub enum DeletionPolicy {
    /// Leave the Zitadel email provider in place. The default, because this resource
    /// routinely adopts configuration it did not create.
    Retain,
    /// Remove the Zitadel email provider along with the resource.
    Delete,
}

impl Default for DeletionPolicy {
    fn default() -> Self {
        Self::Retain
    }
}

#[derive(Deserialize, Serialize, Clone, Default, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct EmailProviderSmtpStatus {
    pub provider_id: String,
    /// SHA-256 of the password last pushed to Zitadel, which never reads it back.
    /// Absent means this operator has not applied a password yet.
    #[serde(default)]
    pub password_hash: Option<String>,
    pub phase: EmailProviderSmtpPhase,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema, PartialEq)]
pub enum EmailProviderSmtpPhase {
    Ready,
}

impl Default for EmailProviderSmtpPhase {
    fn default() -> Self {
        Self::Ready
    }
}

impl IsReady for EmailProviderSmtp {
    fn is_ready(&self) -> bool {
        if let Some(status) = &self.status {
            status.phase == EmailProviderSmtpPhase::Ready
        } else {
            false
        }
    }
}

impl GetStatus for EmailProviderSmtp {
    type Status = EmailProviderSmtpStatus;
    fn get_status(&self) -> &Option<Self::Status> {
        &self.status
    }
}
