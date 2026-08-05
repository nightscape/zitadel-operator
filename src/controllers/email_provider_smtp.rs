use crate::{
    schema::{
        DeletionPolicy, EmailProviderSmtp, EmailProviderSmtpPhase, EmailProviderSmtpSpec, EmailProviderSmtpStatus,
    },
    util::{patch_status, requeue_secs},
    Error, OperatorContext, Result,
};
use futures::StreamExt;
use k8s_openapi::api::core::v1::Secret;
use kube::{
    runtime::{
        controller::Action,
        events::{Event, EventType},
        finalizer::{finalizer, Event as Finalizer},
        watcher::Config,
        Controller,
    },
    Api, Client, Resource, ResourceExt,
};
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};
use tonic::Code;
use tracing::{debug, info, instrument, warn};
use zitadel::api::zitadel::{
    admin::v1::{
        ActivateEmailProviderRequest, AddEmailProviderSmtpRequest, DeactivateEmailProviderRequest,
        GetEmailProviderByIdRequest, ListEmailProvidersRequest, RemoveEmailProviderRequest,
        UpdateEmailProviderSmtpPasswordRequest, UpdateEmailProviderSmtpRequest,
    },
    settings::v1::{email_provider::Config as ProviderConfig, EmailProvider, EmailProviderState},
};

pub static EMAIL_PROVIDER_SMTP_FINALIZER: &str = "emailprovidersmtp.zitadel.org";

/// How the provider Zitadel currently holds was located.
enum Current {
    /// Found under the ID recorded in status.
    Known(EmailProvider),
    /// Found by matching host+user; not yet recorded in status.
    Adoptable(EmailProvider),
    Absent,
}

fn smtp_config(provider: &EmailProvider) -> Option<&zitadel::api::zitadel::settings::v1::EmailProviderSmtp> {
    match &provider.config {
        Some(ProviderConfig::Smtp(smtp)) => Some(smtp),
        _ => None,
    }
}

/// Identity of an SMTP provider for adoption purposes. Zitadel allows several
/// providers to coexist, so host+user is what ties a CR to a pre-existing one.
fn is_adoption_candidate(provider: &EmailProvider, spec: &EmailProviderSmtpSpec) -> bool {
    smtp_config(provider).is_some_and(|smtp| smtp.host == spec.host && smtp.user == spec.user)
}

/// Zitadel trims these fields on write, so comparing or sending untrimmed values
/// would make every reconcile see drift and update forever.
fn normalized(spec: &EmailProviderSmtpSpec) -> EmailProviderSmtpSpec {
    EmailProviderSmtpSpec {
        description: spec.description.trim().to_string(),
        host: spec.host.trim().to_string(),
        user: spec.user.clone(),
        password_secret_ref: spec.password_secret_ref.clone(),
        tls: spec.tls,
        sender_address: spec.sender_address.trim().to_string(),
        sender_name: spec.sender_name.trim().to_string(),
        reply_to_address: spec.reply_to_address.as_ref().map(|r| r.trim().to_string()),
        set_active: spec.set_active,
        deletion_policy: spec.deletion_policy.clone(),
    }
}

fn password_hash(password: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hex::encode(hasher.finalize())
}

/// Zitadel never returns the password, so status carries the hash of what was last
/// pushed. Without a secret reference the operator does not own the credential and
/// must never touch it.
fn needs_password_push(desired: Option<&String>, applied: Option<&String>) -> bool {
    match desired {
        None => false,
        Some(desired) => applied != Some(desired),
    }
}

/// Retain is the default because this resource routinely adopts a provider it did
/// not create, where deleting the CR must not take the instance's email with it.
fn removes_provider_on_delete(policy: &DeletionPolicy) -> bool {
    match policy {
        DeletionPolicy::Retain => false,
        DeletionPolicy::Delete => true,
    }
}

/// Zitadel never returns the password, so it is excluded from the drift check.
fn matches_spec(provider: &EmailProvider, spec: &EmailProviderSmtpSpec) -> bool {
    let Some(smtp) = smtp_config(provider) else {
        return false;
    };
    provider.description == spec.description
        && smtp.host == spec.host
        && smtp.user == spec.user
        && smtp.tls == spec.tls
        && smtp.sender_address == spec.sender_address
        && smtp.sender_name == spec.sender_name
        && smtp.reply_to_address == spec.reply_to_address.clone().unwrap_or_default()
}

/// The k8s Secret is the source of truth for the password. Missing secrets are an
/// error rather than an empty password, which Zitadel would happily store.
async fn read_password(k8s: &Client, provider: &EmailProviderSmtp) -> Result<String> {
    let Some(secret_ref) = &provider.spec.password_secret_ref else {
        return Ok(String::new());
    };

    let secrets = Api::<Secret>::namespaced(k8s.clone(), &secret_ref.namespace);
    let secret = secrets.get_opt(&secret_ref.name).await?.ok_or_else(|| {
        Error::Other(format!(
            "password secret '{}/{}' referenced by EmailProviderSmtp '{}' not found",
            secret_ref.namespace,
            secret_ref.name,
            provider.name_any()
        ))
    })?;
    let key = secret_ref.key.clone().unwrap_or_else(|| provider.name_any());
    let value = secret.data.and_then(|d| d.get(&key).cloned()).ok_or_else(|| {
        Error::Other(format!(
            "password secret '{}/{}' has no key '{}'",
            secret_ref.namespace, secret_ref.name, key
        ))
    })?;

    String::from_utf8(value.0).map_err(|e| {
        Error::Other(format!(
            "password in secret '{}/{}' key '{}' is not valid UTF-8: {}",
            secret_ref.namespace, secret_ref.name, key, e
        ))
    })
}

/// The credential is owned exclusively by `add_request` (initial) and
/// `update_email_provider_smtp_password` (rotation). This builder deliberately takes
/// no password argument, so a config update cannot carry the resolved secret.
fn config_update_request(spec: &EmailProviderSmtpSpec, provider_id: &str) -> UpdateEmailProviderSmtpRequest {
    UpdateEmailProviderSmtpRequest {
        sender_address: spec.sender_address.clone(),
        sender_name: spec.sender_name.clone(),
        tls: spec.tls,
        host: spec.host.clone(),
        user: spec.user.clone(),
        reply_to_address: spec.reply_to_address.clone().unwrap_or_default(),
        password: String::new(),
        description: spec.description.clone(),
        id: provider_id.to_string(),
    }
}

/// Creation is the one path that must carry the password: there is no provider to
/// point the dedicated password RPC at yet.
fn add_request(spec: &EmailProviderSmtpSpec, password: String) -> AddEmailProviderSmtpRequest {
    AddEmailProviderSmtpRequest {
        sender_address: spec.sender_address.clone(),
        sender_name: spec.sender_name.clone(),
        tls: spec.tls,
        host: spec.host.clone(),
        user: spec.user.clone(),
        password,
        reply_to_address: spec.reply_to_address.clone().unwrap_or_default(),
        description: spec.description.clone(),
    }
}

async fn write_status(
    providers: &Api<EmailProviderSmtp>,
    provider: &EmailProviderSmtp,
    provider_id: &str,
    password_hash: Option<String>,
) -> Result<(), kube::Error> {
    patch_status(
        providers,
        provider,
        EmailProviderSmtpStatus {
            provider_id: provider_id.to_string(),
            password_hash,
            phase: EmailProviderSmtpPhase::Ready,
        },
    )
    .await
}

#[instrument(skip(ctx, provider))]
async fn reconcile(provider: Arc<EmailProviderSmtp>, ctx: Arc<OperatorContext>) -> Result<Action> {
    let providers = Api::<EmailProviderSmtp>::all(ctx.k8s.clone());
    let recorder = ctx.build_recorder();

    finalizer(&providers, EMAIL_PROVIDER_SMTP_FINALIZER, provider, |event| async {
        match event {
            Finalizer::Apply(provider) => {
                info!("reconciling email provider {}", provider.name_any());

                let mut admin = ctx.zitadel.builder().build_admin_client().await?;
                let normalized_spec = normalized(&provider.spec);
                let spec = &normalized_spec;

                // Read every reconcile: rotating the Secret is the only signal that
                // the password changed.
                let password = read_password(&ctx.k8s, &provider).await?;
                let desired_password_hash = spec.password_secret_ref.as_ref().map(|_| password_hash(&password));

                let by_id = if let Some(status) = &provider.status {
                    let resp = admin
                        .get_email_provider_by_id(GetEmailProviderByIdRequest {
                            id: status.provider_id.clone(),
                        })
                        .await;
                    match resp {
                        Ok(resp) => resp.into_inner().config,
                        Err(e) if e.code() == Code::NotFound => {
                            debug!("stored provider ID not found in Zitadel, falling back to host/user lookup");
                            None
                        }
                        Err(e) => return Err(Error::ZitadelError(e)),
                    }
                } else {
                    None
                };

                let current = match by_id {
                    Some(existing) => Current::Known(existing),
                    None => {
                        let all = admin
                            .list_email_providers(ListEmailProvidersRequest { query: None })
                            .await?
                            .into_inner()
                            .result;
                        let mut matching = all.into_iter().filter(|p| is_adoption_candidate(p, spec));
                        match (matching.next(), matching.next()) {
                            (Some(first), None) => Current::Adoptable(first),
                            (None, _) => Current::Absent,
                            (Some(_), Some(_)) => {
                                return Err(Error::Other(format!(
                                    "multiple Zitadel email providers match host '{}' and user '{}'",
                                    spec.host, spec.user
                                )))
                            }
                        }
                    }
                };

                // Both the adopted and the known provider may have drifted from the spec.
                let needs_update = match &current {
                    Current::Absent => false,
                    Current::Known(existing) | Current::Adoptable(existing) => !matches_spec(existing, spec),
                };

                // Newly added providers start out inactive.
                let (provider_id, state, applied_password_hash) = match current {
                    Current::Absent => {
                        debug!("email provider not found, creating");

                        let id = admin
                            .add_email_provider_smtp(add_request(spec, password.clone()))
                            .await?
                            .into_inner()
                            .id;

                        write_status(&providers, &provider, &id, desired_password_hash.clone()).await?;

                        recorder
                            .publish(
                                &Event {
                                    type_: EventType::Normal,
                                    reason: "Created".to_string(),
                                    note: Some("Email provider created".to_string()),
                                    action: "Creating".to_string(),
                                    secondary: None,
                                },
                                &provider.object_ref(&()),
                            )
                            .await?;

                        (
                            id,
                            EmailProviderState::Unspecified as i32,
                            desired_password_hash.clone(),
                        )
                    }
                    Current::Adoptable(existing) => {
                        debug!("email provider with host {} found, adopting", spec.host);

                        write_status(&providers, &provider, &existing.id, None).await?;

                        recorder
                            .publish(
                                &Event {
                                    type_: EventType::Normal,
                                    reason: "Adopted".to_string(),
                                    note: Some("Existing email provider adopted".to_string()),
                                    action: "Adopting".to_string(),
                                    secondary: None,
                                },
                                &provider.object_ref(&()),
                            )
                            .await?;

                        (existing.id.clone(), existing.state, None)
                    }
                    Current::Known(existing) => (
                        existing.id.clone(),
                        existing.state,
                        provider.status.as_ref().and_then(|s| s.password_hash.clone()),
                    ),
                };

                if needs_update {
                    debug!("email provider configuration changed, updating");

                    admin
                        .update_email_provider_smtp(config_update_request(spec, &provider_id))
                        .await?;

                    recorder
                        .publish(
                            &Event {
                                type_: EventType::Normal,
                                reason: "Updated".to_string(),
                                note: Some("Email provider configuration updated".to_string()),
                                action: "Updating".to_string(),
                                secondary: None,
                            },
                            &provider.object_ref(&()),
                        )
                        .await?;
                }

                if needs_password_push(desired_password_hash.as_ref(), applied_password_hash.as_ref()) {
                    debug!("smtp password changed, pushing to zitadel");

                    admin
                        .update_email_provider_smtp_password(UpdateEmailProviderSmtpPasswordRequest {
                            password: password.clone(),
                            id: provider_id.clone(),
                        })
                        .await?;

                    write_status(&providers, &provider, &provider_id, desired_password_hash.clone()).await?;

                    recorder
                        .publish(
                            &Event {
                                type_: EventType::Normal,
                                reason: "PasswordUpdated".to_string(),
                                note: Some("Email provider password updated".to_string()),
                                action: "UpdatingPassword".to_string(),
                                secondary: None,
                            },
                            &provider.object_ref(&()),
                        )
                        .await?;
                }

                let is_active = state == EmailProviderState::EmailProviderActive as i32;
                if spec.set_active && !is_active {
                    debug!("activating email provider");

                    admin
                        .activate_email_provider(ActivateEmailProviderRequest {
                            id: provider_id.clone(),
                        })
                        .await?;

                    recorder
                        .publish(
                            &Event {
                                type_: EventType::Normal,
                                reason: "Activated".to_string(),
                                note: Some("Email provider activated".to_string()),
                                action: "Activating".to_string(),
                                secondary: None,
                            },
                            &provider.object_ref(&()),
                        )
                        .await?;
                } else if !spec.set_active && is_active {
                    debug!("deactivating email provider");

                    admin
                        .deactivate_email_provider(DeactivateEmailProviderRequest {
                            id: provider_id.clone(),
                        })
                        .await?;

                    recorder
                        .publish(
                            &Event {
                                type_: EventType::Normal,
                                reason: "Deactivated".to_string(),
                                note: Some("Email provider deactivated".to_string()),
                                action: "Deactivating".to_string(),
                                secondary: None,
                            },
                            &provider.object_ref(&()),
                        )
                        .await?;
                }

                Ok(Action::requeue(Duration::from_secs(requeue_secs())))
            }
            Finalizer::Cleanup(provider) => {
                info!("cleaning up email provider {}", provider.name_any());

                if !removes_provider_on_delete(&provider.spec.deletion_policy) {
                    debug!("deletionPolicy is Retain, leaving the zitadel email provider in place");

                    recorder
                        .publish(
                            &Event {
                                type_: EventType::Normal,
                                reason: "Retained".to_string(),
                                note: Some(format!(
                                    "Email provider left in Zitadel because {} has deletionPolicy Retain",
                                    provider.name_any()
                                )),
                                action: "Retaining".to_string(),
                                secondary: None,
                            },
                            &provider.object_ref(&()),
                        )
                        .await?;

                    return Ok(Action::await_change());
                }

                if let Some(status) = &provider.status {
                    let mut admin = ctx.zitadel.builder().build_admin_client().await?;
                    let resp = admin
                        .remove_email_provider(RemoveEmailProviderRequest {
                            id: status.provider_id.clone(),
                        })
                        .await;

                    match resp {
                        Ok(_) => {
                            debug!("email provider removed");

                            recorder
                                .publish(
                                    &Event {
                                        type_: EventType::Normal,
                                        reason: "DeleteRequested".to_string(),
                                        note: Some(format!("Email provider {} was deleted", provider.name_any())),
                                        action: "Deleting".to_string(),
                                        secondary: None,
                                    },
                                    &provider.object_ref(&()),
                                )
                                .await?;
                        }
                        Err(e) if e.code() == Code::NotFound => {
                            debug!("email provider not found");
                        }
                        Err(e) => return Err(Error::ZitadelError(e)),
                    }
                } else {
                    debug!("email provider never appears to have been created");
                }

                Ok(Action::await_change())
            }
        }
    })
    .await
    .map_err(|e| Error::FinalizerError(Box::new(e)))
}

fn error_policy(_: Arc<EmailProviderSmtp>, error: &Error, _: Arc<OperatorContext>) -> Action {
    warn!("reconcile failed: {:?}", error);
    Action::requeue(Duration::from_secs(60))
}

pub async fn run(context: Arc<OperatorContext>) {
    let providers = Api::<EmailProviderSmtp>::all(context.k8s.clone());
    Controller::new(providers, Config::default().any_semantic())
        .shutdown_on_signal()
        .run(reconcile, error_policy, context)
        .filter_map(|x| async move { std::result::Result::ok(x) })
        .for_each(|_| futures::future::ready(()))
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use zitadel::api::zitadel::settings::v1::{EmailProviderHttp, EmailProviderSmtp as SmtpSettings};

    fn spec() -> EmailProviderSmtpSpec {
        EmailProviderSmtpSpec {
            description: "Mailjet".to_string(),
            host: "in-v3.mailjet.com:587".to_string(),
            user: "apikey".to_string(),
            password_secret_ref: None,
            tls: true,
            sender_address: "noreply@aiuno.app".to_string(),
            sender_name: "Aiuno".to_string(),
            reply_to_address: None,
            set_active: true,
            deletion_policy: DeletionPolicy::Retain,
        }
    }

    fn secret_ref() -> crate::schema::NamespacedSecretKeySelector {
        crate::schema::NamespacedSecretKeySelector {
            name: "smtp-password".to_string(),
            namespace: "zitadel".to_string(),
            key: None,
        }
    }

    fn provider_from(spec: &EmailProviderSmtpSpec) -> EmailProvider {
        EmailProvider {
            details: None,
            id: "380599158664331800".to_string(),
            state: EmailProviderState::EmailProviderActive as i32,
            description: spec.description.clone(),
            config: Some(ProviderConfig::Smtp(SmtpSettings {
                sender_address: spec.sender_address.clone(),
                sender_name: spec.sender_name.clone(),
                tls: spec.tls,
                host: spec.host.clone(),
                user: spec.user.clone(),
                reply_to_address: spec.reply_to_address.clone().unwrap_or_default(),
            })),
        }
    }

    #[test]
    fn identical_config_has_no_drift() {
        let spec = spec();
        assert!(matches_spec(&provider_from(&spec), &spec));
    }

    #[test]
    fn absent_reply_to_matches_empty_string_from_zitadel() {
        let mut spec = spec();
        spec.reply_to_address = None;
        let provider = provider_from(&spec);
        assert!(matches_spec(&provider, &spec));

        spec.reply_to_address = Some("support@aiuno.app".to_string());
        assert!(!matches_spec(&provider, &spec));
    }

    #[test]
    fn every_comparable_field_is_covered_by_the_drift_check() {
        let base = spec();
        let provider = provider_from(&base);

        // Exhaustive destructuring: adding a spec field stops this compiling, forcing
        // a decision about whether the drift check has to cover it.
        let EmailProviderSmtpSpec {
            description: _,
            host: _,
            user: _,
            tls: _,
            sender_address: _,
            sender_name: _,
            reply_to_address: _,
            // Not comparable: Zitadel never returns the password.
            password_secret_ref: _,
            // Not comparable: carried by EmailProvider.state, not the smtp config.
            set_active: _,
            // Not comparable: only consulted on delete.
            deletion_policy: _,
        } = spec();

        type Mutation = (&'static str, fn(&mut EmailProviderSmtpSpec));
        let mutations: Vec<Mutation> = vec![
            ("description", |s| s.description = "other".to_string()),
            ("host", |s| s.host = "smtp.example.com:25".to_string()),
            ("user", |s| s.user = "other".to_string()),
            ("tls", |s| s.tls = false),
            ("senderAddress", |s| s.sender_address = "x@y.z".to_string()),
            ("senderName", |s| s.sender_name = "Other".to_string()),
            ("replyToAddress", |s| s.reply_to_address = Some("r@y.z".to_string())),
        ];

        for (field, mutate) in mutations {
            let mut mutated = spec();
            mutate(&mut mutated);
            assert!(!matches_spec(&provider, &mutated), "drift in {field} was not detected");
        }
    }

    #[test]
    fn password_only_changes_are_invisible_to_the_drift_check() {
        // Zitadel never returns the password; a CR that only changes the secret
        // must not be reported as drifted, matching human_user's write-only handling.
        let mut spec = spec();
        let provider = provider_from(&spec);
        spec.password_secret_ref = Some(secret_ref());
        assert!(matches_spec(&provider, &spec));
    }

    #[test]
    fn adoption_matches_on_host_and_user_only() {
        let base = spec();
        let mut existing = provider_from(&base);
        // A provider configured out-of-band differs in everything but host+user.
        if let Some(ProviderConfig::Smtp(smtp)) = &mut existing.config {
            smtp.sender_name = "Legacy".to_string();
            smtp.tls = false;
        }
        existing.description = "managed by tofu".to_string();

        assert!(is_adoption_candidate(&existing, &base));
        assert!(!matches_spec(&existing, &base));
    }

    #[test]
    fn adoption_rejects_other_hosts_users_and_http_providers() {
        let base = spec();

        let mut other_host = spec();
        other_host.host = "smtp.example.com:587".to_string();
        assert!(!is_adoption_candidate(&provider_from(&base), &other_host));

        let mut other_user = spec();
        other_user.user = "someone-else".to_string();
        assert!(!is_adoption_candidate(&provider_from(&base), &other_user));

        let http = EmailProvider {
            details: None,
            id: "1".to_string(),
            state: EmailProviderState::EmailProviderActive as i32,
            description: base.description.clone(),
            config: Some(ProviderConfig::Http(EmailProviderHttp {
                endpoint: "https://example.com/hook".to_string(),
            })),
        };
        assert!(!is_adoption_candidate(&http, &base));
        assert!(!matches_spec(&http, &base));
    }

    #[test]
    fn whitespace_in_spec_does_not_cause_an_endless_update_loop() {
        // Zitadel trims these fields on write, so an untrimmed spec must still compare
        // equal to the provider it produced.
        let clean = spec();
        let provider = provider_from(&clean);

        let mut padded = spec();
        padded.description = "  Mailjet  ".to_string();
        padded.host = " in-v3.mailjet.com:587\t".to_string();
        padded.sender_address = " noreply@aiuno.app ".to_string();
        padded.sender_name = "  Aiuno ".to_string();
        padded.reply_to_address = Some("  ".to_string());

        assert!(
            !matches_spec(&provider, &padded),
            "untrimmed spec should not match as-is"
        );
        assert!(
            matches_spec(&provider, &normalized(&padded)),
            "normalized spec must match, otherwise reconcile updates forever"
        );
        assert!(is_adoption_candidate(&provider, &normalized(&padded)));
    }

    #[test]
    fn normalizing_leaves_already_clean_values_untouched() {
        let clean = spec();
        assert!(matches_spec(&provider_from(&clean), &normalized(&clean)));
    }

    #[test]
    fn password_push_is_skipped_without_a_secret_ref() {
        // No secretRef means the operator does not own the credential.
        assert!(!needs_password_push(None, None));
        assert!(!needs_password_push(None, Some(&password_hash("anything"))));
    }

    #[test]
    fn rotating_the_secret_triggers_a_password_push() {
        let old = password_hash("old-secret");
        let new = password_hash("new-secret");
        assert_ne!(old, new);

        // Steady state: hash recorded in status matches the secret.
        assert!(!needs_password_push(Some(&old), Some(&old)));
        // Secret rotated behind the operator's back.
        assert!(needs_password_push(Some(&new), Some(&old)));
    }

    #[test]
    fn adopting_a_provider_pushes_an_owned_password_once() {
        // Adoption records the id with no hash, so a spec that carries a secretRef
        // takes ownership of the credential on the next step, then goes quiet.
        let desired = password_hash("from-k8s-secret");
        assert!(needs_password_push(Some(&desired), None));
        assert!(!needs_password_push(Some(&desired), Some(&desired)));
    }

    #[test]
    fn password_hash_does_not_leak_the_password() {
        let secret = "hunter2";
        let hash = password_hash(secret);
        assert!(!hash.contains(secret));
        assert_eq!(hash.len(), 64);
        assert_eq!(hash, password_hash(secret), "hash must be stable across reconciles");
    }

    #[test]
    fn config_update_never_carries_the_password() {
        // The credential must not ride along on a config update: Zitadel treating an
        // empty password as leave-alone is an upstream compat branch, not our contract.
        let mut with_ref = spec();
        with_ref.password_secret_ref = Some(secret_ref());

        for spec in [spec(), with_ref] {
            let req = config_update_request(&spec, "380599158664331800");
            assert!(req.password.is_empty(), "config update must not carry a password");
            assert_eq!(req.id, "380599158664331800");
            assert_eq!(req.host, spec.host);
            assert_eq!(req.description, spec.description);
        }
    }

    #[test]
    fn creation_is_the_only_config_write_that_carries_the_password() {
        let spec = spec();
        let req = add_request(&spec, "s3cret".to_string());
        assert_eq!(req.password, "s3cret");
        assert_eq!(req.host, spec.host);
    }

    #[test]
    fn config_update_sends_trimmed_values() {
        let mut padded = spec();
        padded.description = "  Mailjet  ".to_string();
        padded.host = " in-v3.mailjet.com:587 ".to_string();

        let req = config_update_request(&normalized(&padded), "1");
        assert_eq!(req.description, "Mailjet");
        assert_eq!(req.host, "in-v3.mailjet.com:587");
    }

    #[test]
    fn retain_is_the_default_and_leaves_the_provider_alone() {
        // Adopted config (prod's hand-made provider) must survive CR deletion.
        assert_eq!(DeletionPolicy::default(), DeletionPolicy::Retain);
        assert!(!removes_provider_on_delete(&DeletionPolicy::default()));
        assert!(!removes_provider_on_delete(&spec().deletion_policy));
    }

    #[test]
    fn delete_policy_removes_the_provider() {
        assert!(removes_provider_on_delete(&DeletionPolicy::Delete));
    }

    #[test]
    fn deletion_policy_does_not_affect_config_drift() {
        let mut retained = spec();
        retained.deletion_policy = DeletionPolicy::Retain;
        let provider = provider_from(&retained);

        let mut deleted = spec();
        deleted.deletion_policy = DeletionPolicy::Delete;
        assert!(matches_spec(&provider, &deleted));
    }
}
