use crate::{
    schema::{
        IdentityProvider, IdentityProviderAzureAdSpec, IdentityProviderInnerSpec, IdentityProviderJwtSpec,
        IdentityProviderPhase, IdentityProviderStatus, Organization,
    },
    util::{
        create_request_with_org_id, patch_status, requeue_secs, CurrentState, CurrentStateParameters,
        CurrentStateRetriever, GetStatus,
    },
    Error, OperatorContext, Result,
};
use futures::StreamExt;
use k8s_openapi::api::core::v1::Secret;
use kube::{
    runtime::{
        controller::Action,
        events::{Event, EventType, Recorder},
        finalizer::{finalizer, Event as Finalizer},
        metadata_watcher,
        reflector::{Lookup, ObjectRef},
        watcher::Config,
        Controller, WatchStreamExt,
    },
    Api, Client, Resource, ResourceExt,
};
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};
use tonic::{service::interceptor::InterceptedService, Code};
use tracing::{debug, info, instrument, warn};
use zitadel::api::zitadel::{
    admin::v1::GetLoginPolicyRequest,
    idp::v1::{
        azure_ad_tenant, idp::Config as IdpConfig, provider_config::Config as ProviderConfig, AutoLinkingOption,
        AzureAdTenant, Idp, IdpFieldName, IdpNameQuery, IdpOwnerType, IdpOwnerTypeQuery, IdpStylingType, Options,
        Provider, ProviderType,
    },
    management::v1::{
        add_custom_login_policy_request, idp_query, management_service_client::ManagementServiceClient, provider_query,
        AddAzureAdProviderRequest, AddCustomLoginPolicyRequest, AddIdpToLoginPolicyRequest, AddOrgJwtidpRequest,
        DeleteProviderRequest, GetOrgIdpByIdRequest, GetProviderByIdRequest, IdpQuery, ListLoginPolicyIdPsRequest,
        ListOrgIdPsRequest, ListProvidersRequest, ProviderQuery, RemoveIdpFromLoginPolicyRequest, RemoveOrgIdpRequest,
        UpdateAzureAdProviderRequest, UpdateOrgIdpRequest, UpdateOrgIdpjwtConfigRequest,
    },
    v1::TextQueryMethod,
};

use crate::CustomHeaderInterceptor;

pub static IDENTITY_PROVIDER_FINALIZER: &str = "identityprovider.zitadel.org";

fn jwt_spec(idp: &IdentityProvider) -> &IdentityProviderJwtSpec {
    match &idp.spec.inner {
        IdentityProviderInnerSpec::Jwt(jwt) => jwt,
        other => panic!("jwt reconcile reached with a {other:?} spec"),
    }
}

fn azure_ad_spec(idp: &IdentityProvider) -> &IdentityProviderAzureAdSpec {
    match &idp.spec.inner {
        IdentityProviderInnerSpec::AzureAd(azure) => azure,
        other => panic!("azure ad reconcile reached with a {other:?} spec"),
    }
}

fn matches_spec(object: &Idp, idp: &IdentityProvider) -> bool {
    let jwt = jwt_spec(idp);
    let Some(IdpConfig::JwtConfig(config)) = &object.config else {
        return false;
    };
    object.name == idp.spec.name
        && object.auto_register == idp.spec.auto_register
        && config.issuer == jwt.issuer
        && config.jwt_endpoint == jwt.jwt_endpoint.as_str()
        && config.keys_endpoint == jwt.keys_endpoint.as_str()
        && config.header_name == jwt.header_name
}

/// Only a directory ID identifies one tenant. Zitadel puts the string straight
/// into `https://login.microsoftonline.com/{}/v2.0`, so `common`,
/// `organizations` and `consumers` reach Microsoft's multi-tenant endpoints and
/// admit every Microsoft account. Zitadel also reads those three back as a
/// tenant *type* rather than a tenant id, which no spec of ours can equal, so
/// one would additionally make every reconcile see drift and rewrite the
/// provider forever.
fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

/// Lower case only: nothing has shown that Zitadel stores the string
/// case-preserving, and an upper-case one it folded would read back different
/// from the spec and make every reconcile see drift.
fn is_directory_id(tenant_id: &str) -> bool {
    let groups = [8, 4, 4, 4, 12];
    let mut parts = tenant_id.split('-');
    groups.iter().all(|len| {
        parts
            .next()
            .is_some_and(|part| part.len() == *len && part.bytes().all(is_lower_hex))
    }) && parts.next().is_none()
}

/// A pinned tenant, never `common` or `organisations`: those admit every
/// Microsoft account rather than the customer's directory.
fn pinned_tenant(tenant_id: &str) -> AzureAdTenant {
    assert!(is_directory_id(tenant_id), "{tenant_id} is not a directory ID");
    AzureAdTenant {
        r#type: Some(azure_ad_tenant::Type::TenantId(tenant_id.to_string())),
    }
}

/// Zitadel's console defaults for an Azure AD provider, with `autoRegister`
/// carried over from the spec the same way the jwt variant does it.
fn provider_options(auto_register: bool) -> Options {
    Options {
        is_linking_allowed: true,
        is_creation_allowed: true,
        is_auto_creation: auto_register,
        is_auto_update: true,
        auto_linking: AutoLinkingOption::Unspecified.into(),
    }
}

fn client_secret_hash(secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    hex::encode(hasher.finalize())
}

/// Zitadel never returns the client secret, so the drift check covers everything
/// but it; rotation is detected against the hash recorded in status.
fn azure_ad_matches_spec(object: &Provider, idp: &IdentityProvider) -> bool {
    let azure = azure_ad_spec(idp);
    let Some(config) = &object.config else {
        return false;
    };
    let Some(ProviderConfig::AzureAd(azure_config)) = &config.config else {
        return false;
    };
    object.name == idp.spec.name
        && config.options == Some(provider_options(idp.spec.auto_register))
        && azure_config.client_id == azure.client_id
        && azure_config.tenant == Some(pinned_tenant(&azure.tenant_id))
        && azure_config.email_verified == azure.email_verified
        && azure_config.scopes.is_empty()
}

/// Adoption keys on the display name alone, so a provider of another kind can
/// answer to it. Taking that one over would replace an identity source the
/// organization's users are already linked to.
fn is_azure_ad_provider(object: &Provider) -> bool {
    object.r#type == i32::from(ProviderType::AzureAd)
}

/// Guards both adoption by name and a `status.id` lookup. Neither is known to be
/// reachable — the legacy API answers `NotFound` for the provider templates the
/// azureAd variant creates, and never lists one — but adopting or deleting a
/// foreign provider is not a mistake worth leaving to that.
fn is_jwt_provider(object: &Idp) -> bool {
    matches!(object.config, Some(IdpConfig::JwtConfig(_)))
}

/// Zitadel reports a provider that is gone two ways, because deleting the
/// organization takes its providers with it.
fn is_already_gone(e: &tonic::Status) -> bool {
    e.code() == Code::NotFound
        || (e.code() == Code::PermissionDenied && e.message() == "Organisation doesn't exist (AUTH-Bs7Ds)")
}

/// `status.id` is an id in one Zitadel API only, and only this operator ever writes
/// it. A provider of the other kind behind it therefore means the spec variant was
/// flipped past the CRD's immutability rule, and any call this operator would make
/// next addresses the wrong provider. Refuse without mutating anything.
async fn refuse_type_mismatch<T>(
    recorder: &Recorder,
    idp: &IdentityProvider,
    declared: &str,
    id: &str,
    action: &str,
) -> Result<T> {
    let note = format!(
        "IdentityProvider {} declares {declared} provider, but the provider stored under \
         status.id '{id}' is of another type; the provider type cannot change, so delete and \
         recreate the resource",
        idp.name_any()
    );
    warn!("{note}");
    recorder
        .publish(
            &Event {
                type_: EventType::Warning,
                reason: "TypeMismatch".to_string(),
                note: Some(note.clone()),
                action: action.to_string(),
                secondary: None,
            },
            &idp.object_ref(&()),
        )
        .await?;
    Err(Error::Other(note))
}

/// Zitadel never reads a client secret back, so the hash of the last one pushed
/// is the only way to tell a rotated Secret from a steady state. An absent hash
/// means this operator has pushed nothing yet, which is where adoption leaves a
/// provider whose credential it does not know.
fn needs_client_secret_push(applied: Option<&str>, desired: &str) -> bool {
    applied != Some(desired)
}

/// The status of a provider whose credential this operator has just pushed.
fn pushed_status(id: String, organization_id: String, client_secret_hash: String) -> IdentityProviderStatus {
    IdentityProviderStatus {
        id,
        organization_id,
        client_secret_hash: Some(client_secret_hash),
        phase: IdentityProviderPhase::Ready,
    }
}

/// The status of a provider this operator adopted. The hash stays absent on
/// purpose: the adopted provider holds a client secret the operator never
/// pushed, so the next reconcile has to replace it with the Secret's.
fn adopted_status(id: String, organization_id: String) -> IdentityProviderStatus {
    IdentityProviderStatus {
        id,
        organization_id,
        client_secret_hash: None,
        phase: IdentityProviderPhase::Ready,
    }
}

/// The k8s Secret is the source of truth for the client secret. A missing secret
/// is an error rather than an empty string, which Zitadel would happily store.
async fn read_client_secret(k8s: &Client, idp: &IdentityProvider) -> Result<String> {
    let secret_ref = &azure_ad_spec(idp).client_secret_ref;
    let ns = idp.metadata.namespace.as_ref().unwrap();
    let secrets = Api::<Secret>::namespaced(k8s.clone(), ns);
    let secret = secrets.get_opt(&secret_ref.name).await?.ok_or_else(|| {
        Error::Other(format!(
            "client secret '{}/{}' referenced by IdentityProvider '{}' not found",
            ns,
            secret_ref.name,
            idp.name_any()
        ))
    })?;
    let value = secret
        .data
        .and_then(|data| data.get(&secret_ref.key).cloned())
        .ok_or_else(|| {
            Error::Other(format!(
                "client secret '{}/{}' has no key '{}'",
                ns, secret_ref.name, secret_ref.key
            ))
        })?;

    String::from_utf8(value.0).map_err(|e| {
        Error::Other(format!(
            "client secret in '{}/{}' key '{}' is not valid UTF-8: {e}",
            ns, secret_ref.name, secret_ref.key
        ))
    })
}

type Management =
    ManagementServiceClient<InterceptedService<tonic::transport::Channel, CustomHeaderInterceptor>>;

/// Give the organization a login policy of its own, copied from the instance
/// default.
///
/// A provider can only be attached to a policy the organization owns. The copy
/// leaves the organization's login behaviour unchanged at this moment, but the
/// organization stops following later edits to the instance default.
async fn copy_instance_login_policy(
    ctx: &OperatorContext,
    management: &mut Management,
    org_id: &str,
) -> Result<()> {
    let mut admin = ctx.zitadel.builder().build_admin_client().await?;
    let default = admin
        .get_login_policy(GetLoginPolicyRequest {})
        .await?
        .into_inner()
        .policy
        .ok_or_else(|| Error::Other("the instance has no default login policy".to_string()))?;

    let created = management
        .add_custom_login_policy(create_request_with_org_id(
            AddCustomLoginPolicyRequest {
                allow_username_password: default.allow_username_password,
                allow_register: default.allow_register,
                allow_external_idp: default.allow_external_idp,
                force_mfa: default.force_mfa,
                force_mfa_local_only: default.force_mfa_local_only,
                passwordless_type: default.passwordless_type,
                hide_password_reset: default.hide_password_reset,
                ignore_unknown_usernames: default.ignore_unknown_usernames,
                allow_domain_discovery: default.allow_domain_discovery,
                disable_login_with_email: default.disable_login_with_email,
                disable_login_with_phone: default.disable_login_with_phone,
                default_redirect_uri: default.default_redirect_uri,
                password_check_lifetime: default.password_check_lifetime,
                external_login_check_lifetime: default.external_login_check_lifetime,
                mfa_init_skip_lifetime: default.mfa_init_skip_lifetime,
                second_factor_check_lifetime: default.second_factor_check_lifetime,
                multi_factor_check_lifetime: default.multi_factor_check_lifetime,
                second_factors: default.second_factors,
                multi_factors: default.multi_factors,
                // Every provider the default policy offers is instance-owned,
                // and the organization would lose it by owning a policy.
                idps: default
                    .idps
                    .into_iter()
                    .map(|link| add_custom_login_policy_request::Idp {
                        idp_id: link.idp_id,
                        owner_type: IdpOwnerType::System.into(),
                    })
                    .collect(),
            },
            org_id.to_string(),
        ))
        .await;

    match created {
        // Reached when a concurrent reconcile for another provider of the same
        // organization created the policy first.
        Err(e) if e.code() == Code::AlreadyExists => Ok(()),
        other => other.map(|_| ()).map_err(Error::from),
    }
}

async fn add_to_login_policy(
    management: &mut Management,
    idp_id: &str,
    org_id: &str,
) -> std::result::Result<(), tonic::Status> {
    management
        .add_idp_to_login_policy(create_request_with_org_id(
            AddIdpToLoginPolicyRequest {
                idp_id: idp_id.to_string(),
                owner_type: IdpOwnerType::Org.into(),
            },
            org_id.to_string(),
        ))
        .await
        .map(|_| ())
}

/// Membership of the organization's login policy, which is what actually makes
/// a provider appear on the login screen.
async fn reconcile_login_screen(
    ctx: &OperatorContext,
    management: &mut Management,
    recorder: &Recorder,
    idp: &IdentityProvider,
    idp_id: &str,
    org_id: &str,
) -> Result<()> {
    let listed = management
        .list_login_policy_id_ps(create_request_with_org_id(
            ListLoginPolicyIdPsRequest { query: None },
            org_id.to_string(),
        ))
        .await?
        .into_inner()
        .result;
    let on_screen = listed.iter().any(|link| link.idp_id == idp_id);

    if on_screen == idp.spec.show_on_login_screen {
        return Ok(());
    }

    let resp = if idp.spec.show_on_login_screen {
        add_to_login_policy(management, idp_id, org_id).await
    } else {
        management
            .remove_idp_from_login_policy(create_request_with_org_id(
                RemoveIdpFromLoginPolicyRequest {
                    idp_id: idp_id.to_string(),
                },
                org_id.to_string(),
            ))
            .await
            .map(|_| ())
    };

    // Org-Ffgw2 is Zitadel's "this organization has no login policy of its own",
    // the state every organization starts in.
    let inherits =
        |e: &tonic::Status| e.code() == Code::NotFound && e.message().contains("Org-Ffgw2");

    let resp = match resp {
        // Reached when the organization's policy is removed between the listing
        // above and this call. Nothing to withdraw from: an organization without
        // a policy of its own offers no provider, which is the asked-for state.
        Err(e) if !idp.spec.show_on_login_screen && inherits(&e) => {
            debug!(
                "organization {} has no login policy of its own, so the provider was not offered \
                 anyway",
                idp.spec.organization_name
            );
            return Ok(());
        }
        // The organization keeps the policy once it has one: withdrawing the
        // provider later must not send it back to inheriting, which would
        // change how it logs users in.
        Err(e) if idp.spec.show_on_login_screen && inherits(&e) => {
            if let Err(e) = copy_instance_login_policy(ctx, management, org_id).await {
                let note = format!(
                    "Organization {} inherits the instance default login policy, and giving it a \
                     custom copy of that policy failed, so the provider cannot be offered on its \
                     login screen: {e}",
                    idp.spec.organization_name
                );
                warn!("{note}");
                recorder
                    .publish(
                        &Event {
                            type_: EventType::Warning,
                            reason: "NoCustomLoginPolicy".to_string(),
                            note: Some(note.clone()),
                            action: "NotOffered".to_string(),
                            secondary: None,
                        },
                        &idp.object_ref(&()),
                    )
                    .await?;
                return Err(Error::Other(note));
            }

            info!(
                "organization {} had no login policy of its own; created one copied from the \
                 instance default",
                idp.spec.organization_name
            );

            add_to_login_policy(management, idp_id, org_id).await
        }
        other => other,
    };

    match resp {
        Ok(()) => {
            let (reason, note) = if idp.spec.show_on_login_screen {
                ("OfferedOnLoginScreen", "Provider added to the login policy")
            } else {
                ("WithdrawnFromLoginScreen", "Provider removed from the login policy")
            };
            debug!("{note}");
            recorder
                .publish(
                    &Event {
                        type_: EventType::Normal,
                        reason: reason.to_string(),
                        note: Some(note.to_string()),
                        action: "Updating".to_string(),
                        secondary: None,
                    },
                    &idp.object_ref(&()),
                )
                .await?;
            Ok(())
        }
        Err(e) => Err(Error::ZitadelError(e)),
    }
}

struct IdentityProviderStateRetriever {
    pub management: ManagementServiceClient<InterceptedService<tonic::transport::Channel, CustomHeaderInterceptor>>,
}
impl CurrentStateRetriever<IdentityProvider, Idp, Organization> for IdentityProviderStateRetriever {
    async fn get_object(&mut self, status: &<IdentityProvider as GetStatus>::Status) -> Result<Option<Idp>> {
        Ok(self
            .management
            .get_org_idp_by_id(create_request_with_org_id(
                GetOrgIdpByIdRequest { id: status.id.clone() },
                status.organization_id.clone(),
            ))
            .await?
            .into_inner()
            .idp)
    }

    async fn list_objects(
        &mut self,
        idp: &IdentityProvider,
        org: &<Organization as GetStatus>::Status,
    ) -> Result<Vec<Idp>> {
        let matching = self
            .management
            .list_org_id_ps(create_request_with_org_id(
                ListOrgIdPsRequest {
                    query: None,
                    sorting_column: IdpFieldName::Unspecified.into(),
                    queries: vec![IdpQuery {
                        query: Some(idp_query::Query::IdpNameQuery(IdpNameQuery {
                            name: idp.spec.name.clone(),
                            method: TextQueryMethod::Equals.into(),
                        })),
                    }],
                },
                org.id.clone(),
            ))
            .await?
            .into_inner()
            .result;
        Ok(matching)
    }
}

/// The provider's own id and org, once it is known to exist.
async fn reconcile_jwt(
    management: &mut Management,
    recorder: &Recorder,
    idps: &Api<IdentityProvider>,
    orgs: &Api<Organization>,
    idp: &Arc<IdentityProvider>,
) -> Result<Option<(String, String)>> {
    let jwt = jwt_spec(idp);

    let state = CurrentState::<Organization, Idp>::determine(CurrentStateParameters {
        resource: idp.clone(),
        resource_api: idps.clone(),
        parent_api: orgs.clone(),
        parent_name: idp.spec.organization_name.clone(),
        retriever: IdentityProviderStateRetriever {
            management: management.clone(),
        },
        is_equal: matches_spec,
    })
    .await?;

    if let CurrentState::ExistsEqual(object, _) | CurrentState::ExistsUnequal(object, _) = &state {
        if !is_jwt_provider(object) {
            return refuse_type_mismatch(recorder, idp, "a jwt", &object.id, "NotUpdated").await;
        }
    }

    // The provider's own id and org, once it is known to exist.
    let ensured = match state {
        CurrentState::ExistsEqual(object, org) => Some((object.id, org.id)),
        CurrentState::ExistsUnequal(object, org) => {
            debug!("identity provider changed, updating");

            let org_id = org.id.clone();

            // Zitadel splits the provider across two calls: the envelope carries
            // name and auto-register, the config carries the endpoints.
            management
                .update_org_idp(create_request_with_org_id(
                    UpdateOrgIdpRequest {
                        idp_id: object.id.clone(),
                        name: idp.spec.name.clone(),
                        styling_type: object.styling_type,
                        auto_register: idp.spec.auto_register,
                    },
                    org.id.clone(),
                ))
                .await?;

            management
                .update_org_idpjwt_config(create_request_with_org_id(
                    UpdateOrgIdpjwtConfigRequest {
                        idp_id: object.id.clone(),
                        jwt_endpoint: jwt.jwt_endpoint.to_string(),
                        issuer: jwt.issuer.clone(),
                        keys_endpoint: jwt.keys_endpoint.to_string(),
                        header_name: jwt.header_name.clone(),
                    },
                    org.id,
                ))
                .await?;

            recorder
                .publish(
                    &Event {
                        type_: EventType::Normal,
                        reason: "SpecChanged".to_string(),
                        note: Some(format!("Identity provider {} updated", idp.spec.name)),
                        action: "Updating".into(),
                        secondary: None,
                    },
                    &idp.object_ref(&()),
                )
                .await?;

            Some((object.id, org_id))
        }
        CurrentState::NotExists(org) => {
            debug!("identity provider not found, (re)creating");

            let resp = management
                .add_org_jwtidp(create_request_with_org_id(
                    AddOrgJwtidpRequest {
                        name: idp.spec.name.clone(),
                        styling_type: IdpStylingType::StylingTypeUnspecified.into(),
                        jwt_endpoint: jwt.jwt_endpoint.to_string(),
                        issuer: jwt.issuer.clone(),
                        keys_endpoint: jwt.keys_endpoint.to_string(),
                        header_name: jwt.header_name.clone(),
                        auto_register: idp.spec.auto_register,
                    },
                    org.id.clone(),
                ))
                .await?
                .into_inner();

            let idp_id = resp.idp_id;
            let org_id = org.id;

            patch_status(
                idps,
                idp.as_ref(),
                IdentityProviderStatus {
                    id: idp_id.clone(),
                    organization_id: org_id.clone(),
                    client_secret_hash: None,
                    phase: IdentityProviderPhase::Ready,
                },
            )
            .await?;

            recorder
                .publish(
                    &Event {
                        type_: EventType::Normal,
                        reason: "Created".to_string(),
                        note: Some("Identity provider created".to_string()),
                        action: "Creating".to_string(),
                        secondary: None,
                    },
                    &idp.object_ref(&()),
                )
                .await?;

            Some((idp_id, org_id))
        }
        CurrentState::ParentNotFound => {
            info!("organization {} not found", idp.spec.organization_name);

            recorder
                .publish(
                    &Event {
                        type_: EventType::Normal,
                        reason: "Missing".to_string(),
                        note: Some("Organization does not exist".to_string()),
                        action: "NotCreated".to_string(),
                        secondary: None,
                    },
                    &idp.object_ref(&()),
                )
                .await?;

            None
        }
        CurrentState::ParentNotReady(_) => {
            info!("organization {} not ready", idp.spec.organization_name);

            recorder
                .publish(
                    &Event {
                        type_: EventType::Normal,
                        reason: "NotCreated".to_string(),
                        note: Some("Organization is not yet created".to_string()),
                        action: "NotCreated".to_string(),
                        secondary: None,
                    },
                    &idp.object_ref(&()),
                )
                .await?;

            None
        }
        CurrentState::FoundAdoptable(object, org) => {
            if !is_jwt_provider(&object) {
                let note = format!(
                    "Organization {} already has a provider named '{}' that is not a jwt \
                     provider, so this resource cannot manage it",
                    idp.spec.organization_name, idp.spec.name
                );
                warn!("{note}");
                recorder
                    .publish(
                        &Event {
                            type_: EventType::Warning,
                            reason: "NameTaken".to_string(),
                            note: Some(note.clone()),
                            action: "NotAdopted".to_string(),
                            secondary: None,
                        },
                        &idp.object_ref(&()),
                    )
                    .await?;
                return Err(Error::Other(note));
            }

            debug!("identity provider found, attaching id to resource");

            let org_id = org.id;

            patch_status(
                idps,
                idp.as_ref(),
                IdentityProviderStatus {
                    id: object.id.clone(),
                    organization_id: org_id.clone(),
                    client_secret_hash: None,
                    phase: IdentityProviderPhase::Ready,
                },
            )
            .await?;

            recorder
                .publish(
                    &Event {
                        type_: EventType::Normal,
                        reason: "Creating".to_string(),
                        note: Some("Existing identity provider adopted".to_string()),
                        action: "Adopted".to_string(),
                        secondary: None,
                    },
                    &idp.object_ref(&()),
                )
                .await?;

            Some((object.id, org_id))
        }
    };

    Ok(ensured)
}

/// Azure AD lives only in the provider-template API: the legacy `Idp` message
/// the jwt variant uses carries no Azure AD configuration at all.
struct AzureAdProviderStateRetriever {
    pub management: Management,
}
impl CurrentStateRetriever<IdentityProvider, Provider, Organization> for AzureAdProviderStateRetriever {
    async fn get_object(&mut self, status: &<IdentityProvider as GetStatus>::Status) -> Result<Option<Provider>> {
        Ok(self
            .management
            .get_provider_by_id(create_request_with_org_id(
                GetProviderByIdRequest { id: status.id.clone() },
                status.organization_id.clone(),
            ))
            .await?
            .into_inner()
            .idp)
    }

    async fn list_objects(
        &mut self,
        idp: &IdentityProvider,
        org: &<Organization as GetStatus>::Status,
    ) -> Result<Vec<Provider>> {
        Ok(self
            .management
            .list_providers(create_request_with_org_id(
                ListProvidersRequest {
                    query: None,
                    queries: vec![
                        ProviderQuery {
                            query: Some(provider_query::Query::IdpNameQuery(IdpNameQuery {
                                name: idp.spec.name.clone(),
                                method: TextQueryMethod::Equals.into(),
                            })),
                        },
                        // An org-scoped listing still reports the instance's own
                        // providers, which are not this operator's to adopt.
                        ProviderQuery {
                            query: Some(provider_query::Query::OwnerTypeQuery(IdpOwnerTypeQuery {
                                owner_type: IdpOwnerType::Org.into(),
                            })),
                        },
                    ],
                },
                org.id.clone(),
            ))
            .await?
            .into_inner()
            .result)
    }
}

/// The provider's own id and org, once it is known to exist.
async fn reconcile_azure_ad(
    ctx: &OperatorContext,
    management: &mut Management,
    recorder: &Recorder,
    idps: &Api<IdentityProvider>,
    orgs: &Api<Organization>,
    idp: &Arc<IdentityProvider>,
) -> Result<Option<(String, String)>> {
    let azure = azure_ad_spec(idp);

    // The CRD rejects anything else, so this only catches a resource that got in
    // around it. Creating the provider anyway would federate the whole of
    // Microsoft instead of the customer's directory.
    if !is_directory_id(&azure.tenant_id) {
        let note = format!(
            "tenantId '{}' is not a lower-case Entra directory ID, and the multi-tenant endpoints \
             it would select admit every Microsoft account",
            azure.tenant_id
        );
        warn!("{note}");
        recorder
            .publish(
                &Event {
                    type_: EventType::Warning,
                    reason: "TenantNotPinned".to_string(),
                    note: Some(note.clone()),
                    action: "NotCreated".to_string(),
                    secondary: None,
                },
                &idp.object_ref(&()),
            )
            .await?;
        return Err(Error::Other(note));
    }

    // Read every reconcile: rotating the Secret is the only signal that the
    // client secret changed, because Zitadel never reads one back.
    let secret = read_client_secret(&ctx.k8s, idp).await?;
    let desired_hash = client_secret_hash(&secret);
    let rotated = needs_client_secret_push(
        idp.status
            .as_ref()
            .and_then(|status| status.client_secret_hash.as_deref()),
        &desired_hash,
    );

    let state = CurrentState::<Organization, Provider>::determine(CurrentStateParameters {
        resource: idp.clone(),
        resource_api: idps.clone(),
        parent_api: orgs.clone(),
        parent_name: idp.spec.organization_name.clone(),
        retriever: AzureAdProviderStateRetriever {
            management: management.clone(),
        },
        is_equal: azure_ad_matches_spec,
    })
    .await?;

    if let CurrentState::ExistsEqual(object, _) | CurrentState::ExistsUnequal(object, _) = &state {
        if !is_azure_ad_provider(object) {
            return refuse_type_mismatch(recorder, idp, "an azureAd", &object.id, "NotUpdated").await;
        }
    }

    let ensured = match state {
        CurrentState::ExistsEqual(object, org) if !rotated => Some((object.id, org.id)),
        CurrentState::ExistsEqual(object, org) | CurrentState::ExistsUnequal(object, org) => {
            debug!("azure ad provider changed, updating");

            management
                .update_azure_ad_provider(create_request_with_org_id(
                    UpdateAzureAdProviderRequest {
                        id: object.id.clone(),
                        name: idp.spec.name.clone(),
                        client_id: azure.client_id.clone(),
                        client_secret: secret,
                        tenant: Some(pinned_tenant(&azure.tenant_id)),
                        email_verified: azure.email_verified,
                        scopes: vec![],
                        provider_options: Some(provider_options(idp.spec.auto_register)),
                    },
                    org.id.clone(),
                ))
                .await?;

            patch_status(
                idps,
                idp.as_ref(),
                pushed_status(object.id.clone(), org.id.clone(), desired_hash),
            )
            .await?;

            recorder
                .publish(
                    &Event {
                        type_: EventType::Normal,
                        reason: "SpecChanged".to_string(),
                        note: Some(format!("Identity provider {} updated", idp.spec.name)),
                        action: "Updating".into(),
                        secondary: None,
                    },
                    &idp.object_ref(&()),
                )
                .await?;

            Some((object.id, org.id))
        }
        CurrentState::NotExists(org) => {
            debug!("azure ad provider not found, (re)creating");

            let idp_id = management
                .add_azure_ad_provider(create_request_with_org_id(
                    AddAzureAdProviderRequest {
                        name: idp.spec.name.clone(),
                        client_id: azure.client_id.clone(),
                        client_secret: secret,
                        tenant: Some(pinned_tenant(&azure.tenant_id)),
                        email_verified: azure.email_verified,
                        scopes: vec![],
                        provider_options: Some(provider_options(idp.spec.auto_register)),
                    },
                    org.id.clone(),
                ))
                .await?
                .into_inner()
                .id;

            patch_status(
                idps,
                idp.as_ref(),
                pushed_status(idp_id.clone(), org.id.clone(), desired_hash),
            )
            .await?;

            recorder
                .publish(
                    &Event {
                        type_: EventType::Normal,
                        reason: "Created".to_string(),
                        note: Some("Identity provider created".to_string()),
                        action: "Creating".to_string(),
                        secondary: None,
                    },
                    &idp.object_ref(&()),
                )
                .await?;

            Some((idp_id, org.id))
        }
        CurrentState::ParentNotFound => {
            info!("organization {} not found", idp.spec.organization_name);

            recorder
                .publish(
                    &Event {
                        type_: EventType::Normal,
                        reason: "Missing".to_string(),
                        note: Some("Organization does not exist".to_string()),
                        action: "NotCreated".to_string(),
                        secondary: None,
                    },
                    &idp.object_ref(&()),
                )
                .await?;

            None
        }
        CurrentState::ParentNotReady(_) => {
            info!("organization {} not ready", idp.spec.organization_name);

            recorder
                .publish(
                    &Event {
                        type_: EventType::Normal,
                        reason: "NotCreated".to_string(),
                        note: Some("Organization is not yet created".to_string()),
                        action: "NotCreated".to_string(),
                        secondary: None,
                    },
                    &idp.object_ref(&()),
                )
                .await?;

            None
        }
        CurrentState::FoundAdoptable(object, org) => {
            if !is_azure_ad_provider(&object) {
                let note = format!(
                    "Organization {} already has a provider named '{}' that is not an Azure AD \
                     provider, so this resource cannot manage it",
                    idp.spec.organization_name, idp.spec.name
                );
                warn!("{note}");
                recorder
                    .publish(
                        &Event {
                            type_: EventType::Warning,
                            reason: "NameTaken".to_string(),
                            note: Some(note.clone()),
                            action: "NotAdopted".to_string(),
                            secondary: None,
                        },
                        &idp.object_ref(&()),
                    )
                    .await?;
                return Err(Error::Other(note));
            }

            debug!("azure ad provider found, attaching id to resource");

            patch_status(idps, idp.as_ref(), adopted_status(object.id.clone(), org.id.clone())).await?;

            recorder
                .publish(
                    &Event {
                        type_: EventType::Normal,
                        reason: "Creating".to_string(),
                        note: Some("Existing identity provider adopted".to_string()),
                        action: "Adopted".to_string(),
                        secondary: None,
                    },
                    &idp.object_ref(&()),
                )
                .await?;

            Some((object.id, org.id))
        }
    };

    Ok(ensured)
}

#[instrument(skip(ctx, idp))]
async fn reconcile(idp: Arc<IdentityProvider>, ctx: Arc<OperatorContext>) -> Result<Action> {
    let ns = idp.metadata.namespace.as_ref().unwrap();
    let idps = Api::<IdentityProvider>::namespaced(ctx.k8s.clone(), &ns);
    let orgs = Api::<Organization>::all(ctx.k8s.clone());
    let recorder = ctx.build_recorder();

    finalizer(&idps, IDENTITY_PROVIDER_FINALIZER, idp, |event| async {
        match event {
            Finalizer::Apply(idp) => {
                info!("reconciling identity provider {}", idp.name_any());

                let mut management = ctx.zitadel.builder().build_management_client().await?;

                let ensured = match &idp.spec.inner {
                    IdentityProviderInnerSpec::Jwt(_) => {
                        reconcile_jwt(&mut management, &recorder, &idps, &orgs, &idp).await?
                    }
                    IdentityProviderInnerSpec::AzureAd(_) => {
                        reconcile_azure_ad(&ctx, &mut management, &recorder, &idps, &orgs, &idp).await?
                    }
                };

                if let Some((idp_id, org_id)) = ensured {
                    reconcile_login_screen(&ctx, &mut management, &recorder, &idp, &idp_id, &org_id).await?;
                }

                Ok(Action::requeue(Duration::from_secs(requeue_secs())))
            }
            Finalizer::Cleanup(idp) => {
                info!("cleaning up identity provider {}", idp.name_any());

                let mut management = ctx.zitadel.builder().build_management_client().await?;

                if let Some(status) = &idp.status {
                    let stored = match management
                        .get_provider_by_id(create_request_with_org_id(
                            GetProviderByIdRequest { id: status.id.clone() },
                            status.organization_id.clone(),
                        ))
                        .await
                    {
                        Ok(resp) => resp.into_inner().idp,
                        Err(e) if is_already_gone(&e) => None,
                        Err(e) => return Result::Err(Error::ZitadelError(e)),
                    };

                    // Deletion follows the provider's own type rather than the spec
                    // variant: only this operator writes status.id, so a mismatch means
                    // the variant was flipped and the declared API never issued that id.
                    let Some(azure_ad) = stored.as_ref().map(is_azure_ad_provider) else {
                        debug!("identity provider not found");
                        return Ok(Action::await_change());
                    };

                    if azure_ad != matches!(idp.spec.inner, IdentityProviderInnerSpec::AzureAd(_)) {
                        let note = format!(
                            "IdentityProvider {} declares a different provider type than the one \
                             stored under status.id '{}'; deleting the stored provider",
                            idp.name_any(),
                            status.id
                        );
                        warn!("{note}");
                        recorder
                            .publish(
                                &Event {
                                    type_: EventType::Warning,
                                    reason: "TypeMismatch".to_string(),
                                    note: Some(note),
                                    action: "Deleting".to_string(),
                                    secondary: None,
                                },
                                &idp.object_ref(&()),
                            )
                            .await?;
                    }

                    let resp = if azure_ad {
                        management
                            .delete_provider(create_request_with_org_id(
                                DeleteProviderRequest { id: status.id.clone() },
                                status.organization_id.clone(),
                            ))
                            .await
                            .map(|_| ())
                    } else {
                        management
                            .remove_org_idp(create_request_with_org_id(
                                RemoveOrgIdpRequest {
                                    idp_id: status.id.clone(),
                                },
                                status.organization_id.clone(),
                            ))
                            .await
                            .map(|_| ())
                    };

                    match resp {
                        Ok(_) => {
                            debug!("identity provider removed");

                            recorder
                                .publish(
                                    &Event {
                                        type_: EventType::Normal,
                                        reason: "DeleteRequested".to_string(),
                                        note: Some(format!("Identity provider {} was deleted", idp.name_any())),
                                        action: "Deleting".to_string(),
                                        secondary: None,
                                    },
                                    &idp.object_ref(&()),
                                )
                                .await?;
                        }
                        Err(e) if is_already_gone(&e) => {
                            debug!("identity provider no longer exists");
                        }
                        Err(e) => return Result::Err(Error::ZitadelError(e)),
                    }
                } else {
                    debug!("identity provider never appears to have been created");
                }

                Ok(Action::await_change())
            }
        }
    })
    .await
    .map_err(|e| Error::FinalizerError(Box::new(e)))
}

fn error_policy(_: Arc<IdentityProvider>, error: &Error, _: Arc<OperatorContext>) -> Action {
    warn!("reconcile failed: {:?}", error);
    Action::requeue(Duration::from_secs(60))
}

pub async fn run(context: Arc<OperatorContext>) {
    let idps = Api::<IdentityProvider>::all(context.k8s.clone());
    let orgs = Api::<Organization>::all(context.k8s.clone());
    let controller = Controller::new(idps, Config::default().any_semantic());
    let store = controller.store();
    controller
        .watches_stream(
            metadata_watcher(orgs, Config::default()).touched_objects(),
            move |org| {
                store
                    .state()
                    .into_iter()
                    .filter(move |idp| org.name().map(String::from).as_ref() == Some(&idp.spec.organization_name))
                    .map(|idp| ObjectRef::from_obj(&*idp))
            },
        )
        .shutdown_on_signal()
        .run(reconcile, error_policy, context)
        .filter_map(|x| async move { std::result::Result::ok(x) })
        .for_each(|_| futures::future::ready(()))
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{ClientSecretKeySelector, IdentityProviderSpec};
    use kube::CustomResourceExt;
    use zitadel::api::zitadel::idp::v1::{AzureAdConfig, AzureAdTenantType, JwtConfig, ProviderConfig as Config};

    const TENANT: &str = "ba5316df-1a48-4eaf-a2ca-f58b8408485d";
    const CLIENT: &str = "c9652a4e-39f2-4ad7-b93d-8f847ca7d6c0";

    fn azure_cr() -> IdentityProvider {
        let spec = IdentityProviderSpec {
            name: "Microsoft (Qunaira)".to_string(),
            organization_name: "legal".to_string(),
            auto_register: true,
            show_on_login_screen: true,
            inner: IdentityProviderInnerSpec::AzureAd(IdentityProviderAzureAdSpec {
                tenant_id: TENANT.to_string(),
                client_id: CLIENT.to_string(),
                client_secret_ref: ClientSecretKeySelector {
                    name: "zitadel-entra".to_string(),
                    key: "client-secret".to_string(),
                },
                email_verified: true,
            }),
        };
        IdentityProvider::new("legal-entra-idp", spec)
    }

    fn provider_from(idp: &IdentityProvider) -> Provider {
        let azure = azure_ad_spec(idp);
        Provider {
            id: "380599158664331800".to_string(),
            details: None,
            state: 0,
            name: idp.spec.name.clone(),
            owner: IdpOwnerType::Org.into(),
            r#type: ProviderType::AzureAd.into(),
            config: Some(Config {
                options: Some(provider_options(idp.spec.auto_register)),
                config: Some(ProviderConfig::AzureAd(AzureAdConfig {
                    client_id: azure.client_id.clone(),
                    tenant: Some(pinned_tenant(&azure.tenant_id)),
                    email_verified: azure.email_verified,
                    scopes: vec![],
                })),
            }),
        }
    }

    fn azure_config(provider: &mut Provider) -> &mut AzureAdConfig {
        match &mut provider.config.as_mut().unwrap().config {
            Some(ProviderConfig::AzureAd(config)) => config,
            _ => panic!("not an azure ad provider"),
        }
    }

    #[test]
    fn a_directory_id_is_accepted() {
        assert!(is_directory_id(TENANT));
        assert_eq!(
            pinned_tenant(TENANT).r#type,
            Some(azure_ad_tenant::Type::TenantId(TENANT.to_string()))
        );
    }

    /// The three multi-tenant selectors are the whole point of the check: each
    /// one federates every Microsoft account instead of one customer directory.
    #[test]
    fn the_multi_tenant_selectors_are_rejected() {
        for selector in ["common", "organizations", "organisations", "consumers"] {
            assert!(!is_directory_id(selector), "{selector} was taken for a directory ID");
        }
    }

    #[test]
    fn anything_that_is_not_a_directory_id_is_rejected() {
        for malformed in [
            "",
            "contoso.onmicrosoft.com",
            // Right shape, wrong alphabet.
            "ba5316dg-1a48-4eaf-a2ca-f58b8408485d",
            // Right alphabet, wrong grouping.
            "ba5316df1a484eafa2caf58b8408485d",
            "ba5316df-1a48-4eaf-a2ca-f58b840848",
            "ba5316df-1a48-4eaf-a2ca-f58b8408485d-",
            "ba5316df-1a48-4eaf-a2ca-f58b8408485d-0000",
            " ba5316df-1a48-4eaf-a2ca-f58b8408485d",
            // Entra prints directory IDs in either case. Only the lower-case
            // one is safe to hand to Zitadel, so the other is a rejection
            // rather than a value to quietly fold.
            "BA5316DF-1A48-4EAF-A2CA-F58B8408485D",
            "ba5316df-1a48-4eaf-a2ca-F58b8408485d",
        ] {
            assert!(
                !is_directory_id(malformed),
                "{malformed:?} was taken for a directory ID"
            );
        }
    }

    /// Zitadel reads `common` back as a tenant *type*, which no spec of ours can
    /// equal, so a provider created with one would also be rewritten on every
    /// single reconcile.
    #[test]
    fn a_tenant_type_never_equals_a_pinned_tenant() {
        let idp = azure_cr();
        let mut multi_tenant = provider_from(&idp);
        azure_config(&mut multi_tenant).tenant = Some(AzureAdTenant {
            r#type: Some(azure_ad_tenant::Type::TenantType(AzureAdTenantType::Common.into())),
        });
        assert!(!azure_ad_matches_spec(&multi_tenant, &idp));
    }

    #[test]
    fn only_an_azure_ad_provider_is_an_azure_ad_provider() {
        let idp = azure_cr();
        assert!(is_azure_ad_provider(&provider_from(&idp)));

        for taken_by in [
            ProviderType::Jwt,
            ProviderType::Oidc,
            ProviderType::Saml,
            ProviderType::Unspecified,
        ] {
            let mut other = provider_from(&idp);
            other.r#type = taken_by.into();
            assert!(
                !is_azure_ad_provider(&other),
                "{taken_by:?} must not pass as Azure AD"
            );
        }
    }

    #[test]
    fn an_adopted_provider_still_owes_its_client_secret() {
        let status = adopted_status("380599158664331800".to_string(), "org".to_string());
        assert_eq!(status.client_secret_hash, None);
        assert!(
            needs_client_secret_push(status.client_secret_hash.as_deref(), &client_secret_hash("from-k8s")),
            "adoption must leave the next reconcile a secret to push"
        );
    }

    #[test]
    fn a_pushed_secret_is_not_pushed_again() {
        let hash = client_secret_hash("unchanged");
        let status = pushed_status("380599158664331800".to_string(), "org".to_string(), hash.clone());
        assert_eq!(status.client_secret_hash, Some(hash.clone()));
        assert!(
            !needs_client_secret_push(status.client_secret_hash.as_deref(), &hash),
            "a steady state must not rewrite the provider on every requeue"
        );
        assert!(
            needs_client_secret_push(status.client_secret_hash.as_deref(), &client_secret_hash("rotated")),
            "a rotated Secret must be pushed"
        );
    }

    #[test]
    fn auto_register_drives_auto_creation_only() {
        assert!(provider_options(true).is_auto_creation);
        assert!(!provider_options(false).is_auto_creation);
        for auto_register in [true, false] {
            let options = provider_options(auto_register);
            assert!(options.is_auto_update, "Entra stays the source of truth for profiles");
            assert!(options.is_linking_allowed);
            assert!(options.is_creation_allowed);
            assert_eq!(
                options.auto_linking,
                i32::from(AutoLinkingOption::Unspecified),
                "auto-linking prompts must stay off"
            );
        }
    }

    #[test]
    fn a_provider_built_from_the_spec_matches_it() {
        let idp = azure_cr();
        assert!(azure_ad_matches_spec(&provider_from(&idp), &idp));
    }

    #[test]
    fn every_comparable_field_is_part_of_the_drift_check() {
        let idp = azure_cr();

        let mut renamed = provider_from(&idp);
        renamed.name = "Microsoft".to_string();
        assert!(!azure_ad_matches_spec(&renamed, &idp), "name");

        let mut other_client = provider_from(&idp);
        azure_config(&mut other_client).client_id = "00000000-0000-0000-0000-000000000000".to_string();
        assert!(!azure_ad_matches_spec(&other_client, &idp), "clientId");

        let mut other_tenant = provider_from(&idp);
        azure_config(&mut other_tenant).tenant = Some(pinned_tenant("00000000-0000-0000-0000-000000000000"));
        assert!(!azure_ad_matches_spec(&other_tenant, &idp), "tenantId");

        let mut common_tenant = provider_from(&idp);
        azure_config(&mut common_tenant).tenant = None;
        assert!(
            !azure_ad_matches_spec(&common_tenant, &idp),
            "an unpinned tenant is drift"
        );

        let mut unverified = provider_from(&idp);
        azure_config(&mut unverified).email_verified = false;
        assert!(!azure_ad_matches_spec(&unverified, &idp), "emailVerified");

        let mut no_auto_register = provider_from(&idp);
        no_auto_register.config.as_mut().unwrap().options = Some(provider_options(false));
        assert!(!azure_ad_matches_spec(&no_auto_register, &idp), "autoRegister");

        let mut scoped = provider_from(&idp);
        azure_config(&mut scoped).scopes = vec!["openid".to_string()];
        assert!(!azure_ad_matches_spec(&scoped, &idp), "scopes");

        let mut optionless = provider_from(&idp);
        optionless.config.as_mut().unwrap().options = None;
        assert!(!azure_ad_matches_spec(&optionless, &idp), "absent options");
    }

    /// Every option is settable in the Zitadel console, so each one is drift the
    /// next reconcile has to undo rather than carry until a secret rotation.
    #[test]
    fn an_option_changed_in_the_console_counts_as_drift() {
        let idp = azure_cr();
        let base = provider_options(idp.spec.auto_register);

        let mut edits = vec![];
        for flip in [
            Options {
                is_linking_allowed: !base.is_linking_allowed,
                ..base
            },
            Options {
                is_creation_allowed: !base.is_creation_allowed,
                ..base
            },
            Options {
                is_auto_creation: !base.is_auto_creation,
                ..base
            },
            Options {
                is_auto_update: !base.is_auto_update,
                ..base
            },
            Options {
                auto_linking: AutoLinkingOption::Email.into(),
                ..base
            },
        ] {
            let mut edited = provider_from(&idp);
            edited.config.as_mut().unwrap().options = Some(flip);
            edits.push((flip, edited));
        }

        for (flip, edited) in edits {
            assert!(!azure_ad_matches_spec(&edited, &idp), "{flip:?} must count as drift");
        }
    }

    #[test]
    fn a_provider_of_another_type_never_matches() {
        let idp = azure_cr();

        let mut jwt = provider_from(&idp);
        jwt.config.as_mut().unwrap().config = Some(ProviderConfig::Jwt(JwtConfig::default()));
        assert!(!azure_ad_matches_spec(&jwt, &idp));

        let mut configless = provider_from(&idp);
        configless.config = None;
        assert!(!azure_ad_matches_spec(&configless, &idp));
    }

    #[test]
    fn the_secret_hash_is_stable_and_opaque() {
        let secret = "hunter2";
        let hash = client_secret_hash(secret);
        assert_eq!(hash, client_secret_hash(secret), "a stable hash across reconciles");
        assert!(!hash.contains(secret), "the hash must not carry the secret");
        assert_ne!(hash, client_secret_hash("hunter3"));
    }

    #[test]
    fn the_variant_is_tagged_azure_ad_in_camel_case() {
        let json = serde_json::to_value(&azure_cr().spec).unwrap();
        let azure = &json["azureAd"];
        assert_eq!(azure["tenantId"], TENANT);
        assert_eq!(azure["clientId"], CLIENT);
        assert_eq!(azure["clientSecretRef"]["key"], "client-secret");
        assert_eq!(azure["emailVerified"], true);
        assert!(json.get("jwt").is_none());
    }

    fn azure_ad_spec_from(azure: serde_json::Value) -> IdentityProviderSpec {
        serde_json::from_value(serde_json::json!({
            "name": "Microsoft",
            "organizationName": "legal",
            "azureAd": azure,
        }))
        .unwrap()
    }

    fn complete_azure_ad() -> serde_json::Value {
        serde_json::json!({
            "tenantId": TENANT,
            "clientId": CLIENT,
            "clientSecretRef": { "name": "zitadel-entra", "key": "client-secret" },
        })
    }

    #[test]
    fn email_verified_defaults_off_and_the_rest_is_required() {
        let spec = azure_ad_spec_from(complete_azure_ad());
        let azure = match &spec.inner {
            IdentityProviderInnerSpec::AzureAd(azure) => azure,
            other => panic!("parsed as {other:?}"),
        };
        assert!(!azure.email_verified);
        assert_eq!(azure.client_secret_ref.key, "client-secret");

        for missing in ["tenantId", "clientId", "clientSecretRef"] {
            let mut azure = complete_azure_ad();
            azure.as_object_mut().unwrap().remove(missing);
            let value = serde_json::json!({
                "name": "Microsoft",
                "organizationName": "legal",
                "azureAd": azure,
            });
            serde_json::from_value::<IdentityProviderSpec>(value).expect_err(&format!("{missing} must be required"));
        }

        for missing in ["name", "key"] {
            let mut azure = complete_azure_ad();
            azure["clientSecretRef"].as_object_mut().unwrap().remove(missing);
            let value = serde_json::json!({
                "name": "Microsoft",
                "organizationName": "legal",
                "azureAd": azure,
            });
            serde_json::from_value::<IdentityProviderSpec>(value)
                .expect_err(&format!("clientSecretRef.{missing} must be required"));
        }
    }

    /// The selector carries no namespace: one would let whoever may create an
    /// IdentityProvider have the operator read any Secret in the cluster, and
    /// `status.clientSecretHash` read it back.
    #[test]
    fn the_client_secret_is_resolved_without_a_namespace() {
        let schema = schemars::schema_for!(ClientSecretKeySelector);
        let properties = &schema.schema.object.as_ref().unwrap().properties;
        assert_eq!(
            properties.keys().collect::<Vec<_>>(),
            vec!["key", "name"],
            "the selector must offer nothing but a name and a key"
        );

        let mut azure = complete_azure_ad();
        azure["clientSecretRef"]["namespace"] = serde_json::json!("kube-system");
        let spec = azure_ad_spec_from(azure);
        let round_trip = serde_json::to_value(&spec).unwrap();
        assert!(
            round_trip["azureAd"]["clientSecretRef"].get("namespace").is_none(),
            "a namespace the API server would prune must not survive into the operator"
        );
    }

    /// The variant decides which Zitadel API owns the provider, so a flip would send
    /// `status.id` to an API that never issued it.
    #[test]
    fn the_variant_is_immutable_in_the_crd() {
        let crd = serde_json::to_value(IdentityProvider::crd()).unwrap();
        let rules = &crd["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["x-kubernetes-validations"];
        let rules = rules.as_array().expect("the root schema must carry a CEL rule");
        let variant = rules
            .iter()
            .find(|rule| rule["rule"] == "has(self.spec.jwt) == has(oldSelf.spec.jwt)")
            .expect("the jwt/azureAd variant must be immutable");
        assert_eq!(
            variant["message"],
            "the provider type cannot change; delete and recreate the IdentityProvider"
        );
    }

    /// `status.id` is an id in one Zitadel API alone. Reconciling a spec against a
    /// provider of the other kind would address a provider this resource does not own.
    #[test]
    fn a_provider_of_the_other_kind_is_never_taken_for_the_spec_variant() {
        let azure = provider_from(&azure_cr());
        let mut jwt = azure.clone();
        jwt.r#type = ProviderType::Jwt.into();
        assert!(is_azure_ad_provider(&azure));
        assert!(!is_azure_ad_provider(&jwt));

    }

    /// Adoption keys on the display name alone, and the cleanup deletes whatever
    /// `status.id` names, so a resource that adopted a provider of another kind
    /// would take an identity source its users are linked to down with it.
    #[test]
    fn only_a_jwt_provider_is_adopted_by_a_jwt_resource() {
        let jwt = Idp {
            config: Some(IdpConfig::JwtConfig(JwtConfig::default())),
            ..Idp::default()
        };
        assert!(is_jwt_provider(&jwt));

        // Everything else the legacy API can answer with.
        for taken_by in [Some(IdpConfig::OidcConfig(Default::default())), None] {
            let other = Idp {
                config: taken_by.clone(),
                ..Idp::default()
            };
            assert!(
                !is_jwt_provider(&other),
                "{taken_by:?} must not be adopted as a jwt provider"
            );
        }
    }
}
