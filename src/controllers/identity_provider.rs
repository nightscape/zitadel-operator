use crate::{
    schema::{
        IdentityProvider, IdentityProviderInnerSpec, IdentityProviderPhase, IdentityProviderStatus,
        Organization,
    },
    util::{
        create_request_with_org_id, patch_status, requeue_secs, CurrentState, CurrentStateParameters,
        CurrentStateRetriever, GetStatus,
    },
    Error, OperatorContext, Result,
};
use futures::StreamExt;
use kube::{
    runtime::{
        controller::Action,
        events::{Event, EventType},
        finalizer::{finalizer, Event as Finalizer},
        metadata_watcher,
        reflector::{Lookup, ObjectRef},
        watcher::Config,
        Controller, WatchStreamExt,
    },
    Api, Resource, ResourceExt,
};
use std::{sync::Arc, time::Duration};
use tonic::{service::interceptor::InterceptedService, Code};
use tracing::{debug, info, instrument, warn};
use zitadel::api::zitadel::{
    idp::v1::{idp::Config as IdpConfig, Idp, IdpFieldName, IdpNameQuery, IdpStylingType},
    management::v1::{
        idp_query, management_service_client::ManagementServiceClient, AddOrgJwtidpRequest,
        GetOrgIdpByIdRequest, IdpQuery, ListOrgIdPsRequest, RemoveOrgIdpRequest, UpdateOrgIdpRequest,
        UpdateOrgIdpjwtConfigRequest,
    },
    v1::TextQueryMethod,
};

use crate::CustomHeaderInterceptor;

pub static IDENTITY_PROVIDER_FINALIZER: &str = "identityprovider.zitadel.org";

fn matches_spec(object: &Idp, idp: &IdentityProvider) -> bool {
    let IdentityProviderInnerSpec::Jwt(jwt) = &idp.spec.inner;
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

                let IdentityProviderInnerSpec::Jwt(jwt) = &idp.spec.inner;

                let mut management = ctx.zitadel.builder().build_management_client().await?;

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

                match state {
                    CurrentState::ExistsEqual(_, _) => {}
                    CurrentState::ExistsUnequal(object, org) => {
                        debug!("identity provider changed, updating");

                        // Zitadel splits the provider across two calls: the
                        // envelope carries name and auto-register, the config
                        // carries the endpoints.
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

                        patch_status(
                            &idps,
                            idp.as_ref(),
                            IdentityProviderStatus {
                                id: resp.idp_id,
                                organization_id: org.id,
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
                    }
                    CurrentState::FoundAdoptable(object, org) => {
                        debug!("identity provider found, attaching id to resource");

                        patch_status(
                            &idps,
                            idp.as_ref(),
                            IdentityProviderStatus {
                                id: object.id.clone(),
                                organization_id: org.id,
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
                    }
                }

                Ok(Action::requeue(Duration::from_secs(requeue_secs())))
            }
            Finalizer::Cleanup(idp) => {
                info!("cleaning up identity provider {}", idp.name_any());

                let mut management = ctx.zitadel.builder().build_management_client().await?;

                if let Some(status) = &idp.status {
                    let resp = management
                        .remove_org_idp(create_request_with_org_id(
                            RemoveOrgIdpRequest {
                                idp_id: status.id.clone(),
                            },
                            status.organization_id.clone(),
                        ))
                        .await;

                    match resp {
                        Ok(_) => {
                            debug!("identity provider removed");

                            recorder
                                .publish(
                                    &Event {
                                        type_: EventType::Normal,
                                        reason: "DeleteRequested".to_string(),
                                        note: Some(format!(
                                            "Identity provider {} was deleted",
                                            idp.name_any()
                                        )),
                                        action: "Deleting".to_string(),
                                        secondary: None,
                                    },
                                    &idp.object_ref(&()),
                                )
                                .await?;
                        }
                        Err(e) if e.code() == Code::NotFound => {
                            debug!("identity provider not found");
                        }
                        Err(e)
                            if e.code() == Code::PermissionDenied
                                && e.message() == "Organisation doesn't exist (AUTH-Bs7Ds)" =>
                        {
                            debug!("organization not found, identity provider does not exist");
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
