use crate::{
    schema::{Organization, OrganizationPhase, OrganizationStatus},
    util::{create_request_with_org_id, patch_status, requeue_secs},
    Error, OperatorContext, Result,
};
use futures::StreamExt;
use kube::{
    runtime::{
        controller::Action,
        events::{Event, EventType},
        finalizer::{finalizer, Event as Finalizer},
        watcher::Config,
        Controller,
    },
    Api, Resource, ResourceExt,
};
use std::{env, sync::Arc, time::Duration};
use tonic::Code;
use tracing::{debug, info, instrument, warn};
use zitadel::api::zitadel::{
    admin::v1::RemoveOrgRequest,
    management::v1::{GetMyOrgRequest, UpdateOrgRequest},
    object::v2::TextQueryMethod,
    org::v2::{
        add_organization_request::{admin::UserType, Admin},
        search_query::Query, AddOrganizationRequest, ListOrganizationsRequest, OrganizationFieldName, OrganizationNameQuery, SearchQuery,
    },
};

pub static ORGANIZATION_FINALIZER: &str = "organization.zitadel.org";

#[instrument(skip(ctx, org))]
async fn reconcile(org: Arc<Organization>, ctx: Arc<OperatorContext>) -> Result<Action> {
    let orgs = Api::<Organization>::all(ctx.k8s.clone());
    let recorder = ctx.build_recorder();

    finalizer(&orgs, ORGANIZATION_FINALIZER, org, |event| async {
        match event {
            Finalizer::Apply(org) => {
                info!("reconciling organization {}", org.name_any());

                let mut organization = ctx.zitadel.builder().build_organization_client().await?;
                let mut management = ctx.zitadel.builder().build_management_client().await?;
                let operator_admin = Admin {
                    roles: vec!["ORG_OWNER".to_string()],
                    user_type: Some(UserType::UserId(ctx.operator_user_id.clone())),
                };

                if let Some(status) = &org.status {
                    let resp = management.get_my_org(
                        create_request_with_org_id(GetMyOrgRequest {}, status.id.clone())
                    ).await;

                    match resp {
                        Ok(resp) => {
                            let stored = resp.into_inner().org.unwrap();
                            if stored.name != org.spec.name {
                                debug!("organization name changed, updating");

                                management
                                    .update_org(create_request_with_org_id(
                                        UpdateOrgRequest {
                                            name: org.spec.name.clone(),
                                        },
                                        stored.id.clone(),
                                    ))
                                    .await?;

                                recorder
                                    .publish(
                                        &Event {
                                            type_: EventType::Normal,
                                            reason: "NameChanged".to_string(),
                                            note: Some(format!(
                                                "Organization name changed from {} to {}",
                                                stored.name, org.spec.name
                                            )),
                                            action: "Updating".into(),
                                            secondary: None,
                                        },
                                        &org.object_ref(&()),
                                    )
                                    .await?;
                            }
                        }
                        Err(e) if e.code() == Code::NotFound
                            || (e.code() == Code::PermissionDenied
                                && e.message().contains("doesn't exist")) =>
                        {
                            debug!("organization not found");

                            let resp = organization
                                .add_organization(AddOrganizationRequest {
                                    name: org.spec.name.clone(),
                                    admins: vec![operator_admin.clone()],
                                })
                                .await?
                                .into_inner();

                            patch_status(
                                &orgs,
                                org.as_ref(),
                                OrganizationStatus {
                                    id: resp.organization_id,
                                    phase: OrganizationPhase::Ready,
                                },
                            )
                            .await?;

                            recorder
                                .publish(
                                    &Event {
                                        type_: EventType::Normal,
                                        reason: "Created".to_string(),
                                        note: Some("Organization created".to_string()),
                                        action: "Creating".to_string(),
                                        secondary: None,
                                    },
                                    &org.object_ref(&()),
                                )
                                .await?;
                        }
                        Err(e) => return Result::Err(Error::ZitadelError(e)),
                    }
                } else {
                    debug!("organization has no status, searching for existing");

                    let search_resp = organization.list_organizations(ListOrganizationsRequest {
                        queries: vec![SearchQuery {
                            query: Some(Query::NameQuery(OrganizationNameQuery {
                                name: org.spec.name.clone(),
                                method: TextQueryMethod::Equals as i32,
                            }))
                        }],
                        query: None,
                        sorting_column: OrganizationFieldName::Unspecified as i32,
                    }).await?.into_inner();

                    if let Some(existing) = search_resp.result.first() {
                        debug!("organization with name {} found, adopting", org.spec.name);

                        patch_status(
                            &orgs,
                            org.as_ref(),
                            OrganizationStatus {
                                id: existing.id.clone(),
                                phase: OrganizationPhase::Ready,
                            },
                        )
                        .await?;

                        recorder
                            .publish(
                                &Event {
                                    type_: EventType::Normal,
                                    reason: "Adopted".to_string(),
                                    note: Some("Organization adopted".to_string()),
                                    action: "Adopting".to_string(),
                                    secondary: None,
                                },
                                &org.object_ref(&()),
                            )
                            .await?;
                    } else {
                        let resp = organization
                            .add_organization(AddOrganizationRequest {
                                name: org.spec.name.clone(),
                                admins: vec![operator_admin],
                            })
                            .await?
                            .into_inner();

                        patch_status(
                            &orgs,
                            org.as_ref(),
                            OrganizationStatus {
                                id: resp.organization_id,
                                phase: OrganizationPhase::Ready,
                            },
                        )
                        .await?;

                        recorder
                            .publish(
                                &Event {
                                    type_: EventType::Normal,
                                    reason: "Created".to_string(),
                                    note: Some("Organization created".to_string()),
                                    action: "Creating".to_string(),
                                    secondary: None,
                                },
                                &org.object_ref(&()),
                            )
                            .await?;
                    }
                }

                Ok(Action::requeue(Duration::from_secs(requeue_secs())))
            }
            Finalizer::Cleanup(org) => {
                info!("cleaning up organization {}", org.name_any());

                if let Some(status) = &org.status {
                    if env::var("ZITADEL_DELETE_ORG").unwrap_or("0".to_string()) == "1" {
                        let mut admin = ctx.zitadel.builder().build_admin_client().await?;
                        let resp = admin
                            .remove_org(RemoveOrgRequest {
                                org_id: status.id.clone(),
                            })
                            .await;

                        match resp {
                            Ok(_) => {
                                debug!("organization removed");

                                recorder
                                    .publish(
                                        &Event {
                                            type_: EventType::Normal,
                                            reason: "DeleteRequested".to_string(),
                                            note: Some(format!("Organization {} was deleted", org.name_any())),
                                            action: "Deleting".to_string(),
                                            secondary: None,
                                        },
                                        &org.object_ref(&()),
                                    )
                                    .await?;
                            }
                            Err(e) if e.code() == Code::NotFound => {
                                debug!("organization not found");
                            }
                            Err(e) if e.code() == Code::PermissionDenied => {
                                warn!("insufficient permissions to delete org in Zitadel (requires IAM Admin); clearing K8s status only");
                                patch_status(&orgs, org.as_ref(), None::<OrganizationStatus>).await?;
                            }
                            Err(e) => return Result::Err(Error::ZitadelError(e)),
                        }
                    } else {
                        patch_status(
                            &orgs,
                            org.as_ref(),
                            None::<OrganizationStatus>,
                        )
                        .await?;
                        debug!("organization id removed from kubernetes resource");
                    }
                } else {
                    debug!("organization never appears to have been created");
                }

                Ok(Action::await_change())
            }
        }
    })
    .await
    .map_err(|e| Error::FinalizerError(Box::new(e)))
}

fn error_policy(_: Arc<Organization>, error: &Error, _: Arc<OperatorContext>) -> Action {
    warn!("reconcile failed: {:?}", error);
    Action::requeue(Duration::from_secs(60))
}

pub async fn run(context: Arc<OperatorContext>) {
    let orgs = Api::<Organization>::all(context.k8s.clone());
    Controller::new(orgs, Config::default().any_semantic())
        .shutdown_on_signal()
        .run(reconcile, error_policy, context)
        .filter_map(|x| async move { std::result::Result::ok(x) })
        .for_each(|_| futures::future::ready(()))
        .await;
}
