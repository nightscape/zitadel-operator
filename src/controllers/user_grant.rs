use crate::{
    schema::{HumanUser, Project, UserGrant, UserGrantPhase, UserGrantStatus},
    util::{create_request_with_org_id, patch_status, GetStatus, IsReady},
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
use tonic::Code;
use tracing::{debug, info, instrument, warn};
use zitadel::api::zitadel::management::v1::{
    AddUserGrantRequest, GetUserGrantByIdRequest, ListUserGrantRequest, RemoveUserGrantRequest,
    UpdateUserGrantRequest,
};

pub static USER_GRANT_FINALIZER: &str = "usergrant.zitadel.org";

#[instrument(skip(ctx, grant))]
async fn reconcile(grant: Arc<UserGrant>, ctx: Arc<OperatorContext>) -> Result<Action> {
    let ns = grant.metadata.namespace.as_ref().unwrap();
    let grants = Api::<UserGrant>::namespaced(ctx.k8s.clone(), ns);
    let users = Api::<HumanUser>::namespaced(
        ctx.k8s.clone(),
        grant.spec.user_namespace.as_ref().unwrap_or(ns),
    );
    let projs = Api::<Project>::namespaced(
        ctx.k8s.clone(),
        grant.spec.project_namespace.as_ref().unwrap_or(ns),
    );
    let recorder = ctx.build_recorder();

    finalizer(&grants, USER_GRANT_FINALIZER, grant, |event| async {
        match event {
            Finalizer::Apply(grant) => {
                info!("reconciling user grant {}", grant.name_any());

                let mut management = ctx.zitadel.builder().build_management_client().await?;

                // Get user
                let user = users.get_opt(&grant.spec.user_name).await?;
                let user = match user {
                    None => {
                        info!("user {} not found", grant.spec.user_name);
                        recorder
                            .publish(
                                &Event {
                                    type_: EventType::Normal,
                                    reason: "Missing".to_string(),
                                    note: Some("User does not exist".to_string()),
                                    action: "NotCreated".to_string(),
                                    secondary: None,
                                },
                                &grant.object_ref(&()),
                            )
                            .await?;
                        return Ok(Action::await_change());
                    }
                    Some(user) => user,
                };

                let user_status = match user.get_status() {
                    Some(status) if user.is_ready() => status,
                    _ => {
                        info!("user {} not ready", grant.spec.user_name);
                        recorder
                            .publish(
                                &Event {
                                    type_: EventType::Normal,
                                    reason: "NotCreated".to_string(),
                                    note: Some("User is not yet created".to_string()),
                                    action: "NotCreated".to_string(),
                                    secondary: None,
                                },
                                &grant.object_ref(&()),
                            )
                            .await?;
                        return Ok(Action::await_change());
                    }
                };

                // Get project
                let proj = projs.get_opt(&grant.spec.project_name).await?;
                let proj = match proj {
                    None => {
                        info!("project {} not found", grant.spec.project_name);
                        recorder
                            .publish(
                                &Event {
                                    type_: EventType::Normal,
                                    reason: "Missing".to_string(),
                                    note: Some("Project does not exist".to_string()),
                                    action: "NotCreated".to_string(),
                                    secondary: None,
                                },
                                &grant.object_ref(&()),
                            )
                            .await?;
                        return Ok(Action::await_change());
                    }
                    Some(proj) => proj,
                };

                let proj_status = match proj.get_status() {
                    Some(status) if proj.is_ready() => status,
                    _ => {
                        info!("project {} not ready", grant.spec.project_name);
                        recorder
                            .publish(
                                &Event {
                                    type_: EventType::Normal,
                                    reason: "NotCreated".to_string(),
                                    note: Some("Project is not yet created".to_string()),
                                    action: "NotCreated".to_string(),
                                    secondary: None,
                                },
                                &grant.object_ref(&()),
                            )
                            .await?;
                        return Ok(Action::await_change());
                    }
                };

                // Check if grant exists by ID (if we have status)
                if let Some(status) = &grant.status {
                    let existing = management
                        .get_user_grant_by_id(create_request_with_org_id(
                            GetUserGrantByIdRequest {
                                user_id: status.user_id.clone(),
                                grant_id: status.id.clone(),
                            },
                            status.organization_id.clone(),
                        ))
                        .await;

                    match existing {
                        Ok(resp) => {
                            if let Some(existing_grant) = resp.into_inner().user_grant {
                                // Grant exists, check if roles need updating
                                let mut existing_roles: Vec<String> = existing_grant.role_keys.clone();
                                let mut desired_roles: Vec<String> = grant.spec.role_keys.clone();
                                existing_roles.sort();
                                desired_roles.sort();

                                if existing_roles != desired_roles {
                                    debug!("grant roles changed, updating");
                                    management
                                        .update_user_grant(create_request_with_org_id(
                                            UpdateUserGrantRequest {
                                                user_id: status.user_id.clone(),
                                                grant_id: status.id.clone(),
                                                role_keys: grant.spec.role_keys.clone(),
                                            },
                                            status.organization_id.clone(),
                                        ))
                                        .await?;

                                    recorder
                                        .publish(
                                            &Event {
                                                type_: EventType::Normal,
                                                reason: "Updated".to_string(),
                                                note: Some("Grant roles updated".to_string()),
                                                action: "Updating".to_string(),
                                                secondary: None,
                                            },
                                            &grant.object_ref(&()),
                                        )
                                        .await?;
                                }
                                return Ok(Action::await_change());
                            }
                        }
                        Err(e) if e.code() == Code::NotFound => {
                            debug!("grant not found by ID, will search");
                        }
                        Err(e) => return Err(Error::ZitadelError(e)),
                    }
                }

                // Search for existing grant for this user+project
                let existing_grants = management
                    .list_user_grants(create_request_with_org_id(
                        ListUserGrantRequest {
                            query: None,
                            queries: vec![
                                zitadel::api::zitadel::user::v1::UserGrantQuery {
                                    query: Some(
                                        zitadel::api::zitadel::user::v1::user_grant_query::Query::UserIdQuery(
                                            zitadel::api::zitadel::user::v1::UserGrantUserIdQuery {
                                                user_id: user_status.id.clone(),
                                            },
                                        ),
                                    ),
                                },
                                zitadel::api::zitadel::user::v1::UserGrantQuery {
                                    query: Some(
                                        zitadel::api::zitadel::user::v1::user_grant_query::Query::ProjectIdQuery(
                                            zitadel::api::zitadel::user::v1::UserGrantProjectIdQuery {
                                                project_id: proj_status.id.clone(),
                                            },
                                        ),
                                    ),
                                },
                            ],
                        },
                        proj_status.organization_id.clone(),
                    ))
                    .await?
                    .into_inner()
                    .result;

                if let Some(existing_grant) = existing_grants.into_iter().next() {
                    debug!("grant found, adopting");
                    patch_status(
                        &grants,
                        grant.as_ref(),
                        UserGrantStatus {
                            id: existing_grant.id,
                            user_id: user_status.id.clone(),
                            project_id: proj_status.id.clone(),
                            organization_id: proj_status.organization_id.clone(),
                            phase: UserGrantPhase::Ready,
                        },
                    )
                    .await?;

                    recorder
                        .publish(
                            &Event {
                                type_: EventType::Normal,
                                reason: "Creating".to_string(),
                                note: Some("Existing grant adopted".to_string()),
                                action: "Adopted".to_string(),
                                secondary: None,
                            },
                            &grant.object_ref(&()),
                        )
                        .await?;

                    return Ok(Action::await_change());
                }

                // Grant doesn't exist, create it
                debug!("grant not found, creating");

                let resp = management
                    .add_user_grant(create_request_with_org_id(
                        AddUserGrantRequest {
                            user_id: user_status.id.clone(),
                            project_id: proj_status.id.clone(),
                            project_grant_id: String::new(),
                            role_keys: grant.spec.role_keys.clone(),
                        },
                        proj_status.organization_id.clone(),
                    ))
                    .await?
                    .into_inner();

                patch_status(
                    &grants,
                    grant.as_ref(),
                    UserGrantStatus {
                        id: resp.user_grant_id,
                        user_id: user_status.id.clone(),
                        project_id: proj_status.id.clone(),
                        organization_id: proj_status.organization_id.clone(),
                        phase: UserGrantPhase::Ready,
                    },
                )
                .await?;

                recorder
                    .publish(
                        &Event {
                            type_: EventType::Normal,
                            reason: "Created".to_string(),
                            note: Some("Grant created".to_string()),
                            action: "Creating".to_string(),
                            secondary: None,
                        },
                        &grant.object_ref(&()),
                    )
                    .await?;

                Ok(Action::await_change())
            }
            Finalizer::Cleanup(grant) => {
                info!("cleaning up user grant {}", grant.name_any());

                let mut management = ctx.zitadel.builder().build_management_client().await?;

                if let Some(status) = &grant.status {
                    let resp = management
                        .remove_user_grant(create_request_with_org_id(
                            RemoveUserGrantRequest {
                                user_id: status.user_id.clone(),
                                grant_id: status.id.clone(),
                            },
                            status.organization_id.clone(),
                        ))
                        .await;

                    match resp {
                        Ok(_) => {
                            debug!("grant removed");

                            recorder
                                .publish(
                                    &Event {
                                        type_: EventType::Normal,
                                        reason: "DeleteRequested".to_string(),
                                        note: Some(format!("Grant {} was deleted", grant.name_any())),
                                        action: "Deleting".to_string(),
                                        secondary: None,
                                    },
                                    &grant.object_ref(&()),
                                )
                                .await?;
                        }
                        Err(e) if e.code() == Code::NotFound => {
                            debug!("grant not found");
                        }
                        Err(e)
                            if e.code() == Code::PermissionDenied
                                && e.message().contains("doesn't exist") =>
                        {
                            debug!("user or organization not found, grant does not exist");
                        }
                        Err(e) => return Err(Error::ZitadelError(e)),
                    }
                } else {
                    debug!("grant never appears to have been created");
                }

                Ok(Action::await_change())
            }
        }
    })
    .await
    .map_err(|e| Error::FinalizerError(Box::new(e)))
}

fn error_policy(_: Arc<UserGrant>, error: &Error, _: Arc<OperatorContext>) -> Action {
    warn!("reconcile failed: {:?}", error);
    Action::requeue(Duration::from_secs(60))
}

pub async fn run(context: Arc<OperatorContext>) {
    let grants = Api::<UserGrant>::all(context.k8s.clone());
    let users = Api::<HumanUser>::all(context.k8s.clone());
    let projs = Api::<Project>::all(context.k8s.clone());
    let controller = Controller::new(grants, Config::default().any_semantic());
    let store = controller.store();
    let store2 = store.clone();
    controller
        .watches_stream(
            metadata_watcher(users, Config::default()).touched_objects(),
            move |user| {
                store
                    .state()
                    .into_iter()
                    .filter(move |grant| {
                        user.name().map(String::from).as_ref() == Some(&grant.spec.user_name)
                    })
                    .map(|grant| ObjectRef::from_obj(&*grant))
            },
        )
        .watches_stream(
            metadata_watcher(projs, Config::default()).touched_objects(),
            move |proj| {
                store2
                    .state()
                    .into_iter()
                    .filter(move |grant| {
                        proj.name().map(String::from).as_ref() == Some(&grant.spec.project_name)
                    })
                    .map(|grant| ObjectRef::from_obj(&*grant))
            },
        )
        .shutdown_on_signal()
        .run(reconcile, error_policy, context)
        .filter_map(|x| async move { std::result::Result::ok(x) })
        .for_each(|_| futures::future::ready(()))
        .await;
}
