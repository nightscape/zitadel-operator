use crate::{
    schema::{Project, ProjectRole, ProjectRolePhase, ProjectRoleStatus},
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
    AddProjectRoleRequest, ListProjectRolesRequest, RemoveProjectRoleRequest, UpdateProjectRoleRequest,
};

pub static PROJECT_ROLE_FINALIZER: &str = "projectrole.zitadel.org";

struct ZitadelRole {
    pub display_name: String,
    pub group: String,
}

#[instrument(skip(ctx, role))]
async fn reconcile(role: Arc<ProjectRole>, ctx: Arc<OperatorContext>) -> Result<Action> {
    let ns = role.metadata.namespace.as_ref().unwrap();
    let roles = Api::<ProjectRole>::namespaced(ctx.k8s.clone(), ns);
    let projs = Api::<Project>::namespaced(ctx.k8s.clone(), role.spec.project_namespace.as_ref().unwrap_or(ns));
    let recorder = ctx.build_recorder();

    finalizer(&roles, PROJECT_ROLE_FINALIZER, role, |event| async {
        match event {
            Finalizer::Apply(role) => {
                info!("reconciling project role {}", role.name_any());

                let mut management = ctx.zitadel.builder().build_management_client().await?;

                let proj = projs.get_opt(&role.spec.project_name).await?;
                let proj = match proj {
                    None => {
                        info!("project {} not found", role.spec.project_name);
                        recorder
                            .publish(
                                &Event {
                                    type_: EventType::Normal,
                                    reason: "Missing".to_string(),
                                    note: Some("Project does not exist".to_string()),
                                    action: "NotCreated".to_string(),
                                    secondary: None,
                                },
                                &role.object_ref(&()),
                            )
                            .await?;
                        return Ok(Action::await_change());
                    }
                    Some(proj) => proj,
                };

                let proj_status = match proj.get_status() {
                    Some(status) if proj.is_ready() => status,
                    _ => {
                        info!("project {} not ready", role.spec.project_name);
                        recorder
                            .publish(
                                &Event {
                                    type_: EventType::Normal,
                                    reason: "NotCreated".to_string(),
                                    note: Some("Project is not yet created".to_string()),
                                    action: "NotCreated".to_string(),
                                    secondary: None,
                                },
                                &role.object_ref(&()),
                            )
                            .await?;
                        return Ok(Action::await_change());
                    }
                };

                let existing_role = management
                    .list_project_roles(create_request_with_org_id(
                        ListProjectRolesRequest {
                            project_id: proj_status.id.clone(),
                            query: None,
                            queries: vec![zitadel::api::zitadel::project::v1::RoleQuery {
                                query: Some(zitadel::api::zitadel::project::v1::role_query::Query::KeyQuery(
                                    zitadel::api::zitadel::project::v1::RoleKeyQuery {
                                        key: role.spec.key.clone(),
                                        method: zitadel::api::zitadel::v1::TextQueryMethod::Equals.into(),
                                    },
                                )),
                            }],
                        },
                        proj_status.organization_id.clone(),
                    ))
                    .await?
                    .into_inner()
                    .result
                    .into_iter()
                    .next()
                    .map(|r| ZitadelRole {
                        display_name: r.display_name,
                        group: r.group,
                    });

                let spec_group = role.spec.group.clone().unwrap_or_default();

                match existing_role {
                    Some(existing) if existing.display_name == role.spec.display_name && existing.group == spec_group => {
                        debug!("role already exists and matches spec");

                        if role.status.is_none() {
                            patch_status(
                                &roles,
                                role.as_ref(),
                                ProjectRoleStatus {
                                    project_id: proj_status.id.clone(),
                                    organization_id: proj_status.organization_id.clone(),
                                    phase: ProjectRolePhase::Ready,
                                },
                            )
                            .await?;

                            recorder
                                .publish(
                                    &Event {
                                        type_: EventType::Normal,
                                        reason: "Creating".to_string(),
                                        note: Some("Existing role adopted".to_string()),
                                        action: "Adopted".to_string(),
                                        secondary: None,
                                    },
                                    &role.object_ref(&()),
                                )
                                .await?;
                        }
                    }
                    Some(_existing) => {
                        debug!("role exists but differs, updating");

                        management
                            .update_project_role(create_request_with_org_id(
                                UpdateProjectRoleRequest {
                                    project_id: proj_status.id.clone(),
                                    role_key: role.spec.key.clone(),
                                    display_name: role.spec.display_name.clone(),
                                    group: spec_group,
                                },
                                proj_status.organization_id.clone(),
                            ))
                            .await?;

                        if role.status.is_none() {
                            patch_status(
                                &roles,
                                role.as_ref(),
                                ProjectRoleStatus {
                                    project_id: proj_status.id.clone(),
                                    organization_id: proj_status.organization_id.clone(),
                                    phase: ProjectRolePhase::Ready,
                                },
                            )
                            .await?;
                        }

                        recorder
                            .publish(
                                &Event {
                                    type_: EventType::Normal,
                                    reason: "Updated".to_string(),
                                    note: Some("Role updated".to_string()),
                                    action: "Updating".to_string(),
                                    secondary: None,
                                },
                                &role.object_ref(&()),
                            )
                            .await?;
                    }
                    None => {
                        debug!("role not found, creating");

                        management
                            .add_project_role(create_request_with_org_id(
                                AddProjectRoleRequest {
                                    project_id: proj_status.id.clone(),
                                    role_key: role.spec.key.clone(),
                                    display_name: role.spec.display_name.clone(),
                                    group: spec_group,
                                },
                                proj_status.organization_id.clone(),
                            ))
                            .await?;

                        patch_status(
                            &roles,
                            role.as_ref(),
                            ProjectRoleStatus {
                                project_id: proj_status.id.clone(),
                                organization_id: proj_status.organization_id.clone(),
                                phase: ProjectRolePhase::Ready,
                            },
                        )
                        .await?;

                        recorder
                            .publish(
                                &Event {
                                    type_: EventType::Normal,
                                    reason: "Created".to_string(),
                                    note: Some("Role created".to_string()),
                                    action: "Creating".to_string(),
                                    secondary: None,
                                },
                                &role.object_ref(&()),
                            )
                            .await?;
                    }
                }

                Ok(Action::await_change())
            }
            Finalizer::Cleanup(role) => {
                info!("cleaning up project role {}", role.name_any());

                let mut management = ctx.zitadel.builder().build_management_client().await?;

                if let Some(status) = &role.status {
                    let resp = management
                        .remove_project_role(create_request_with_org_id(
                            RemoveProjectRoleRequest {
                                project_id: status.project_id.clone(),
                                role_key: role.spec.key.clone(),
                            },
                            status.organization_id.clone(),
                        ))
                        .await;

                    match resp {
                        Ok(_) => {
                            debug!("role removed");

                            recorder
                                .publish(
                                    &Event {
                                        type_: EventType::Normal,
                                        reason: "DeleteRequested".to_string(),
                                        note: Some(format!("Role {} was deleted", role.name_any())),
                                        action: "Deleting".to_string(),
                                        secondary: None,
                                    },
                                    &role.object_ref(&()),
                                )
                                .await?;
                        }
                        Err(e) if e.code() == Code::NotFound => {
                            debug!("role not found");
                        }
                        Err(e)
                            if e.code() == Code::PermissionDenied
                                && e.message().contains("doesn't exist") =>
                        {
                            debug!("project or organization not found, role does not exist");
                        }
                        Err(e) => return Result::Err(Error::ZitadelError(e)),
                    }
                } else {
                    debug!("role never appears to have been created");
                }

                Ok(Action::await_change())
            }
        }
    })
    .await
    .map_err(|e| Error::FinalizerError(Box::new(e)))
}

fn error_policy(_: Arc<ProjectRole>, error: &Error, _: Arc<OperatorContext>) -> Action {
    warn!("reconcile failed: {:?}", error);
    Action::requeue(Duration::from_secs(60))
}

pub async fn run(context: Arc<OperatorContext>) {
    let roles = Api::<ProjectRole>::all(context.k8s.clone());
    let projs = Api::<Project>::all(context.k8s.clone());
    let controller = Controller::new(roles, Config::default().any_semantic());
    let store = controller.store();
    controller
        .watches_stream(
            metadata_watcher(projs, Config::default()).touched_objects(),
            move |proj| {
                store
                    .state()
                    .into_iter()
                    .filter(move |role| proj.name().map(String::from).as_ref() == Some(&role.spec.project_name))
                    .map(|role| ObjectRef::from_obj(&*role))
            },
        )
        .shutdown_on_signal()
        .run(reconcile, error_policy, context)
        .filter_map(|x| async move { std::result::Result::ok(x) })
        .for_each(|_| futures::future::ready(()))
        .await;
}
