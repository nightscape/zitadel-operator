use crate::{
    schema::{Organization, Project, ProjectPhase, ProjectStatus},
    util::{
        create_request_with_org_id, patch_status, CurrentState, CurrentStateParameters, CurrentStateRetriever,
        GetStatus,
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
use zitadel::api::{
    interceptors::ServiceAccountInterceptor,
    zitadel::{
        management::v1::{
            management_service_client::ManagementServiceClient, AddProjectRequest, GetProjectByIdRequest,
            ListProjectsRequest, RemoveProjectRequest, UpdateProjectRequest,
        },
        project::v1::PrivateLabelingSetting,
    },
};

pub static PROJECT_FINALIZER: &str = "project.zitadel.org";

struct ProjectStateRetriever {
    pub management: ManagementServiceClient<InterceptedService<tonic::transport::Channel, ServiceAccountInterceptor>>,
}
impl CurrentStateRetriever<Project, zitadel::api::zitadel::project::v1::Project, Organization>
    for ProjectStateRetriever
{
    async fn get_object(
        &mut self,
        status: &<Project as GetStatus>::Status,
    ) -> Result<Option<zitadel::api::zitadel::project::v1::Project>> {
        Ok(self
            .management
            .get_project_by_id(GetProjectByIdRequest { id: status.id.clone() })
            .await?
            .into_inner()
            .project)
    }

    async fn list_objects(
        &mut self,
        proj: &Project,
        org: &<Organization as GetStatus>::Status,
    ) -> Result<Vec<zitadel::api::zitadel::project::v1::Project>> {
        let matching = self
            .management
            .list_projects(create_request_with_org_id(
                ListProjectsRequest {
                    query: None,
                    queries: vec![zitadel::api::zitadel::project::v1::ProjectQuery {
                        query: Some(zitadel::api::zitadel::project::v1::project_query::Query::NameQuery(
                            zitadel::api::zitadel::project::v1::ProjectNameQuery {
                                name: proj.spec.name.clone(),
                                method: zitadel::api::zitadel::v1::TextQueryMethod::Equals.into(),
                            },
                        )),
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

#[instrument(skip(ctx, proj))]
async fn reconcile(proj: Arc<Project>, ctx: Arc<OperatorContext>) -> Result<Action> {
    let ns = proj.metadata.namespace.as_ref().unwrap();
    let projs = Api::<Project>::namespaced(ctx.k8s.clone(), &ns);
    let orgs = Api::<Organization>::all(ctx.k8s.clone());
    let recorder = ctx.build_recorder();

    finalizer(&projs, PROJECT_FINALIZER, proj, |event| async {
        match event {
            Finalizer::Apply(proj) => {
                info!("reconciling project {}", proj.name_any());

                let mut management = ctx.zitadel.builder().build_management_client().await?;

                let state = CurrentState::<Organization, zitadel::api::zitadel::project::v1::Project>::determine(
                    CurrentStateParameters {
                        resource: proj.clone(),
                        resource_api: projs.clone(),
                        parent_api: orgs.clone(),
                        parent_name: proj.spec.organization_name.clone(),
                        retriever: ProjectStateRetriever {
                            management: management.clone(),
                        },
                        is_equal: |object, proj| {
                        object.name == proj.spec.name
                            && object.project_role_assertion == proj.spec.project_role_assertion
                    },
                    },
                )
                .await?;

                match state {
                    CurrentState::ExistsEqual(_, _) => {}
                    CurrentState::ExistsUnequal(project, org) => {
                        debug!("project name changed, updating");

                        management
                            .update_project(create_request_with_org_id(
                                UpdateProjectRequest {
                                    id: project.id,
                                    name: proj.spec.name.clone(),
                                    project_role_assertion: proj.spec.project_role_assertion,
                                    project_role_check: project.project_role_check,
                                    has_project_check: project.has_project_check,
                                    private_labeling_setting: project.private_labeling_setting,
                                },
                                org.id,
                            ))
                            .await?;

                        recorder
                            .publish(
                                &Event {
                                    type_: EventType::Normal,
                                    reason: "NameChanged".to_string(),
                                    note: Some(format!(
                                        "Project name changed from {} to {}",
                                        project.name, proj.spec.name
                                    )),
                                    action: "Updating".into(),
                                    secondary: None,
                                },
                                &proj.object_ref(&()),
                            )
                            .await?;
                    }
                    CurrentState::NotExists(org) => {
                        debug!("project not found, (re)creating");

                        let resp = management
                            .add_project(create_request_with_org_id(
                                AddProjectRequest {
                                    name: proj.spec.name.clone(),
                                    project_role_assertion: proj.spec.project_role_assertion,
                                    project_role_check: false,
                                    has_project_check: false,
                                    private_labeling_setting: PrivateLabelingSetting::Unspecified.into(),
                                },
                                org.id.clone(),
                            ))
                            .await?
                            .into_inner();

                        patch_status(
                            &projs,
                            proj.as_ref(),
                            ProjectStatus {
                                id: resp.id,
                                organization_id: org.id,
                                phase: ProjectPhase::Ready,
                            },
                        )
                        .await?;

                        recorder
                            .publish(
                                &Event {
                                    type_: EventType::Normal,
                                    reason: "Created".to_string(),
                                    note: Some("Project created".to_string()),
                                    action: "Creating".to_string(),
                                    secondary: None,
                                },
                                &proj.object_ref(&()),
                            )
                            .await?;
                    }
                    CurrentState::ParentNotFound => {
                        info!("organization {} not found", proj.spec.organization_name);

                        recorder
                            .publish(
                                &Event {
                                    type_: EventType::Normal,
                                    reason: "Missing".to_string(),
                                    note: Some("Organization does not exist".to_string()),
                                    action: "NotCreated".to_string(),
                                    secondary: None,
                                },
                                &proj.object_ref(&()),
                            )
                            .await?;
                    }
                    CurrentState::ParentNotReady(_) => {
                        info!("organization {} not ready", proj.spec.organization_name);

                        recorder
                            .publish(
                                &Event {
                                    type_: EventType::Normal,
                                    reason: "NotCreated".to_string(),
                                    note: Some("Organization is not yet created".to_string()),
                                    action: "NotCreated".to_string(),
                                    secondary: None,
                                },
                                &proj.object_ref(&()),
                            )
                            .await?;
                    }
                    CurrentState::FoundAdoptable(project, org) => {
                        debug!("project found, attaching id to resource");

                        patch_status(
                            &projs,
                            proj.as_ref(),
                            ProjectStatus {
                                id: project.id.clone(),
                                organization_id: org.id,
                                phase: ProjectPhase::Ready,
                            },
                        )
                        .await?;

                        recorder
                            .publish(
                                &Event {
                                    type_: EventType::Normal,
                                    reason: "Creating".to_string(),
                                    note: Some("Existing project adopted".to_string()),
                                    action: "Adopted".to_string(),
                                    secondary: None,
                                },
                                &proj.object_ref(&()),
                            )
                            .await?;
                    }
                }

                Ok(Action::await_change())
            }
            Finalizer::Cleanup(proj) => {
                info!("cleaning up project {}", proj.name_any());

                let mut management = ctx.zitadel.builder().build_management_client().await?;

                if let Some(status) = &proj.status {
                    let resp = management
                        .remove_project(create_request_with_org_id(
                            RemoveProjectRequest { id: status.id.clone() },
                            status.organization_id.clone(),
                        ))
                        .await;

                    match resp {
                        Ok(_) => {
                            debug!("project removed");

                            recorder
                                .publish(
                                    &Event {
                                        type_: EventType::Normal,
                                        reason: "DeleteRequested".to_string(),
                                        note: Some(format!("Project {} was deleted", proj.name_any())),
                                        action: "Deleting".to_string(),
                                        secondary: None,
                                    },
                                    &proj.object_ref(&()),
                                )
                                .await?;
                        }
                        Err(e) if e.code() == Code::NotFound => {
                            debug!("project not found");
                        }
                        Err(e)
                            if e.code() == Code::PermissionDenied
                                && e.message() == "Organisation doesn't exist (AUTH-Bs7Ds)" =>
                        {
                            debug!("organization not found, project does not exist");
                        }
                        Err(e) => return Result::Err(Error::ZitadelError(e)),
                    }
                } else {
                    debug!("project never appears to have been created");
                }

                Ok(Action::await_change())
            }
        }
    })
    .await
    .map_err(|e| Error::FinalizerError(Box::new(e)))
}

fn error_policy(_: Arc<Project>, error: &Error, _: Arc<OperatorContext>) -> Action {
    warn!("reconcile failed: {:?}", error);
    Action::requeue(Duration::from_secs(60))
}

#[derive(Error, Debug)]
enum WatchError {
    #[error("Kube Error: {0}")]
    KubeError(#[from] kube::Error),

    #[error("Kube Watch Error: {0}")]
    WatchError(#[from] kube::runtime::watcher::Error),
}

pub async fn run(context: Arc<OperatorContext>) {
    let projs = Api::<Project>::all(context.k8s.clone());
    let orgs = Api::<Organization>::all(context.k8s.clone());
    let controller = Controller::new(projs, Config::default().any_semantic());
    let store = controller.store();
    controller
        .watches_stream(
            metadata_watcher(orgs, Config::default()).touched_objects(),
            move |org| {
                store
                    .state()
                    .into_iter()
                    .filter(move |proj| org.name().map(String::from).as_ref() == Some(&proj.spec.organization_name))
                    .map(|proj| ObjectRef::from_obj(&*proj))
            },
        )
        .shutdown_on_signal()
        .run(reconcile, error_policy, context)
        .filter_map(|x| async move { std::result::Result::ok(x) })
        .for_each(|_| futures::future::ready(()))
        .await;
}
