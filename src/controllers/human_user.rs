use crate::{
    schema::{Gender, HumanUser, HumanUserPhase, HumanUserStatus, Organization},
    util::{create_request_with_org_id, patch_status, requeue_secs, GetStatus, IsReady},
    Error, OperatorContext, Result,
};
use futures::StreamExt;
use k8s_openapi::api::core::v1::Secret;
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
use zitadel::api::zitadel::{
    management::v1::{AddHumanUserRequest, GetUserByIdRequest, ListUsersRequest, RemoveUserRequest},
    user::v1::{search_query, SearchQuery, UserNameQuery},
};

pub static HUMAN_USER_FINALIZER: &str = "humanuser.zitadel.org";

impl From<&Gender> for i32 {
    fn from(g: &Gender) -> Self {
        match g {
            Gender::Unspecified => zitadel::api::zitadel::user::v1::Gender::Unspecified as i32,
            Gender::Female => zitadel::api::zitadel::user::v1::Gender::Female as i32,
            Gender::Male => zitadel::api::zitadel::user::v1::Gender::Male as i32,
            Gender::Diverse => zitadel::api::zitadel::user::v1::Gender::Diverse as i32,
        }
    }
}

#[instrument(skip(ctx, user))]
async fn reconcile(user: Arc<HumanUser>, ctx: Arc<OperatorContext>) -> Result<Action> {
    let ns = user.metadata.namespace.as_ref().unwrap();
    let users = Api::<HumanUser>::namespaced(ctx.k8s.clone(), ns);
    let orgs = Api::<Organization>::all(ctx.k8s.clone());
    let secrets = Api::<Secret>::namespaced(ctx.k8s.clone(), ns);
    let recorder = ctx.build_recorder();

    finalizer(&users, HUMAN_USER_FINALIZER, user, |event| async {
        match event {
            Finalizer::Apply(user) => {
                info!("reconciling human user {}", user.name_any());

                let mut management = ctx.zitadel.builder().build_management_client().await?;

                let org = orgs.get_opt(&user.spec.organization_name).await?;
                let org = match org {
                    None => {
                        info!("organization {} not found", user.spec.organization_name);
                        recorder
                            .publish(
                                &Event {
                                    type_: EventType::Normal,
                                    reason: "Missing".to_string(),
                                    note: Some("Organization does not exist".to_string()),
                                    action: "NotCreated".to_string(),
                                    secondary: None,
                                },
                                &user.object_ref(&()),
                            )
                            .await?;
                        return Ok(Action::requeue(Duration::from_secs(requeue_secs())));
                    }
                    Some(org) => org,
                };

                let org_status = match org.get_status() {
                    Some(status) if org.is_ready() => status,
                    _ => {
                        info!("organization {} not ready", user.spec.organization_name);
                        recorder
                            .publish(
                                &Event {
                                    type_: EventType::Normal,
                                    reason: "NotCreated".to_string(),
                                    note: Some("Organization is not yet created".to_string()),
                                    action: "NotCreated".to_string(),
                                    secondary: None,
                                },
                                &user.object_ref(&()),
                            )
                            .await?;
                        return Ok(Action::requeue(Duration::from_secs(requeue_secs())));
                    }
                };

                // Check if user exists by ID (if we have status)
                if let Some(status) = &user.status {
                    let existing = management
                        .get_user_by_id(create_request_with_org_id(
                            GetUserByIdRequest {
                                id: status.id.clone(),
                            },
                            org_status.id.clone(),
                        ))
                        .await;

                    match existing {
                        Ok(resp) => {
                            if resp.into_inner().user.is_some() {
                                // User exists, no update support in v1 API
                                debug!("user exists, skipping (updates not supported in v1 API)");
                                return Ok(Action::requeue(Duration::from_secs(requeue_secs())));
                            }
                        }
                        Err(e) if e.code() == Code::NotFound => {
                            debug!("user not found by ID, will search by username");
                        }
                        Err(e) => return Err(Error::ZitadelError(e)),
                    }
                }

                // Search for existing user by username
                let existing_users = management
                    .list_users(create_request_with_org_id(
                        ListUsersRequest {
                            query: None,
                            sorting_column: 0,
                            queries: vec![SearchQuery {
                                query: Some(search_query::Query::UserNameQuery(UserNameQuery {
                                    user_name: user.spec.username.clone(),
                                    method: zitadel::api::zitadel::v1::TextQueryMethod::Equals.into(),
                                })),
                            }],
                        },
                        org_status.id.clone(),
                    ))
                    .await?
                    .into_inner()
                    .result;

                if let Some(existing_user) = existing_users.into_iter().next() {
                    debug!("user found by username, adopting");
                    patch_status(
                        &users,
                        user.as_ref(),
                        HumanUserStatus {
                            id: existing_user.id,
                            organization_id: org_status.id.clone(),
                            phase: HumanUserPhase::Ready,
                        },
                    )
                    .await?;

                    recorder
                        .publish(
                            &Event {
                                type_: EventType::Normal,
                                reason: "Creating".to_string(),
                                note: Some("Existing user adopted".to_string()),
                                action: "Adopted".to_string(),
                                secondary: None,
                            },
                            &user.object_ref(&()),
                        )
                        .await?;

                    return Ok(Action::requeue(Duration::from_secs(requeue_secs())));
                }

                // User doesn't exist, create it
                debug!("user not found, creating");

                // Optionally read password from secret
                let password = if let Some(secret_ref) = &user.spec.password_secret_ref {
                    let secret = secrets.get_opt(&secret_ref.name).await?;
                    if let Some(secret) = secret {
                        let key = secret_ref
                            .key
                            .clone()
                            .unwrap_or_else(|| user.metadata.name.clone().unwrap());
                        match secret.data.and_then(|d| d.get(&key).cloned()) {
                            Some(v) => Some(String::from_utf8(v.0).map_err(|e| {
                                Error::Other(format!(
                                    "password in secret '{}' key '{}' is not valid UTF-8: {}",
                                    secret_ref.name, key, e
                                ))
                            })?),
                            None => None,
                        }
                    } else {
                        warn!("password secret {} not found", secret_ref.name);
                        None
                    }
                } else {
                    None
                };

                let display_name = user.spec.profile.display_name.clone().unwrap_or_else(|| {
                    format!(
                        "{} {}",
                        user.spec.profile.given_name, user.spec.profile.family_name
                    )
                });

                let resp = management
                    .add_human_user(create_request_with_org_id(
                        AddHumanUserRequest {
                            user_name: user.spec.username.clone(),
                            profile: Some(
                                zitadel::api::zitadel::management::v1::add_human_user_request::Profile {
                                    first_name: user.spec.profile.given_name.clone(),
                                    last_name: user.spec.profile.family_name.clone(),
                                    nick_name: user.spec.profile.nick_name.clone().unwrap_or_default(),
                                    display_name,
                                    preferred_language: user
                                        .spec
                                        .profile
                                        .preferred_language
                                        .clone()
                                        .unwrap_or_else(|| "en".to_string()),
                                    gender: user.spec.profile.gender.as_ref().map(|g| g.into()).unwrap_or(0),
                                },
                            ),
                            email: Some(
                                zitadel::api::zitadel::management::v1::add_human_user_request::Email {
                                    email: user.spec.email.email.clone(),
                                    is_email_verified: user.spec.email.is_verified,
                                },
                            ),
                            phone: user.spec.phone.as_ref().map(|p| {
                                zitadel::api::zitadel::management::v1::add_human_user_request::Phone {
                                    phone: p.phone.clone(),
                                    is_phone_verified: p.is_verified,
                                }
                            }),
                            initial_password: password.unwrap_or_default(),
                        },
                        org_status.id.clone(),
                    ))
                    .await?
                    .into_inner();

                patch_status(
                    &users,
                    user.as_ref(),
                    HumanUserStatus {
                        id: resp.user_id,
                        organization_id: org_status.id.clone(),
                        phase: HumanUserPhase::Ready,
                    },
                )
                .await?;

                recorder
                    .publish(
                        &Event {
                            type_: EventType::Normal,
                            reason: "Created".to_string(),
                            note: Some("User created".to_string()),
                            action: "Creating".to_string(),
                            secondary: None,
                        },
                        &user.object_ref(&()),
                    )
                    .await?;

                Ok(Action::requeue(Duration::from_secs(requeue_secs())))
            }
            Finalizer::Cleanup(user) => {
                info!("cleaning up human user {}", user.name_any());

                let mut management = ctx.zitadel.builder().build_management_client().await?;

                if let Some(status) = &user.status {
                    let resp = management
                        .remove_user(create_request_with_org_id(
                            RemoveUserRequest {
                                id: status.id.clone(),
                            },
                            status.organization_id.clone(),
                        ))
                        .await;

                    match resp {
                        Ok(_) => {
                            debug!("user removed");

                            recorder
                                .publish(
                                    &Event {
                                        type_: EventType::Normal,
                                        reason: "DeleteRequested".to_string(),
                                        note: Some(format!("User {} was deleted", user.name_any())),
                                        action: "Deleting".to_string(),
                                        secondary: None,
                                    },
                                    &user.object_ref(&()),
                                )
                                .await?;
                        }
                        Err(e) if e.code() == Code::NotFound => {
                            debug!("user not found");
                        }
                        Err(e)
                            if e.code() == Code::PermissionDenied
                                && e.message().contains("doesn't exist") =>
                        {
                            debug!("organization not found, user does not exist");
                        }
                        Err(e) => return Err(Error::ZitadelError(e)),
                    }
                } else {
                    debug!("user never appears to have been created");
                }

                Ok(Action::await_change())
            }
        }
    })
    .await
    .map_err(|e| Error::FinalizerError(Box::new(e)))
}

fn error_policy(_: Arc<HumanUser>, error: &Error, _: Arc<OperatorContext>) -> Action {
    warn!("reconcile failed: {:?}", error);
    Action::requeue(Duration::from_secs(60))
}

pub async fn run(context: Arc<OperatorContext>) {
    let users = Api::<HumanUser>::all(context.k8s.clone());
    let orgs = Api::<Organization>::all(context.k8s.clone());
    let controller = Controller::new(users, Config::default().any_semantic());
    let store = controller.store();
    controller
        .watches_stream(
            metadata_watcher(orgs, Config::default()).touched_objects(),
            move |org| {
                store
                    .state()
                    .into_iter()
                    .filter(move |user| {
                        org.name().map(String::from).as_ref() == Some(&user.spec.organization_name)
                    })
                    .map(|user| ObjectRef::from_obj(&*user))
            },
        )
        .shutdown_on_signal()
        .run(reconcile, error_policy, context)
        .filter_map(|x| async move { std::result::Result::ok(x) })
        .for_each(|_| futures::future::ready(()))
        .await;
}
