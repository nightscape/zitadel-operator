use crate::{
    schema::{MachineUser, MachineUserPhase, MachineUserStatus, Organization},
    util::{create_request_with_org_id, patch_status, requeue_secs, GetStatus, IsReady},
    Error, OperatorContext, Result,
};
use futures::StreamExt;
use k8s_openapi::api::core::v1::Secret;
use kube::{
    api::ObjectMeta,
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
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use tonic::Code;
use tracing::{debug, info, instrument, warn};
use zitadel::api::zitadel::{
    authn::v1::KeyType,
    management::v1::{
        AddMachineKeyRequest, AddMachineUserRequest, AddOrgMemberRequest, GetUserByIdRequest,
        ListOrgMembersRequest, ListUsersRequest, RemoveMachineKeyRequest, RemoveUserRequest,
        UpdateOrgMemberRequest,
    },
    user::v1::{search_query, AccessTokenType, SearchQuery, UserNameQuery},
};

pub static MACHINE_USER_FINALIZER: &str = "machineuser.zitadel.org";

#[instrument(skip(ctx, mu))]
async fn reconcile(mu: Arc<MachineUser>, ctx: Arc<OperatorContext>) -> Result<Action> {
    let ns = mu.metadata.namespace.as_ref().unwrap();
    let machine_users = Api::<MachineUser>::namespaced(ctx.k8s.clone(), ns);
    let orgs = Api::<Organization>::all(ctx.k8s.clone());
    let secrets = Api::<Secret>::namespaced(ctx.k8s.clone(), ns);
    let recorder = ctx.build_recorder();

    finalizer(&machine_users, MACHINE_USER_FINALIZER, mu, |event| async {
        match event {
            Finalizer::Apply(mu) => {
                info!("reconciling machine user {}", mu.name_any());

                let mut management = ctx.zitadel.builder().build_management_client().await?;

                // --- resolve parent org (mirrors human_user) ---
                let org = match orgs.get_opt(&mu.spec.organization_name).await? {
                    None => {
                        info!("organization {} not found", mu.spec.organization_name);
                        recorder
                            .publish(
                                &Event {
                                    type_: EventType::Normal,
                                    reason: "Missing".to_string(),
                                    note: Some("Organization does not exist".to_string()),
                                    action: "NotCreated".to_string(),
                                    secondary: None,
                                },
                                &mu.object_ref(&()),
                            )
                            .await?;
                        return Ok(Action::requeue(Duration::from_secs(requeue_secs())));
                    }
                    Some(org) => org,
                };
                let org_status = match org.get_status() {
                    Some(status) if org.is_ready() => status,
                    _ => {
                        info!("organization {} not ready", mu.spec.organization_name);
                        return Ok(Action::requeue(Duration::from_secs(requeue_secs())));
                    }
                };
                let org_id = org_status.id.clone();

                // --- 1. resolve or create the machine user -> user_id ---
                let mut user_id: Option<String> = None;

                if let Some(status) = &mu.status {
                    if !status.id.is_empty() {
                        match management
                            .get_user_by_id(create_request_with_org_id(
                                GetUserByIdRequest { id: status.id.clone() },
                                org_id.clone(),
                            ))
                            .await
                        {
                            Ok(resp) => {
                                if resp.into_inner().user.is_some() {
                                    user_id = Some(status.id.clone());
                                }
                            }
                            Err(e) if e.code() == Code::NotFound => {
                                debug!("machine user not found by id, will search by username");
                            }
                            Err(e) => return Err(Error::ZitadelError(e)),
                        }
                    }
                }

                if user_id.is_none() {
                    let existing = management
                        .list_users(create_request_with_org_id(
                            ListUsersRequest {
                                query: None,
                                sorting_column: 0,
                                queries: vec![SearchQuery {
                                    query: Some(search_query::Query::UserNameQuery(UserNameQuery {
                                        user_name: mu.spec.username.clone(),
                                        method: zitadel::api::zitadel::v1::TextQueryMethod::Equals.into(),
                                    })),
                                }],
                            },
                            org_id.clone(),
                        ))
                        .await?
                        .into_inner()
                        .result;
                    if let Some(u) = existing.into_iter().next() {
                        debug!("machine user found by username, adopting");
                        user_id = Some(u.id);
                    }
                }

                if user_id.is_none() {
                    debug!("machine user not found, creating");
                    let resp = management
                        .add_machine_user(create_request_with_org_id(
                            AddMachineUserRequest {
                                user_name: mu.spec.username.clone(),
                                name: mu.spec.name.clone(),
                                description: mu.spec.description.clone().unwrap_or_default(),
                                access_token_type: AccessTokenType::Bearer as i32,
                                user_id: None,
                            },
                            org_id.clone(),
                        ))
                        .await?
                        .into_inner();
                    user_id = Some(resp.user_id);
                    recorder
                        .publish(
                            &Event {
                                type_: EventType::Normal,
                                reason: "Created".to_string(),
                                note: Some("Machine user created".to_string()),
                                action: "Creating".to_string(),
                                secondary: None,
                            },
                            &mu.object_ref(&()),
                        )
                        .await?;
                }
                let user_id = user_id.unwrap();

                // persist id early (idempotency); carry existing key_id forward
                let current_key_id = mu.status.as_ref().map(|s| s.key_id.clone()).unwrap_or_default();
                patch_status(
                    &machine_users,
                    mu.as_ref(),
                    MachineUserStatus {
                        id: user_id.clone(),
                        organization_id: org_id.clone(),
                        key_id: current_key_id.clone(),
                        phase: MachineUserPhase::Ready,
                    },
                )
                .await?;

                // --- 2. ensure org manager membership with the requested roles ---
                let members = management
                    .list_org_members(create_request_with_org_id(
                        ListOrgMembersRequest { query: None, queries: vec![] },
                        org_id.clone(),
                    ))
                    .await?
                    .into_inner()
                    .result;
                let desired = mu.spec.manager_roles.clone();
                let current = members.iter().find(|m| m.user_id == user_id);
                match current {
                    None => {
                        match management
                            .add_org_member(create_request_with_org_id(
                                AddOrgMemberRequest { user_id: user_id.clone(), roles: desired.clone() },
                                org_id.clone(),
                            ))
                            .await
                        {
                            Ok(_) => {}
                            // concurrent reconcile already added it
                            Err(e) if e.code() == Code::AlreadyExists => {}
                            Err(e) => return Err(Error::ZitadelError(e)),
                        }
                    }
                    Some(m) if !desired.iter().all(|r| m.roles.contains(r)) => {
                        management
                            .update_org_member(create_request_with_org_id(
                                UpdateOrgMemberRequest { user_id: user_id.clone(), roles: desired.clone() },
                                org_id.clone(),
                            ))
                            .await?;
                    }
                    Some(_) => {}
                }

                // --- 3. mint machine key -> write Secret (crash-safe ordering) ---
                let secret_name = mu.spec.secret_name.clone();
                let mut key_id = current_key_id;

                if secrets.get_opt(&secret_name).await?.is_none() {
                    // Secret absent. If we already recorded a key_id, this is a re-key
                    // (crash between mint and Secret write, or deliberate Secret deletion):
                    // remove the old key before minting a fresh one.
                    if !key_id.is_empty() {
                        match management
                            .remove_machine_key(create_request_with_org_id(
                                RemoveMachineKeyRequest {
                                    user_id: user_id.clone(),
                                    key_id: key_id.clone(),
                                },
                                org_id.clone(),
                            ))
                            .await
                        {
                            Ok(_) => debug!("removed stale machine key {}", key_id),
                            Err(e) if e.code() == Code::NotFound => {}
                            Err(e) => return Err(Error::ZitadelError(e)),
                        }
                    }

                    let resp = management
                        .add_machine_key(create_request_with_org_id(
                            AddMachineKeyRequest {
                                user_id: user_id.clone(),
                                r#type: KeyType::Json as i32,
                                // expiry/rotation intentionally not wired in V1.5b
                                expiration_date: None,
                                public_key: vec![],
                            },
                            org_id.clone(),
                        ))
                        .await?
                        .into_inner();
                    key_id = resp.key_id.clone();

                    // Persist key_id BEFORE writing the Secret: if we crash here, the next
                    // reconcile sees "Secret absent + key_id set" and re-keys (removing this
                    // now-orphaned key), which self-heals.
                    patch_status(
                        &machine_users,
                        mu.as_ref(),
                        MachineUserStatus {
                            id: user_id.clone(),
                            organization_id: org_id.clone(),
                            key_id: key_id.clone(),
                            phase: MachineUserPhase::Ready,
                        },
                    )
                    .await?;

                    let key_json = String::from_utf8(resp.key_details).map_err(|e| {
                        Error::Other(format!("machine key JSON is not valid UTF-8: {e}"))
                    })?;
                    let mut data = BTreeMap::new();
                    data.insert(mu.spec.secret_key.clone(), key_json);
                    let secret = Secret {
                        metadata: ObjectMeta {
                            name: Some(secret_name.clone()),
                            namespace: mu.metadata.namespace.clone(),
                            owner_references: Some(vec![mu.controller_owner_ref(&()).unwrap()]),
                            ..Default::default()
                        },
                        string_data: Some(data),
                        ..Default::default()
                    };
                    secrets.create(&Default::default(), &secret).await?;

                    recorder
                        .publish(
                            &Event {
                                type_: EventType::Normal,
                                reason: "KeyCreated".to_string(),
                                note: Some(format!("Machine key written to secret {secret_name}")),
                                action: "Creating".to_string(),
                                secondary: None,
                            },
                            &mu.object_ref(&()),
                        )
                        .await?;
                }

                patch_status(
                    &machine_users,
                    mu.as_ref(),
                    MachineUserStatus {
                        id: user_id,
                        organization_id: org_id,
                        key_id,
                        phase: MachineUserPhase::Ready,
                    },
                )
                .await?;

                Ok(Action::requeue(Duration::from_secs(requeue_secs())))
            }
            Finalizer::Cleanup(mu) => {
                info!("cleaning up machine user {}", mu.name_any());

                let mut management = ctx.zitadel.builder().build_management_client().await?;

                if let Some(status) = &mu.status {
                    if !status.id.is_empty() {
                        // Remove the user; the key goes with it, and the Secret is
                        // garbage-collected via its owner reference.
                        let resp = management
                            .remove_user(create_request_with_org_id(
                                RemoveUserRequest { id: status.id.clone() },
                                status.organization_id.clone(),
                            ))
                            .await;
                        match resp {
                            Ok(_) => debug!("machine user removed"),
                            Err(e) if e.code() == Code::NotFound => {}
                            Err(e)
                                if e.code() == Code::PermissionDenied
                                    && e.message().contains("doesn't exist") => {}
                            Err(e) => return Err(Error::ZitadelError(e)),
                        }
                    }
                } else {
                    debug!("machine user never appears to have been created");
                }

                Ok(Action::await_change())
            }
        }
    })
    .await
    .map_err(|e| Error::FinalizerError(Box::new(e)))
}

fn error_policy(_: Arc<MachineUser>, error: &Error, _: Arc<OperatorContext>) -> Action {
    warn!("reconcile failed: {:?}", error);
    Action::requeue(Duration::from_secs(60))
}

pub async fn run(context: Arc<OperatorContext>) {
    let machine_users = Api::<MachineUser>::all(context.k8s.clone());
    let orgs = Api::<Organization>::all(context.k8s.clone());
    let controller = Controller::new(machine_users, Config::default().any_semantic());
    let store = controller.store();
    controller
        .watches_stream(
            metadata_watcher(orgs, Config::default()).touched_objects(),
            move |org| {
                store
                    .state()
                    .into_iter()
                    .filter(move |mu| {
                        org.name().map(String::from).as_ref() == Some(&mu.spec.organization_name)
                    })
                    .map(|mu| ObjectRef::from_obj(&*mu))
            },
        )
        .shutdown_on_signal()
        .run(reconcile, error_policy, context)
        .filter_map(|x| async move { std::result::Result::ok(x) })
        .for_each(|_| futures::future::ready(()))
        .await;
}
