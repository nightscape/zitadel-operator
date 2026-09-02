use crate::{
    actions::{self, ActionsApi},
    schema::{ActionCondition, ActionHandler, ActionHandlerPhase, ActionHandlerStatus, ConditionKind},
    util::{patch_status, requeue_secs},
    Error, OperatorContext, Result,
};
use futures::StreamExt;
use kube::{
    api::ListParams,
    runtime::{
        controller::Action,
        events::{Event, EventType},
        finalizer::{finalizer, Event as Finalizer},
        watcher::Config,
        Controller,
    },
    Api, Resource, ResourceExt,
};
use std::{sync::Arc, time::Duration};
use tracing::{debug, info, instrument, warn};

pub static ACTION_HANDLER_FINALIZER: &str = "actionhandler.zitadel.org";

/// Only a target Zitadel waits on can hand a manipulated payload back. Events
/// give the handler nothing to change, so they get the cheaper webhook target.
fn waits_for_body(kind: ConditionKind) -> bool {
    !matches!(kind, ConditionKind::Event)
}

/// Every target a condition should point at, derived from the whole set of
/// ActionHandlers rather than from the one being reconciled.
///
/// Zitadel's SetExecution replaces a condition's target list outright, so two
/// handlers sharing a condition would otherwise erase each other. Re-deriving
/// on each reconcile is also what keeps deleted handlers from leaving their
/// target id behind.
async fn execution_targets(
    ctx: &OperatorContext,
    condition: &ActionCondition,
    also: Option<&str>,
) -> Result<Vec<String>> {
    let mut targets: Vec<String> = Api::<ActionHandler>::all(ctx.k8s.clone())
        .list(&ListParams::default())
        .await?
        .into_iter()
        // A handler on its way out has stopped claiming its condition.
        .filter(|other| other.metadata.deletion_timestamp.is_none())
        .filter(|other| &other.spec.condition == condition)
        .filter_map(|other| other.status.map(|status| status.target_id))
        .filter(|target_id| !target_id.is_empty())
        .collect();
    targets.extend(also.map(String::from));
    targets.sort();
    targets.dedup();
    Ok(targets)
}

#[instrument(skip(ctx, ah))]
async fn reconcile(ah: Arc<ActionHandler>, ctx: Arc<OperatorContext>) -> Result<Action> {
    let ns = ah.metadata.namespace.as_ref().unwrap().clone();
    let handlers = Api::<ActionHandler>::namespaced(ctx.k8s.clone(), &ns);
    let recorder = ctx.build_recorder();

    finalizer(&handlers, ACTION_HANDLER_FINALIZER, ah, |event| async {
        match event {
            Finalizer::Apply(ah) => {
                info!("reconciling action handler {}", ah.name_any());

                let name = ah.name_any();
                let kind = ah.spec.validate().map_err(Error::Other)?;
                let endpoint = actions::endpoint(&ns, &name).map_err(Error::Other)?;
                let target_name = actions::target_name(&ns, &name);
                let api = ActionsApi::new(&ctx).await?;

                let existing = match &ah.status {
                    Some(status) if !status.target_id.is_empty() => {
                        api.get_target(&status.target_id).await?
                    }
                    _ => None,
                };
                let existing = match existing {
                    Some(target) => Some(target),
                    None => api.find_target_by_name(&target_name).await?,
                };

                let target_id = match existing {
                    Some(target) => {
                        if target.name != target_name || target.endpoint != endpoint {
                            debug!("action target changed, updating");
                            api.update_target(&target.id, &target_name, &endpoint, waits_for_body(kind))
                                .await?;
                        }
                        // Zitadel reveals a signing key only when it mints one, so a
                        // key that survived neither the cache nor the Secret can
                        // only be replaced.
                        if actions::load_signing_key(&ctx, &ns, &name).await?.is_none() {
                            let signing_key = api.rotate_signing_key(&target.id).await?;
                            actions::store_signing_key(&ctx, &ah, signing_key).await?;
                        }
                        target.id
                    }
                    None => {
                        debug!("action target not found, creating");
                        let (id, signing_key) = api
                            .create_target(&target_name, &endpoint, waits_for_body(kind))
                            .await?;
                        actions::store_signing_key(&ctx, &ah, signing_key).await?;

                        recorder
                            .publish(
                                &Event {
                                    type_: EventType::Normal,
                                    reason: "Created".to_string(),
                                    note: Some(format!("Action target {target_name} created")),
                                    action: "Creating".to_string(),
                                    secondary: None,
                                },
                                &ah.object_ref(&()),
                            )
                            .await?;

                        id
                    }
                };

                // A condition is an identity in Zitadel, not a property of the
                // execution, so a changed one leaves the execution it replaces
                // behind unless it is withdrawn by hand.
                if let Some(previous) = ah.status.as_ref().map(|s| &s.condition) {
                    if previous != &ah.spec.condition && previous != &ActionCondition::default() {
                        debug!("condition changed, rebuilding the execution it leaves");
                        let remaining = execution_targets(&ctx, previous, None).await?;
                        api.set_execution(previous, &remaining).await?;
                    }
                }

                let targets = execution_targets(&ctx, &ah.spec.condition, Some(&target_id)).await?;
                api.set_execution(&ah.spec.condition, &targets).await?;

                let unchanged = ah.status.as_ref().is_some_and(|status| {
                    status.target_id == target_id && status.condition == ah.spec.condition
                });
                if !unchanged {
                    patch_status(
                        &handlers,
                        ah.as_ref(),
                        ActionHandlerStatus {
                            target_id,
                            condition: ah.spec.condition.clone(),
                            phase: ActionHandlerPhase::Ready,
                        },
                    )
                    .await?;
                }

                Ok(Action::requeue(Duration::from_secs(requeue_secs())))
            }
            Finalizer::Cleanup(ah) => {
                info!("cleaning up action handler {}", ah.name_any());

                let name = ah.name_any();
                // The Secret goes with the handler that owns it.
                ctx.signing_keys.remove(&ns, &name);

                let Some(status) = &ah.status else {
                    debug!("action handler never appears to have been created");
                    return Ok(Action::await_change());
                };

                let api = ActionsApi::new(&ctx).await?;
                let remaining = execution_targets(&ctx, &status.condition, None).await?;
                api.set_execution(&status.condition, &remaining).await?;
                api.delete_target(&status.target_id).await?;

                recorder
                    .publish(
                        &Event {
                            type_: EventType::Normal,
                            reason: "DeleteRequested".to_string(),
                            note: Some(format!("Action handler {name} was deleted")),
                            action: "Deleting".to_string(),
                            secondary: None,
                        },
                        &ah.object_ref(&()),
                    )
                    .await?;

                Ok(Action::await_change())
            }
        }
    })
    .await
    .map_err(|e| Error::FinalizerError(Box::new(e)))
}

fn error_policy(_: Arc<ActionHandler>, error: &Error, _: Arc<OperatorContext>) -> Action {
    warn!("reconcile failed: {:?}", error);
    Action::requeue(Duration::from_secs(60))
}

pub async fn run(context: Arc<OperatorContext>) {
    let handlers = Api::<ActionHandler>::all(context.k8s.clone());
    Controller::new(handlers, Config::default().any_semantic())
        .shutdown_on_signal()
        .run(reconcile, error_policy, context)
        .filter_map(|x| async move { std::result::Result::ok(x) })
        .for_each(|_| futures::future::ready(()))
        .await;
}
