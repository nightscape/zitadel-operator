use crate::{
    schema::{ActionHandler, ActionHandlerSpec, GrantRoles, Project},
    util::{create_request_with_org_id, GetStatus, IsReady},
    OperatorContext,
};
use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use kube::Api;
use serde_json::Value;
use std::sync::Arc;
use tonic::Code;
use tower_http::catch_panic::CatchPanicLayer;
use tracing::{debug, info, warn};
use zitadel::api::zitadel::management::v1::AddUserGrantRequest;

use super::{handler, signature};

/// Serves the Actions v2 targets the ActionHandler controller registers.
///
/// Never returns, like the controllers it runs beside.
pub async fn run(context: Arc<OperatorContext>) {
    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/handlers/{namespace}/{name}", post(serve))
        .layer(CatchPanicLayer::new())
        .with_state(context);

    let port = super::port();
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await
        .unwrap_or_else(|e| panic!("cannot listen on port {port}: {e}"));
    info!("Action handler server listening on port {port}");
    axum::serve(listener, app)
        .await
        .expect("action handler server stopped");
}

/// Answers one call from Zitadel.
///
/// This sits in the login path, so every failure answers with an empty body,
/// which is Zitadel's own way of saying "keep what you had": a broken handler
/// must cost a manipulation, never a login.
async fn serve(
    State(ctx): State<Arc<OperatorContext>>,
    Path((namespace, name)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let payload: Value = match serde_json::from_slice(&body) {
        Ok(payload) => payload,
        Err(e) => {
            warn!("action handler {namespace}/{name} received a non-JSON payload: {e}");
            return StatusCode::OK.into_response();
        }
    };

    let handlers = Api::<ActionHandler>::namespaced(ctx.k8s.clone(), &namespace);
    let resource = match handlers.get_opt(&name).await {
        Ok(Some(resource)) => resource,
        Ok(None) => {
            warn!("Zitadel called action handler {namespace}/{name}, which does not exist");
            return StatusCode::OK.into_response();
        }
        Err(e) => {
            warn!("cannot read action handler {namespace}/{name}: {e}");
            return StatusCode::OK.into_response();
        }
    };

    let kind = match resource.spec.validate() {
        Ok(kind) => kind,
        Err(e) => {
            warn!("action handler {namespace}/{name} is not usable: {e}");
            return StatusCode::OK.into_response();
        }
    };

    // A payload the operator cannot authenticate is still answered, but it must
    // not reach the grant effect: the endpoint is otherwise a way for anything
    // in the cluster to hand itself a role.
    let authentic = authenticate(&ctx, &namespace, &name, &headers, &body).await;

    let evaluation = handler::evaluate(&resource.spec, &payload);
    if let Some(error) = &evaluation.error {
        warn!("action handler {namespace}/{name} failed: {error}");
    }

    if evaluation.applies && authentic {
        if let Err(e) = grant(&ctx, &resource.spec, &namespace, &evaluation.payload).await {
            warn!("action handler {namespace}/{name} could not grant roles: {e}");
        }
    }

    match handler::answer(kind, &payload, &evaluation.payload) {
        Some(answer) => (StatusCode::OK, axum::Json(answer)).into_response(),
        None => StatusCode::OK.into_response(),
    }
}

async fn authenticate(
    ctx: &OperatorContext,
    namespace: &str,
    name: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> bool {
    let signing_key = match super::load_signing_key(ctx, namespace, name).await {
        Ok(Some(signing_key)) => signing_key,
        Ok(None) => {
            warn!("action handler {namespace}/{name} has no signing key yet, so the call is unverified");
            return false;
        }
        Err(e) => {
            warn!("cannot read the signing key for action handler {namespace}/{name}: {e}");
            return false;
        }
    };
    let Some(header) = headers
        .get(signature::SIGNING_HEADER)
        .and_then(|value| value.to_str().ok())
    else {
        warn!("call to action handler {namespace}/{name} carries no {} header", signature::SIGNING_HEADER);
        return false;
    };
    if signature::verify(header, body, &signing_key) {
        true
    } else {
        warn!("call to action handler {namespace}/{name} carries an invalid signature");
        false
    }
}

async fn grant(
    ctx: &OperatorContext,
    spec: &ActionHandlerSpec,
    namespace: &str,
    payload: &Value,
) -> Result<(), String> {
    let Some(GrantRoles {
        project_name,
        project_namespace,
        role_keys,
        user_id_from,
    }) = &spec.grant_roles
    else {
        return Ok(());
    };

    let user_id = handler::user_id(user_id_from, payload)?;

    let projects = Api::<Project>::namespaced(
        ctx.k8s.clone(),
        project_namespace.as_deref().unwrap_or(namespace),
    );
    let project = projects
        .get_opt(project_name)
        .await
        .map_err(|e| format!("cannot read project {project_name}: {e}"))?
        .ok_or_else(|| format!("project {project_name} does not exist"))?;
    let project_status = match project.get_status() {
        Some(status) if project.is_ready() => status,
        _ => return Err(format!("project {project_name} is not yet created")),
    };

    let mut management = ctx
        .zitadel
        .builder()
        .build_management_client()
        .await
        .map_err(|e| format!("{e:?}"))?;

    match management
        .add_user_grant(create_request_with_org_id(
            AddUserGrantRequest {
                user_id: user_id.clone(),
                project_id: project_status.id.clone(),
                project_grant_id: String::new(),
                role_keys: role_keys.clone(),
            },
            project_status.organization_id.clone(),
        ))
        .await
    {
        Ok(_) => debug!("granted {role_keys:?} on project {project_name} to user {user_id}"),
        // Zitadel may call a handler more than once for the same user, and the
        // grant it already holds is the state this asked for.
        Err(e) if e.code() == Code::AlreadyExists => {
            debug!("user {user_id} already holds a grant on project {project_name}")
        }
        Err(e) => return Err(format!("{e:?}")),
    }
    Ok(())
}
