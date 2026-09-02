//! Proves the Actions v2 handler against a real Zitadel: the operator registers
//! a target and an execution, Zitadel calls back into the operator, and the
//! transform repairs a request Zitadel would otherwise reject.
//!
//! The negative control at the end is the point. It reproduces the failure this
//! feature exists for — Zitadel refusing its own `AddHumanUser` because the IdP
//! link carries no username — so a passing test cannot be a test that proved
//! nothing.

mod e2e;

use anyhow::{anyhow, Context, Result};
use e2e::TestFixture;
use kube::{
    api::{DeleteParams, Patch, PatchParams},
    Api,
};
use serde_json::{json, Value};
use std::{collections::HashMap, sync::Arc, time::Duration};
use zitadel::api::zitadel::{
    idp::v1::IdpStylingType,
    management::v1::AddOrgJwtidpRequest,
    user::v2::{AddHumanUserRequest, IdpLink, ListIdpLinksRequest, SetHumanEmail, SetHumanProfile},
};
use zitadel_operator::{
    actions,
    controllers::action_handler,
    schema::{ActionHandler, ActionHandlerSpec},
    OperatorContext,
};

const NAMESPACE: &str = "default";
const HANDLER: &str = "fill-idp-username";
const PORT: u16 = 18090;

const FILL_USERNAME: &str = r#"
if (.request.idpLinks[0].userName // "") == "" then
  .request.idpLinks[0].userName = .request.idpLinks[0].userId
else . end
"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn action_handler_repairs_a_request_zitadel_would_reject() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();

    let fixture = TestFixture::get_or_init().await;

    // Zitadel runs as a pod inside the k3s container and has to reach this test
    // process on the host, which it can only do through the container's gateway.
    let host = docker_gateway().context("cannot determine the docker gateway")?;
    std::env::set_var("ACTION_HANDLER_PORT", PORT.to_string());
    std::env::set_var("ACTION_HANDLER_URL", format!("http://{host}:{PORT}"));

    let ctx = Arc::new(OperatorContext {
        k8s: fixture.k8s_client.clone(),
        zitadel: fixture.zitadel_builder.clone(),
        operator_user_id: fixture.operator_user_id.clone(),
        custom_headers: HashMap::new(),
        signing_keys: Default::default(),
    });
    tokio::spawn(action_handler::run(ctx.clone()));
    tokio::spawn(actions::run(ctx.clone()));
    await_health(host.as_str()).await?;

    let idp_id = create_jwt_idp(fixture).await?;

    let handlers: Api<ActionHandler> = Api::namespaced(fixture.k8s_client.clone(), NAMESPACE);
    let _ = handlers.delete(HANDLER, &DeleteParams::default()).await;
    apply_handler(&handlers).await?;
    let status = await_ready(&handlers).await?;

    let target_id = status["targetId"].as_str().unwrap().to_string();
    assert!(!target_id.is_empty(), "handler became ready without a target");

    let api = actions::ActionsApi::new(&ctx).await.map_err(|e| anyhow!("{e:?}"))?;
    let target = api
        .get_target(&target_id)
        .await
        .map_err(|e| anyhow!("{e:?}"))?
        .ok_or_else(|| anyhow!("Zitadel does not know target {target_id}"))?;
    assert_eq!(target.endpoint, format!("http://{host}:{PORT}/handlers/{NAMESPACE}/{HANDLER}"));
    assert_eq!(target.name, format!("k8s/{NAMESPACE}/{HANDLER}"));

    // The operator must hold the signing key, or every call it gets is
    // unauthenticated and the grant effect would be unreachable.
    assert!(
        ctx.signing_keys.get(NAMESPACE, HANDLER).is_some(),
        "no signing key cached for the handler"
    );

    let created = add_human_user(fixture, &idp_id, "with-handler").await;
    let created = match created {
        Ok(created) => created,
        Err(e) => panic!(
            "the handler did not repair the request: {e}\n\
             (if this is a connection error, Zitadel could not reach {host}:{PORT})"
        ),
    };

    // Succeeding only proves something made the request valid. Reading the link
    // back proves the transform's own output landed: Zitadel stored the external
    // user id as the username, which is what the jq program put there and what
    // nothing else in this flow would have written.
    let stored = idp_link_username(fixture, &created.user_id).await?;
    assert_eq!(
        stored, created.external_user_id,
        "the IdP link username is not what the transform wrote"
    );

    // Negative control: without the handler the very same call fails, which is
    // both the bug this feature fixes and proof that deletion withdraws the
    // execution rather than leaving it behind.
    handlers.delete(HANDLER, &DeleteParams::default()).await?;
    await_gone(&handlers).await?;

    let rejected = add_human_user(fixture, &idp_id, "without-handler")
        .await
        .expect_err("Zitadel accepted an IdP link with no username");
    assert!(
        rejected.to_string().contains("IDPLink.UserName"),
        "expected Zitadel to reject the empty IdP link username, got: {rejected}"
    );

    assert!(
        api.get_target(&target_id)
            .await
            .map_err(|e| anyhow!("{e:?}"))?
            .is_none(),
        "target {target_id} outlived its ActionHandler"
    );

    Ok(())
}

async fn apply_handler(handlers: &Api<ActionHandler>) -> Result<()> {
    let spec: ActionHandlerSpec = serde_json::from_value(json!({
        "condition": { "request": { "method": "/zitadel.user.v2.UserService/AddHumanUser" } },
        "transform": FILL_USERNAME,
    }))?;
    let mut handler = ActionHandler::new(HANDLER, spec);
    handler.metadata.namespace = Some(NAMESPACE.to_string());
    handlers
        .patch(
            HANDLER,
            &PatchParams::apply("e2e").force(),
            &Patch::Apply(&handler),
        )
        .await?;
    Ok(())
}

async fn create_jwt_idp(fixture: &TestFixture) -> Result<String> {
    let mut management = fixture
        .zitadel_builder
        .builder()
        .build_management_client()
        .await
        .map_err(|e| anyhow!("{e:?}"))?;
    let resp = management
        .add_org_jwtidp(AddOrgJwtidpRequest {
            name: format!("e2e-actions-{}", std::process::id()),
            styling_type: IdpStylingType::StylingTypeUnspecified.into(),
            jwt_endpoint: "https://example.com/jwt".to_string(),
            issuer: "https://example.com".to_string(),
            keys_endpoint: "https://example.com/keys".to_string(),
            header_name: "x-e2e-token".to_string(),
            auto_register: true,
        })
        .await?;
    Ok(resp.into_inner().idp_id)
}

/// The call the handler exists for: an IdP link with no username, which is
/// exactly what Zitadel's own Login V2 sends when the token carries no
/// `preferred_username`.
#[derive(Debug)]
struct CreatedUser {
    user_id: String,
    external_user_id: String,
}

async fn add_human_user(fixture: &TestFixture, idp_id: &str, tag: &str) -> Result<CreatedUser> {
    let mut users = fixture
        .zitadel_builder
        .builder()
        .build_user_client()
        .await
        .map_err(|e| anyhow!("{e:?}"))?;
    let unique = format!(
        "{tag}-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    );
    let external_user_id = format!("external-{unique}");
    let resp = users
        .add_human_user(AddHumanUserRequest {
            username: Some(format!("{unique}@example.com")),
            profile: Some(SetHumanProfile {
                given_name: "E2E".to_string(),
                family_name: "Federated".to_string(),
                ..Default::default()
            }),
            email: Some(SetHumanEmail {
                email: format!("{unique}@example.com"),
                verification: None,
            }),
            idp_links: vec![IdpLink {
                idp_id: idp_id.to_string(),
                user_id: external_user_id.clone(),
                user_name: String::new(),
            }],
            ..Default::default()
        })
        .await
        .map_err(|e| anyhow!("{}", e.message()))?;
    Ok(CreatedUser {
        user_id: resp.into_inner().user_id,
        external_user_id,
    })
}

/// The username Zitadel stored on the user's single IdP link.
async fn idp_link_username(fixture: &TestFixture, user_id: &str) -> Result<String> {
    let mut users = fixture
        .zitadel_builder
        .builder()
        .build_user_client()
        .await
        .map_err(|e| anyhow!("{e:?}"))?;
    let links = users
        .list_idp_links(ListIdpLinksRequest {
            user_id: user_id.to_string(),
            query: None,
        })
        .await
        .map_err(|e| anyhow!("{}", e.message()))?
        .into_inner()
        .result;
    match &links[..] {
        [link] => Ok(link.user_name.clone()),
        other => Err(anyhow!("expected one IdP link, found {}", other.len())),
    }
}

async fn await_ready(handlers: &Api<ActionHandler>) -> Result<Value> {
    for _ in 0..60 {
        if let Some(handler) = handlers.get_opt(HANDLER).await? {
            if let Some(status) = handler.status {
                return Ok(serde_json::to_value(status)?);
            }
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    Err(anyhow!("ActionHandler {HANDLER} never reported a status"))
}

async fn await_gone(handlers: &Api<ActionHandler>) -> Result<()> {
    for _ in 0..60 {
        if handlers.get_opt(HANDLER).await?.is_none() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    Err(anyhow!("ActionHandler {HANDLER} was never removed"))
}

async fn await_health(host: &str) -> Result<()> {
    let client = reqwest::Client::new();
    for _ in 0..30 {
        if client
            .get(format!("http://{host}:{PORT}/healthz"))
            .send()
            .await
            .is_ok()
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    Err(anyhow!("the action handler server never came up on {host}:{PORT}"))
}

/// Address of the host as seen from inside the k3s container, and therefore
/// from the Zitadel pod that NATs out through it.
fn docker_gateway() -> Result<String> {
    let output = std::process::Command::new("docker")
        .args([
            "network",
            "inspect",
            "bridge",
            "-f",
            "{{range .IPAM.Config}}{{.Gateway}}{{end}}",
        ])
        .output()?;
    let gateway = String::from_utf8(output.stdout)?.trim().to_string();
    if gateway.is_empty() {
        return Err(anyhow!("docker's bridge network reports no gateway"));
    }
    Ok(gateway)
}
