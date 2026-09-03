//! Proves against a real Zitadel that an IdentityProvider reaches the login
//! screen of an organization the operator has just created.
//!
//! A brand-new organization inherits the instance default login policy, and
//! Zitadel refuses to attach a provider to an inherited policy. The negative
//! control at the start reproduces that refusal, so a passing test cannot be a
//! test that proved nothing.
//!
//! Not covered: withdrawing a provider from an organization whose policy is
//! removed mid-reconcile. A provider that was never offered leaves the reconcile
//! at its early return, so these cases prove the outcome and never reach the
//! arm that handles a withdrawal from an inheriting organization.

mod e2e;

use anyhow::{anyhow, Context, Result};
use e2e::TestFixture;
use kube::api::{Patch, PatchParams};
use kube::{Api, Resource};
use serde_json::json;
use std::{collections::HashMap, sync::Arc, time::Duration};
use tonic::{Code, Request};
use zitadel::api::zitadel::{
    idp::v1::IdpOwnerType,
    management::v1::{
        AddIdpToLoginPolicyRequest, GetLoginPolicyRequest, ListLoginPolicyIdPsRequest,
    },
};
use zitadel_operator::{
    controllers::identity_provider,
    schema::{IdentityProvider, Organization},
    OperatorContext,
};

const NAMESPACE: &str = "default";

fn with_org<T>(req: T, org_id: &str) -> Request<T> {
    let mut req = Request::new(req);
    req.metadata_mut().insert("x-zitadel-orgid", org_id.parse().unwrap());
    req
}

/// Both cases share one test, because the fixture's port forward dies with the
/// runtime that created it and a second `#[tokio::test]` would find ZITADEL
/// unreachable.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn login_screen_membership_on_a_new_organization() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();

    let fixture = TestFixture::get_or_init().await;

    let ctx = Arc::new(OperatorContext {
        k8s: fixture.k8s_client.clone(),
        zitadel: fixture.zitadel_builder.clone(),
        operator_user_id: fixture.operator_user_id.clone(),
        custom_headers: HashMap::new(),
        signing_keys: Default::default(),
    });
    tokio::spawn(identity_provider::run(ctx.clone()));

    the_provider_is_offered(fixture)
        .await
        .context("a provider asked onto the login screen of a new organization")?;
    an_inheriting_org_is_left_alone(fixture)
        .await
        .context("a provider kept off the login screen of a new organization")?;

    Ok(())
}

async fn the_provider_is_offered(fixture: &TestFixture) -> Result<()> {
    let mut management = fixture
        .zitadel_builder
        .builder()
        .build_management_client()
        .await
        .map_err(|e| anyhow!("{e:?}"))?;

    let suffix = std::process::id();
    let org_name = format!("idp-policy-{suffix}");
    let idp_name = format!("partner-{suffix}");

    let orgs: Api<Organization> = Api::all(fixture.k8s_client.clone());
    orgs.patch(
        &org_name,
        &PatchParams::apply("e2e").force(),
        &Patch::Apply(json!({
            "apiVersion": Organization::api_version(&()),
            "kind": "Organization",
            "metadata": { "name": org_name },
            "spec": { "name": org_name },
        })),
    )
    .await?;

    let org_id = wait_for(Duration::from_secs(120), || async {
        Ok(orgs
            .get(&org_name)
            .await?
            .status
            .map(|status| status.id))
    })
    .await
    .context("the operator never created the organization")?;

    // Negative control: this is the call the provider reconcile makes, and on a
    // freshly created organization Zitadel refuses it. If it ever starts
    // succeeding here, the rest of this test no longer proves anything.
    let refused = management
        .add_idp_to_login_policy(with_org(
            AddIdpToLoginPolicyRequest {
                idp_id: "0".to_string(),
                owner_type: IdpOwnerType::Org.into(),
            },
            &org_id,
        ))
        .await
        .expect_err("Zitadel attached a provider to an inherited login policy");
    assert_eq!(refused.code(), Code::NotFound, "unexpected refusal: {refused}");
    assert!(
        refused.message().contains("Org-Ffgw2"),
        "the organization did not start out inheriting the instance default: {refused}"
    );
    assert!(
        login_policy_is_default(&mut management, &org_id).await?,
        "the organization already owned a login policy before the operator ran"
    );

    let idps: Api<IdentityProvider> = Api::namespaced(fixture.k8s_client.clone(), NAMESPACE);
    idps.patch(
        &idp_name,
        &PatchParams::apply("e2e").force(),
        &Patch::Apply(json!({
            "apiVersion": IdentityProvider::api_version(&()),
            "kind": "IdentityProvider",
            "metadata": { "name": idp_name, "namespace": NAMESPACE },
            "spec": {
                "name": idp_name,
                "organizationName": org_name,
                "showOnLoginScreen": true,
                "jwt": {
                    "issuer": "https://example.com",
                    "jwtEndpoint": "https://example.com/jwt",
                    "keysEndpoint": "https://example.com/keys",
                    "headerName": "x-e2e-token",
                },
            },
        })),
    )
    .await?;

    let idp_id = wait_for(Duration::from_secs(120), || async {
        Ok(idps.get(&idp_name).await?.status.map(|status| status.id))
    })
    .await
    .context("the operator never created the identity provider")?;

    wait_for(Duration::from_secs(120), || {
        let mut management = management.clone();
        let org_id = org_id.clone();
        let idp_id = idp_id.clone();
        async move {
            Ok(linked(&mut management, &org_id, &idp_id).await?.then_some(()))
        }
    })
    .await
    .context("the provider never reached the organization's login screen")?;

    assert!(
        !login_policy_is_default(&mut management, &org_id).await?,
        "the provider is on the login policy but the organization still inherits one"
    );

    // Withdrawing the provider must not hand the policy back: the organization
    // keeps whatever login behaviour it now has.
    idps.patch(
        &idp_name,
        &PatchParams::default(),
        &Patch::Merge(json!({ "spec": { "showOnLoginScreen": false } })),
    )
    .await?;

    wait_for(Duration::from_secs(120), || {
        let mut management = management.clone();
        let org_id = org_id.clone();
        let idp_id = idp_id.clone();
        async move {
            Ok((!linked(&mut management, &org_id, &idp_id).await?).then_some(()))
        }
    })
    .await
    .context("the provider was never withdrawn from the login screen")?;

    assert!(
        !login_policy_is_default(&mut management, &org_id).await?,
        "withdrawing the provider sent the organization back to the inherited policy"
    );

    Ok(())
}

/// An organization that inherits the instance default offers no provider on its
/// login screen already, so the operator has nothing to do and must not report a
/// failure. This is the shape of a tenant that declares a partner IdP with the
/// button off, which is how the first one was configured.
async fn an_inheriting_org_is_left_alone(fixture: &TestFixture) -> Result<()> {
    let mut management = fixture
        .zitadel_builder
        .builder()
        .build_management_client()
        .await
        .map_err(|e| anyhow!("{e:?}"))?;

    let suffix = std::process::id();
    let org_name = format!("idp-inherit-{suffix}");
    let idp_name = format!("hidden-partner-{suffix}");

    let orgs: Api<Organization> = Api::all(fixture.k8s_client.clone());
    orgs.patch(
        &org_name,
        &PatchParams::apply("e2e").force(),
        &Patch::Apply(json!({
            "apiVersion": Organization::api_version(&()),
            "kind": "Organization",
            "metadata": { "name": org_name },
            "spec": { "name": org_name },
        })),
    )
    .await?;

    let org_id = wait_for(Duration::from_secs(120), || async {
        Ok(orgs.get(&org_name).await?.status.map(|status| status.id))
    })
    .await
    .context("the operator never created the organization")?;

    assert!(
        login_policy_is_default(&mut management, &org_id).await?,
        "the organization did not start out inheriting the instance default"
    );

    let idps: Api<IdentityProvider> = Api::namespaced(fixture.k8s_client.clone(), NAMESPACE);
    idps.patch(
        &idp_name,
        &PatchParams::apply("e2e").force(),
        &Patch::Apply(json!({
            "apiVersion": IdentityProvider::api_version(&()),
            "kind": "IdentityProvider",
            "metadata": { "name": idp_name, "namespace": NAMESPACE },
            "spec": {
                "name": idp_name,
                "organizationName": org_name,
                "showOnLoginScreen": false,
                "jwt": {
                    "issuer": "https://example.com",
                    "jwtEndpoint": "https://example.com/jwt",
                    "keysEndpoint": "https://example.com/keys",
                    "headerName": "x-e2e-token",
                },
            },
        })),
    )
    .await?;

    let idp_id = wait_for(Duration::from_secs(120), || async {
        Ok(idps.get(&idp_name).await?.status.map(|status| status.id))
    })
    .await
    .context("the operator never created the identity provider")?;

    // The reconcile has to settle rather than fail forever, so give it several
    // passes and then read what it left behind.
    tokio::time::sleep(Duration::from_secs(20)).await;

    assert!(
        login_policy_is_default(&mut management, &org_id).await?,
        "the operator gave the organization a login policy it never asked for"
    );

    let events: Api<k8s_openapi::api::core::v1::Event> =
        Api::namespaced(fixture.k8s_client.clone(), NAMESPACE);
    let complaints: Vec<String> = events
        .list(&kube::api::ListParams::default())
        .await?
        .items
        .into_iter()
        .filter(|event| {
            event.involved_object.name.as_deref() == Some(idp_name.as_str())
                && event.type_.as_deref() == Some("Warning")
        })
        .filter_map(|event| event.message)
        .collect();
    assert!(
        complaints.is_empty(),
        "the operator reported a failure it had no reason to: {complaints:?}"
    );

    assert!(
        !linked(&mut management, &org_id, &idp_id).await?,
        "the provider reached the login screen despite showOnLoginScreen: false"
    );

    Ok(())
}

type Management = zitadel::api::zitadel::management::v1::management_service_client::ManagementServiceClient<
    tonic::service::interceptor::InterceptedService<
        tonic::transport::Channel,
        zitadel_operator::CustomHeaderInterceptor,
    >,
>;

async fn login_policy_is_default(management: &mut Management, org_id: &str) -> Result<bool> {
    Ok(management
        .get_login_policy(with_org(GetLoginPolicyRequest {}, org_id))
        .await?
        .into_inner()
        .policy
        .expect("an organization always resolves to a login policy")
        .is_default)
}

async fn linked(management: &mut Management, org_id: &str, idp_id: &str) -> Result<bool> {
    Ok(management
        .list_login_policy_id_ps(with_org(ListLoginPolicyIdPsRequest { query: None }, org_id))
        .await?
        .into_inner()
        .result
        .iter()
        .any(|link| link.idp_id == idp_id))
}

/// Polls until the closure yields a value, so a failure names what never
/// happened rather than a bare timeout.
async fn wait_for<T, F, Fut>(timeout: Duration, mut f: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<Option<T>>>,
{
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if let Some(value) = f().await? {
            return Ok(value);
        }
        if std::time::Instant::now() >= deadline {
            return Err(anyhow!("timed out after {timeout:?}"));
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}
