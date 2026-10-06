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
    idp::v1::{azure_ad_tenant, provider_config, IdpOwnerType, IdpStylingType, Options, ProviderType},
    management::v1::{
        AddAzureAdProviderRequest, AddIdpToLoginPolicyRequest, AddOrgJwtidpRequest, GetLoginPolicyRequest,
        GetProviderByIdRequest, ListLoginPolicyIdPsRequest,
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
    an_azure_ad_provider_is_managed_declaratively(fixture)
        .await
        .context("an azureAd provider created, rotated and deleted")?;
    an_existing_azure_ad_provider_is_adopted(fixture)
        .await
        .context("an azureAd provider adopted by name")?;
    a_name_held_by_another_provider_type_is_refused(fixture)
        .await
        .context("an azureAd provider refused a name a jwt provider holds")?;
    an_unpinned_tenant_is_refused_by_the_api_server(fixture)
        .await
        .context("an azureAd provider refused a multi-tenant selector")?;
    the_provider_type_is_immutable(fixture)
        .await
        .context("an azureAd provider refused a flip to the jwt variant")?;
    a_status_id_of_another_type_is_refused(fixture)
        .await
        .context("a status.id naming a provider of another type")?;

    Ok(())
}

/// Entra values that never leave this test: ZITADEL stores an Azure AD provider
/// without ever calling Microsoft, so nothing here has to exist.
const TENANT_ID: &str = "ba5316df-1a48-4eaf-a2ca-f58b8408485d";
const CLIENT_ID: &str = "c9652a4e-39f2-4ad7-b93d-8f847ca7d6c0";

async fn put_client_secret(fixture: &TestFixture, name: &str, value: &str) -> Result<()> {
    let secrets: Api<k8s_openapi::api::core::v1::Secret> = Api::namespaced(fixture.k8s_client.clone(), NAMESPACE);
    secrets
        .patch(
            name,
            &PatchParams::apply("e2e").force(),
            &Patch::Apply(json!({
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": { "name": name, "namespace": NAMESPACE },
                "stringData": { "client-secret": value },
            })),
        )
        .await?;
    Ok(())
}

fn azure_ad_cr(idp_name: &str, org_name: &str, secret_name: &str, email_verified: bool) -> serde_json::Value {
    json!({
        "apiVersion": IdentityProvider::api_version(&()),
        "kind": "IdentityProvider",
        "metadata": { "name": idp_name, "namespace": NAMESPACE },
        "spec": {
            "name": idp_name,
            "organizationName": org_name,
            "autoRegister": true,
            "showOnLoginScreen": true,
            "azureAd": {
                "tenantId": TENANT_ID,
                "clientId": CLIENT_ID,
                "clientSecretRef": {
                    "name": secret_name,
                    "key": "client-secret",
                },
                "emailVerified": email_verified,
            },
        },
    })
}

async fn create_org(fixture: &TestFixture, org_name: &str) -> Result<String> {
    let orgs: Api<Organization> = Api::all(fixture.k8s_client.clone());
    orgs.patch(
        org_name,
        &PatchParams::apply("e2e").force(),
        &Patch::Apply(json!({
            "apiVersion": Organization::api_version(&()),
            "kind": "Organization",
            "metadata": { "name": org_name },
            "spec": { "name": org_name },
        })),
    )
    .await?;

    wait_for(Duration::from_secs(120), || async {
        Ok(orgs.get(org_name).await?.status.map(|status| status.id))
    })
    .await
    .context("the operator never created the organization")
}

/// The whole lifecycle of a declared Entra provider: created with the pinned
/// tenant, offered on the login screen, re-pushed when the Secret rotates, and
/// gone from ZITADEL once the resource is.
async fn an_azure_ad_provider_is_managed_declaratively(fixture: &TestFixture) -> Result<()> {
    let mut management = fixture
        .zitadel_builder
        .builder()
        .build_management_client()
        .await
        .map_err(|e| anyhow!("{e:?}"))?;

    let suffix = std::process::id();
    let org_name = format!("idp-entra-{suffix}");
    let idp_name = format!("microsoft-{suffix}");
    let secret_name = format!("entra-{suffix}");

    put_client_secret(fixture, &secret_name, "first-client-secret").await?;
    let org_id = create_org(fixture, &org_name).await?;

    let idps: Api<IdentityProvider> = Api::namespaced(fixture.k8s_client.clone(), NAMESPACE);
    idps.patch(
        &idp_name,
        &PatchParams::apply("e2e").force(),
        &Patch::Apply(azure_ad_cr(&idp_name, &org_name, &secret_name, true)),
    )
    .await?;

    let status = wait_for(Duration::from_secs(120), || async {
        Ok(idps.get(&idp_name).await?.status)
    })
    .await
    .context("the operator never created the azureAd identity provider")?;
    let idp_id = status.id;
    let first_hash = status
        .client_secret_hash
        .expect("the operator pushed a client secret but recorded no hash");

    let provider = get_provider(&mut management, &org_id, &idp_id).await?;
    assert_eq!(
        provider.r#type,
        i32::from(ProviderType::AzureAd),
        "the provider ZITADEL holds is not an Azure AD provider"
    );
    assert_eq!(provider.name, idp_name);
    let config = provider.config.as_ref().expect("a provider without configuration");
    assert_eq!(
        config.options,
        Some(Options {
            is_linking_allowed: true,
            is_creation_allowed: true,
            is_auto_creation: true,
            is_auto_update: true,
            auto_linking: 0,
        }),
        "provider options did not survive the round trip"
    );
    let Some(provider_config::Config::AzureAd(azure)) = &config.config else {
        return Err(anyhow!("the provider carries no Azure AD configuration"));
    };
    assert_eq!(azure.client_id, CLIENT_ID);
    assert!(azure.email_verified);
    assert_eq!(
        azure.tenant,
        Some(zitadel::api::zitadel::idp::v1::AzureAdTenant {
            r#type: Some(azure_ad_tenant::Type::TenantId(TENANT_ID.to_string())),
        }),
        "the provider is not pinned to the tenant the resource names"
    );

    wait_for(Duration::from_secs(120), || {
        let mut management = management.clone();
        let org_id = org_id.clone();
        let idp_id = idp_id.clone();
        async move { Ok(linked(&mut management, &org_id, &idp_id).await?.then_some(())) }
    })
    .await
    .context("the azureAd provider never reached the organization's login screen")?;

    // Rotating the Secret alone, with the resource untouched: the operator reads
    // it on every reconcile, so the requeue is what has to notice.
    put_client_secret(fixture, &secret_name, "second-client-secret").await?;
    let rotated = wait_for(Duration::from_secs(120), || async {
        Ok(idps
            .get(&idp_name)
            .await?
            .status
            .and_then(|status| status.client_secret_hash)
            .filter(|hash| hash != &first_hash))
    })
    .await
    .context("the rotated client secret was never pushed to ZITADEL")?;
    assert_ne!(rotated, first_hash);

    // A rotation must not replace the provider: users already linked to it keep
    // their link only as long as its id survives.
    assert_eq!(
        idps.get(&idp_name).await?.status.expect("status disappeared").id,
        idp_id,
        "the rotation created a new provider instead of updating the existing one"
    );

    // Nothing is left to converge, so the provider must stop being written. The
    // fixture requeues every 5s, and a reconcile that re-pushed the secret it
    // had already pushed would move the change date on every one of them.
    let settled = change_date(&mut management, &org_id, &idp_id).await?;
    tokio::time::sleep(Duration::from_secs(25)).await;
    assert_eq!(
        change_date(&mut management, &org_id, &idp_id).await?,
        settled,
        "a settled provider is being rewritten on every requeue"
    );

    idps.delete(&idp_name, &kube::api::DeleteParams::default()).await?;
    wait_for(Duration::from_secs(120), || {
        let mut management = management.clone();
        let org_id = org_id.clone();
        let idp_id = idp_id.clone();
        async move {
            let gone = management
                .get_provider_by_id(with_org(GetProviderByIdRequest { id: idp_id }, &org_id))
                .await
                .err()
                .is_some_and(|e| e.code() == Code::NotFound);
            Ok(gone.then_some(()))
        }
    })
    .await
    .context("deleting the resource left the provider in ZITADEL")?;

    Ok(())
}

/// A provider that already exists under the declared name is taken over rather
/// than duplicated, so users linked to it stay linked.
async fn an_existing_azure_ad_provider_is_adopted(fixture: &TestFixture) -> Result<()> {
    let mut management = fixture
        .zitadel_builder
        .builder()
        .build_management_client()
        .await
        .map_err(|e| anyhow!("{e:?}"))?;

    let suffix = std::process::id();
    let org_name = format!("idp-adopt-{suffix}");
    let idp_name = format!("microsoft-adopted-{suffix}");
    let secret_name = format!("entra-adopt-{suffix}");

    put_client_secret(fixture, &secret_name, "adopted-client-secret").await?;
    let org_id = create_org(fixture, &org_name).await?;

    let existing_id = management
        .add_azure_ad_provider(with_org(
            AddAzureAdProviderRequest {
                name: idp_name.clone(),
                client_id: CLIENT_ID.to_string(),
                client_secret: "created-outside-the-operator".to_string(),
                tenant: Some(zitadel::api::zitadel::idp::v1::AzureAdTenant {
                    r#type: Some(azure_ad_tenant::Type::TenantId(TENANT_ID.to_string())),
                }),
                email_verified: true,
                scopes: vec![],
                provider_options: Some(Options {
                    is_linking_allowed: true,
                    is_creation_allowed: true,
                    is_auto_creation: true,
                    is_auto_update: true,
                    auto_linking: 0,
                }),
            },
            &org_id,
        ))
        .await?
        .into_inner()
        .id;

    // Everything about the pre-existing provider already matches the resource
    // except the one thing ZITADEL will not reveal, so the credential is the
    // only reason left for the operator to write to it.
    let before_adoption = change_date(&mut management, &org_id, &existing_id).await?;

    let idps: Api<IdentityProvider> = Api::namespaced(fixture.k8s_client.clone(), NAMESPACE);
    idps.patch(
        &idp_name,
        &PatchParams::apply("e2e").force(),
        &Patch::Apply(azure_ad_cr(&idp_name, &org_name, &secret_name, true)),
    )
    .await?;

    let adopted = wait_for(Duration::from_secs(120), || async {
        Ok(idps.get(&idp_name).await?.status.map(|status| status.id))
    })
    .await
    .context("the operator never settled on an identity provider id")?;
    assert_eq!(
        adopted, existing_id,
        "the operator created a second provider instead of adopting the existing one"
    );

    // Adoption records no hash, so a later reconcile has to replace the
    // credential the operator does not know with the one the Secret holds. The
    // recorded hash says it decided to; the change date says it actually did.
    wait_for(Duration::from_secs(120), || async {
        Ok(idps
            .get(&idp_name)
            .await?
            .status
            .and_then(|status| status.client_secret_hash))
    })
    .await
    .context("the adopted provider never received the Secret's client secret")?;

    wait_for(Duration::from_secs(120), || {
        let mut management = management.clone();
        let org_id = org_id.clone();
        let existing_id = existing_id.clone();
        let before_adoption = before_adoption.clone();
        async move {
            let now = change_date(&mut management, &org_id, &existing_id).await?;
            Ok((now != before_adoption).then_some(()))
        }
    })
    .await
    .context("the adopted provider was never written to, so the Secret was never pushed")?;

    idps.delete(&idp_name, &kube::api::DeleteParams::default()).await?;

    Ok(())
}

/// Adoption keys on the display name, and a provider of another kind can answer
/// to it. Taking that one over would swap out an identity source the
/// organization's users are already linked to, so the operator must refuse.
async fn a_name_held_by_another_provider_type_is_refused(fixture: &TestFixture) -> Result<()> {
    let mut management = fixture
        .zitadel_builder
        .builder()
        .build_management_client()
        .await
        .map_err(|e| anyhow!("{e:?}"))?;

    let suffix = std::process::id();
    let org_name = format!("idp-clash-{suffix}");
    let idp_name = format!("microsoft-clash-{suffix}");
    let secret_name = format!("entra-clash-{suffix}");

    put_client_secret(fixture, &secret_name, "never-pushed").await?;
    let org_id = create_org(fixture, &org_name).await?;

    let jwt_id = management
        .add_org_jwtidp(with_org(
            AddOrgJwtidpRequest {
                name: idp_name.clone(),
                styling_type: IdpStylingType::StylingTypeUnspecified.into(),
                jwt_endpoint: "https://example.com/jwt".to_string(),
                issuer: "https://example.com".to_string(),
                keys_endpoint: "https://example.com/keys".to_string(),
                header_name: "x-e2e-token".to_string(),
                auto_register: true,
            },
            &org_id,
        ))
        .await?
        .into_inner()
        .idp_id;
    let before = change_date(&mut management, &org_id, &jwt_id).await?;

    let idps: Api<IdentityProvider> = Api::namespaced(fixture.k8s_client.clone(), NAMESPACE);
    idps.patch(
        &idp_name,
        &PatchParams::apply("e2e").force(),
        &Patch::Apply(azure_ad_cr(&idp_name, &org_name, &secret_name, true)),
    )
    .await?;

    let complaint = wait_for(Duration::from_secs(120), || async {
        let events: Api<k8s_openapi::api::core::v1::Event> =
            Api::namespaced(fixture.k8s_client.clone(), NAMESPACE);
        Ok(events
            .list(&kube::api::ListParams::default())
            .await?
            .items
            .into_iter()
            .find(|event| {
                event.involved_object.name.as_deref() == Some(idp_name.as_str())
                    && event.reason.as_deref() == Some("NameTaken")
            })
            .and_then(|event| event.message))
    })
    .await
    .context("the operator never complained about the name a jwt provider holds")?;
    assert!(
        complaint.contains("not an Azure AD provider"),
        "unexpected complaint: {complaint}"
    );

    assert!(
        idps.get(&idp_name).await?.status.is_none(),
        "the operator adopted a provider of another type"
    );

    let provider = get_provider(&mut management, &org_id, &jwt_id).await?;
    assert_eq!(
        provider.r#type,
        i32::from(ProviderType::Jwt),
        "the jwt provider was converted into an Azure AD one"
    );
    assert_eq!(
        change_date(&mut management, &org_id, &jwt_id).await?,
        before,
        "the jwt provider was written to despite the refusal"
    );

    idps.delete(&idp_name, &kube::api::DeleteParams::default()).await?;

    Ok(())
}

/// `common`, `organizations` and `consumers` select Microsoft's multi-tenant
/// endpoints, which admit every Microsoft account. The CRD has to turn them away
/// before a resource carrying one ever reaches the operator.
async fn an_unpinned_tenant_is_refused_by_the_api_server(fixture: &TestFixture) -> Result<()> {
    let idps: Api<IdentityProvider> = Api::namespaced(fixture.k8s_client.clone(), NAMESPACE);

    for selector in ["common", "organizations", "consumers", "contoso.onmicrosoft.com"] {
        let name = format!("unpinned-{selector}-{}", std::process::id()).replace('.', "-");
        let mut cr = azure_ad_cr(&name, "irrelevant", "irrelevant", true);
        cr["spec"]["azureAd"]["tenantId"] = json!(selector);

        let refused = idps
            .patch(&name, &PatchParams::apply("e2e").force(), &Patch::Apply(cr))
            .await
            .expect_err(&format!("the API server accepted tenantId '{selector}'"))
            .to_string();
        assert!(
            refused.contains("tenantId") || refused.contains("pattern"),
            "tenantId '{selector}' was refused for an unrelated reason: {refused}"
        );
    }

    Ok(())
}

/// Only this operator writes `status.id`, so a provider of another type behind it
/// means the variant was flipped before the CRD refused it. The apply path must
/// leave that provider alone, and the cleanup must still delete it — through the
/// API that issued the id, not the one the spec declares.
async fn a_status_id_of_another_type_is_refused(fixture: &TestFixture) -> Result<()> {
    let mut management = fixture
        .zitadel_builder
        .builder()
        .build_management_client()
        .await
        .map_err(|e| anyhow!("{e:?}"))?;

    let suffix = std::process::id();
    let org_name = format!("idp-mismatch-{suffix}");
    let idp_name = format!("microsoft-mismatch-{suffix}");
    let secret_name = format!("entra-mismatch-{suffix}");

    put_client_secret(fixture, &secret_name, "never-pushed").await?;
    let org_id = create_org(fixture, &org_name).await?;

    // Named differently from the resource, so adoption cannot reach it: the only
    // way in is the status.id written below.
    let jwt_id = management
        .add_org_jwtidp(with_org(
            AddOrgJwtidpRequest {
                name: format!("legacy-{suffix}"),
                styling_type: IdpStylingType::StylingTypeUnspecified.into(),
                jwt_endpoint: "https://example.com/jwt".to_string(),
                issuer: "https://example.com".to_string(),
                keys_endpoint: "https://example.com/keys".to_string(),
                header_name: "x-e2e-token".to_string(),
                auto_register: true,
            },
            &org_id,
        ))
        .await?
        .into_inner()
        .idp_id;
    let before = change_date(&mut management, &org_id, &jwt_id).await?;

    let idps: Api<IdentityProvider> = Api::namespaced(fixture.k8s_client.clone(), NAMESPACE);
    idps.patch(
        &idp_name,
        &PatchParams::apply("e2e").force(),
        &Patch::Apply(azure_ad_cr(&idp_name, &org_name, &secret_name, true)),
    )
    .await?;
    let azure_id = wait_for(Duration::from_secs(120), || async {
        Ok(idps.get(&idp_name).await?.status.map(|status| status.id))
    })
    .await
    .context("the operator never created the azureAd provider")?;

    // The flip itself: the CRD refuses it on the spec, so the test writes the state
    // it would have left behind.
    idps.patch_status(
        &idp_name,
        &PatchParams::default(),
        &Patch::Merge(json!({ "status": { "id": jwt_id } })),
    )
    .await?;

    let complaint = wait_for(Duration::from_secs(120), || async {
        Ok(type_mismatch(fixture, &idp_name, "NotUpdated").await?)
    })
    .await
    .context("the operator never complained about a status.id of another type")?;
    assert!(
        complaint.contains("cannot change"),
        "unexpected complaint: {complaint}"
    );
    assert_eq!(
        change_date(&mut management, &org_id, &jwt_id).await?,
        before,
        "the operator wrote to the jwt provider behind its status.id"
    );
    assert_eq!(
        get_provider(&mut management, &org_id, &jwt_id).await?.r#type,
        i32::from(ProviderType::Jwt),
        "the jwt provider was converted into an Azure AD one"
    );

    idps.delete(&idp_name, &kube::api::DeleteParams::default()).await?;

    wait_for(Duration::from_secs(120), || async {
        Ok(idps.get_opt(&idp_name).await?.is_none().then_some(()))
    })
    .await
    .context("the finalizer never released the resource")?;

    let warned = type_mismatch(fixture, &idp_name, "Deleting")
        .await?
        .context("the cleanup deleted a provider of another type without saying so")?;
    assert!(
        warned.contains("deleting the stored provider"),
        "unexpected warning: {warned}"
    );
    let gone = get_provider(&mut management, &org_id, &jwt_id)
        .await
        .expect_err("the jwt provider behind status.id outlived the resource")
        .to_string();
    assert!(gone.contains("NotFound") || gone.contains("not found"), "{gone}");

    // The provider the operator did create is orphaned by the flip, exactly as it
    // would be in a cluster. Nothing else in this test cleans it up.
    management
        .delete_provider(with_org(
            zitadel::api::zitadel::management::v1::DeleteProviderRequest { id: azure_id },
            &org_id,
        ))
        .await?;

    Ok(())
}

/// The message of the operator's TypeMismatch warning for one action, if it has
/// published one yet.
async fn type_mismatch(fixture: &TestFixture, idp_name: &str, action: &str) -> Result<Option<String>> {
    let events: Api<k8s_openapi::api::core::v1::Event> = Api::namespaced(fixture.k8s_client.clone(), NAMESPACE);
    Ok(events
        .list(&kube::api::ListParams::default())
        .await?
        .items
        .into_iter()
        .find(|event| {
            event.involved_object.name.as_deref() == Some(idp_name)
                && event.reason.as_deref() == Some("TypeMismatch")
                && event.action.as_deref() == Some(action)
        })
        .and_then(|event| event.message))
}

/// `status.id` is an id in one ZITADEL API only. Flipping the variant would keep it
/// and send it to the other API, which never issued it, so the API server has to
/// refuse the flip rather than leave the operator failing forever.
async fn the_provider_type_is_immutable(fixture: &TestFixture) -> Result<()> {
    let idps: Api<IdentityProvider> = Api::namespaced(fixture.k8s_client.clone(), NAMESPACE);
    let name = format!("variant-flip-{}", std::process::id());

    // An organization that does not exist: the flip has to be refused before the
    // operator ever creates a provider to flip.
    idps.patch(
        &name,
        &PatchParams::apply("e2e").force(),
        &Patch::Apply(azure_ad_cr(&name, "irrelevant", "irrelevant", true)),
    )
    .await?;

    let mut flipped = azure_ad_cr(&name, "irrelevant", "irrelevant", true);
    flipped["spec"].as_object_mut().unwrap().remove("azureAd");
    flipped["spec"]["jwt"] = json!({
        "issuer": "https://example.com",
        "jwtEndpoint": "https://example.com/jwt",
        "keysEndpoint": "https://example.com/keys",
        "headerName": "x-e2e-token",
    });

    let refused = idps
        .patch(&name, &PatchParams::apply("e2e").force(), &Patch::Apply(flipped))
        .await
        .expect_err("the API server accepted a flip from azureAd to jwt")
        .to_string();
    assert!(
        refused.contains("the provider type cannot change"),
        "the flip was refused for an unrelated reason: {refused}"
    );

    Ok(())
}

/// When ZITADEL last wrote the provider. Nothing else reveals that a client
/// secret was pushed, because ZITADEL never reads one back.
async fn change_date(management: &mut Management, org_id: &str, idp_id: &str) -> Result<String> {
    let provider = get_provider(management, org_id, idp_id).await?;
    let details = provider
        .details
        .ok_or_else(|| anyhow!("provider {idp_id} carries no details"))?;
    Ok(format!("{:?}/{}", details.change_date, details.sequence))
}

async fn get_provider(
    management: &mut Management,
    org_id: &str,
    idp_id: &str,
) -> Result<zitadel::api::zitadel::idp::v1::Provider> {
    management
        .get_provider_by_id(with_org(GetProviderByIdRequest { id: idp_id.to_string() }, org_id))
        .await?
        .into_inner()
        .idp
        .ok_or_else(|| anyhow!("ZITADEL has no provider with id {idp_id}"))
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

    let events: Api<k8s_openapi::api::core::v1::Event> = Api::namespaced(fixture.k8s_client.clone(), NAMESPACE);
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
