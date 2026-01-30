use k8s_openapi::api::core::v1::Secret;
use kube::{Api, Client};
use std::{env, sync::Arc};
use tonic::transport::{ClientTlsConfig, Endpoint};
use tracing::info;
use tracing_subscriber::{prelude::*, EnvFilter};
use zitadel::{
    api::{
        interceptors::ServiceAccountInterceptor,
        zitadel::{auth::v1::GetMyUserRequest, management::v1::GetMyOrgRequest},
    },
    credentials::{AuthenticationOptions, ServiceAccount},
};
use zitadel_operator::{
    controllers::{application, human_user, organization, project, project_role, user_grant},
    OperatorContext, ZitadelBuilder,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    #[cfg(feature = "dotenv")]
    dotenv::dotenv().ok();

    let logger = tracing_subscriber::fmt::layer().compact();
    let env_filter = EnvFilter::try_from_env("ZITADEL_LOG")
        .or(EnvFilter::try_new("info"))
        .unwrap();
    let logger = logger.with_filter(tracing_subscriber::filter::filter_fn(|metadata| {
        if metadata.level() != &tracing::Level::DEBUG {
            return true;
        }
        if env::var("ZITADEL_LOG_ALL").unwrap_or("0".to_string()) == "1" {
            return true;
        }
        if metadata.target().starts_with("h2::")
            || metadata.target().starts_with("rustls::")
            || metadata.target().starts_with("hyper_util::client::")
            || metadata.target().starts_with("hyper::client::connect::")
            || metadata.target() == "hyper::client::pool"
            || metadata.target().starts_with("hyper::proto::")
            || metadata.target() == "reqwest::connect"
            || metadata.target() == "tower::buffer::worker"
            || metadata.target() == "kube_runtime::controller"
        {
            return false;
        }
        return true;
    }));
    tracing_subscriber::registry().with(env_filter).with(logger).init();

    info!("Loading k8s client...");
    let k8s = Client::try_default().await.expect("failed to create kube client");

    info!("Loading Zitadel service account...");
    let sa_secret_name = env::var("ZITADEL_SECRET_NAME").expect("missing ZITADEL_SECRET_NAME");
    let sa_secret_namespace = env::var("ZITADEL_SECRET_NAMESPACE").unwrap_or("zitadel".to_string());
    let secret = Api::<Secret>::namespaced(k8s.clone(), &sa_secret_namespace)
        .get(&sa_secret_name)
        .await?;
    let sa_data = secret
        .data
        .and_then(|d| d.first_key_value().and_then(|(_, v)| Some(v.clone())))
        .map(|v| String::from_utf8(v.0).expect("could not convert secret data to string"))
        .expect("supplied secret is empty");
    let sa = ServiceAccount::load_from_json(&sa_data).unwrap();

    let zitadel_url = env::var("ZITADEL_URL").expect("missing ZITADEL_URL");

    let interceptor = ServiceAccountInterceptor::new(
        &zitadel_url,
        &sa,
        Some(AuthenticationOptions {
            api_access: true,
            ..Default::default()
        }),
    );

    // this is essentially the same as the zitadel crate does, but doesn't hide error details
    // we pretty much only have this here to make sure that we get useful errors on certificate failures
    info!("Testing Zitadel connection to {zitadel_url}...");
    Endpoint::from_shared(zitadel_url.to_string())?
        .tls_config(ClientTlsConfig::default().with_native_roots().assume_http2(true))?
        .connect()
        .await?;

    let zitadel_builder = ZitadelBuilder::new(zitadel_url, interceptor);

    zitadel_builder
        .builder()
        .build_management_client()
        .await
        .map_err(|e| anyhow::anyhow!(format!("{:?}", e)))?
        .get_my_org(GetMyOrgRequest {})
        .await?;

    let operator_user_id = zitadel_builder
        .builder()
        .build_auth_client()
        .await
        .map_err(|e| anyhow::anyhow!(format!("{:?}", e)))?
        .get_my_user(GetMyUserRequest {})
        .await?
        .into_inner()
        .user
        .expect("auth.get_my_user returned no user")
        .id;
    info!("Operator user ID: {}", operator_user_id);

    let context = Arc::new(OperatorContext {
        k8s: k8s.clone(),
        zitadel: zitadel_builder,
        operator_user_id,
    });

    info!("Starting controllers...");
    let organization_controller = organization::run(context.clone());
    let project_controller = project::run(context.clone());
    let project_role_controller = project_role::run(context.clone());
    let human_user_controller = human_user::run(context.clone());
    let user_grant_controller = user_grant::run(context.clone());
    let application_controller = application::run(context.clone());

    tokio::join!(
        organization_controller,
        project_controller,
        project_role_controller,
        human_user_controller,
        user_grant_controller,
        application_controller
    );

    Ok(())
}
