use crate::{
    schema::{
        ApiAuthMethodType, AppType, Application, ApplicationInnerSpec, ApplicationPhase, ApplicationStatus, GrantType,
        OidcAuthMethodType, OidcTokenType, OidcVersion, Project, ResponseType,
    },
    util::{
        create_request_with_org_id, patch_status, CurrentState, CurrentStateParameters, CurrentStateRetriever,
        GetStatus,
    },
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
        reflector::ObjectRef,
        watcher::Config,
        Controller, WatchStreamExt,
    },
    Api, Resource, ResourceExt,
};
use openidconnect::{core::CoreProviderMetadata, reqwest::async_http_client, IssuerUrl};
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use tonic::{service::interceptor::InterceptedService, Code};
use tracing::{debug, info, instrument, warn};
use zitadel::api::{
    interceptors::ServiceAccountInterceptor,
    zitadel::management::v1::{
        management_service_client::ManagementServiceClient, GetAppByIdRequest, GetOidcInformationRequest,
        ListAppsRequest, RemoveAppRequest, UpdateApiAppConfigRequest, UpdateAppRequest, UpdateOidcAppConfigRequest,
    },
};

pub static APPLICATION_FINALIZER: &str = "application.zitadel.org";

struct AddAppResponse {
    pub app_id: String,
    #[allow(dead_code)]
    pub details: Option<zitadel::api::zitadel::v1::ObjectDetails>,
    pub client_id: String,
    pub client_secret: String,
    #[allow(dead_code)]
    pub none_compliant: Option<bool>,
    #[allow(dead_code)]
    pub compliance_problems: Option<Vec<zitadel::api::zitadel::v1::LocalizedMessage>>,
}
impl Into<AddAppResponse> for zitadel::api::zitadel::management::v1::AddOidcAppResponse {
    fn into(self) -> AddAppResponse {
        AddAppResponse {
            app_id: self.app_id,
            details: self.details,
            client_id: self.client_id,
            client_secret: self.client_secret,
            none_compliant: Some(self.none_compliant),
            compliance_problems: Some(self.compliance_problems),
        }
    }
}
impl Into<AddAppResponse> for zitadel::api::zitadel::management::v1::AddApiAppResponse {
    fn into(self) -> AddAppResponse {
        AddAppResponse {
            app_id: self.app_id,
            details: self.details,
            client_id: self.client_id,
            client_secret: self.client_secret,
            none_compliant: None,
            compliance_problems: None,
        }
    }
}

struct ApplicationStateRetriever {
    pub management: ManagementServiceClient<InterceptedService<tonic::transport::Channel, ServiceAccountInterceptor>>,
}
impl CurrentStateRetriever<Application, zitadel::api::zitadel::app::v1::App, Project> for ApplicationStateRetriever {
    async fn get_object(
        &mut self,
        status: &<Application as GetStatus>::Status,
    ) -> Result<Option<zitadel::api::zitadel::app::v1::App>> {
        Ok(self
            .management
            .get_app_by_id(create_request_with_org_id(
                GetAppByIdRequest {
                    app_id: status.id.clone(),
                    project_id: status.project_id.clone(),
                },
                status.organization_id.clone(),
            ))
            .await?
            .into_inner()
            .app)
    }

    async fn list_objects(
        &mut self,
        app: &Application,
        proj: &<Project as GetStatus>::Status,
    ) -> Result<Vec<zitadel::api::zitadel::app::v1::App>> {
        let matching = self
            .management
            .list_apps(create_request_with_org_id(
                ListAppsRequest {
                    project_id: proj.id.clone(),
                    query: None,
                    queries: vec![zitadel::api::zitadel::app::v1::AppQuery {
                        query: Some(zitadel::api::zitadel::app::v1::app_query::Query::NameQuery(
                            zitadel::api::zitadel::app::v1::AppNameQuery {
                                name: app.spec.name.clone(),
                                method: zitadel::api::zitadel::v1::TextQueryMethod::Equals.into(),
                            },
                        )),
                    }],
                },
                proj.organization_id.clone(),
            ))
            .await?
            .into_inner()
            .result;
        Ok(matching)
    }
}

impl From<ApiAuthMethodType> for i32 {
    fn from(amt: ApiAuthMethodType) -> Self {
        match amt {
            ApiAuthMethodType::Basic => zitadel::api::zitadel::app::v1::ApiAuthMethodType::Basic as i32,
            ApiAuthMethodType::PrivateKeyJwt => zitadel::api::zitadel::app::v1::ApiAuthMethodType::PrivateKeyJwt as i32,
        }
    }
}

impl From<ResponseType> for i32 {
    fn from(rt: ResponseType) -> Self {
        match rt {
            ResponseType::Code => zitadel::api::zitadel::app::v1::OidcResponseType::Code as i32,
            ResponseType::IdToken => zitadel::api::zitadel::app::v1::OidcResponseType::IdToken as i32,
            ResponseType::IdTokenToken => zitadel::api::zitadel::app::v1::OidcResponseType::IdTokenToken as i32,
        }
    }
}

impl From<i32> for ResponseType {
    fn from(val: i32) -> Self {
        match val {
            x if x == zitadel::api::zitadel::app::v1::OidcResponseType::Code as i32 => ResponseType::Code,
            x if x == zitadel::api::zitadel::app::v1::OidcResponseType::IdToken as i32 => ResponseType::IdToken,
            x if x == zitadel::api::zitadel::app::v1::OidcResponseType::IdTokenToken as i32 => {
                ResponseType::IdTokenToken
            }
            _ => unreachable!(),
        }
    }
}

impl From<GrantType> for i32 {
    fn from(gt: GrantType) -> Self {
        match gt {
            GrantType::AuthorizationCode => zitadel::api::zitadel::app::v1::OidcGrantType::AuthorizationCode as i32,
            GrantType::Implicit => zitadel::api::zitadel::app::v1::OidcGrantType::Implicit as i32,
            GrantType::RefreshToken => zitadel::api::zitadel::app::v1::OidcGrantType::RefreshToken as i32,
            GrantType::DeviceCode => zitadel::api::zitadel::app::v1::OidcGrantType::DeviceCode as i32,
            GrantType::TokenExchange => zitadel::api::zitadel::app::v1::OidcGrantType::TokenExchange as i32,
        }
    }
}

impl From<i32> for GrantType {
    fn from(val: i32) -> Self {
        match val {
            x if x == zitadel::api::zitadel::app::v1::OidcGrantType::AuthorizationCode as i32 => {
                GrantType::AuthorizationCode
            }
            x if x == zitadel::api::zitadel::app::v1::OidcGrantType::Implicit as i32 => GrantType::Implicit,
            x if x == zitadel::api::zitadel::app::v1::OidcGrantType::RefreshToken as i32 => GrantType::RefreshToken,
            x if x == zitadel::api::zitadel::app::v1::OidcGrantType::DeviceCode as i32 => GrantType::DeviceCode,
            x if x == zitadel::api::zitadel::app::v1::OidcGrantType::TokenExchange as i32 => GrantType::TokenExchange,
            _ => unreachable!(),
        }
    }
}

impl From<AppType> for i32 {
    fn from(at: AppType) -> Self {
        match at {
            AppType::Web => zitadel::api::zitadel::app::v1::OidcAppType::Web as i32,
            AppType::UserAgent => zitadel::api::zitadel::app::v1::OidcAppType::UserAgent as i32,
            AppType::Native => zitadel::api::zitadel::app::v1::OidcAppType::Native as i32,
        }
    }
}

impl From<i32> for AppType {
    fn from(val: i32) -> Self {
        match val {
            x if x == zitadel::api::zitadel::app::v1::OidcAppType::Web as i32 => AppType::Web,
            x if x == zitadel::api::zitadel::app::v1::OidcAppType::UserAgent as i32 => AppType::UserAgent,
            x if x == zitadel::api::zitadel::app::v1::OidcAppType::Native as i32 => AppType::Native,
            _ => unreachable!(),
        }
    }
}

impl From<OidcAuthMethodType> for i32 {
    fn from(amt: OidcAuthMethodType) -> Self {
        match amt {
            OidcAuthMethodType::Basic => zitadel::api::zitadel::app::v1::OidcAuthMethodType::Basic as i32,
            OidcAuthMethodType::Post => zitadel::api::zitadel::app::v1::OidcAuthMethodType::Post as i32,
            OidcAuthMethodType::None => zitadel::api::zitadel::app::v1::OidcAuthMethodType::None as i32,
            OidcAuthMethodType::PrivateKeyJwt => {
                zitadel::api::zitadel::app::v1::OidcAuthMethodType::PrivateKeyJwt as i32
            }
        }
    }
}

impl From<i32> for OidcAuthMethodType {
    fn from(val: i32) -> Self {
        match val {
            x if x == zitadel::api::zitadel::app::v1::OidcAuthMethodType::Basic as i32 => OidcAuthMethodType::Basic,
            x if x == zitadel::api::zitadel::app::v1::OidcAuthMethodType::Post as i32 => OidcAuthMethodType::Post,
            x if x == zitadel::api::zitadel::app::v1::OidcAuthMethodType::None as i32 => OidcAuthMethodType::None,
            x if x == zitadel::api::zitadel::app::v1::OidcAuthMethodType::PrivateKeyJwt as i32 => {
                OidcAuthMethodType::PrivateKeyJwt
            }
            _ => unreachable!(),
        }
    }
}

impl From<OidcVersion> for i32 {
    fn from(v: OidcVersion) -> Self {
        match v {
            OidcVersion::V1_0 => zitadel::api::zitadel::app::v1::OidcVersion::OidcVersion10 as i32,
        }
    }
}

impl From<i32> for OidcVersion {
    fn from(val: i32) -> Self {
        match val {
            x if x == zitadel::api::zitadel::app::v1::OidcVersion::OidcVersion10 as i32 => OidcVersion::V1_0,
            _ => unreachable!(),
        }
    }
}

impl From<OidcTokenType> for i32 {
    fn from(tt: OidcTokenType) -> Self {
        match tt {
            OidcTokenType::Bearer => zitadel::api::zitadel::app::v1::OidcTokenType::Bearer as i32,
            OidcTokenType::Jwt => zitadel::api::zitadel::app::v1::OidcTokenType::Jwt as i32,
        }
    }
}

impl From<i32> for OidcTokenType {
    fn from(val: i32) -> Self {
        match val {
            x if x == zitadel::api::zitadel::app::v1::OidcTokenType::Bearer as i32 => OidcTokenType::Bearer,
            x if x == zitadel::api::zitadel::app::v1::OidcTokenType::Jwt as i32 => OidcTokenType::Jwt,
            _ => unreachable!(),
        }
    }
}

#[instrument(skip(ctx, app))]
async fn reconcile(app: Arc<Application>, ctx: Arc<OperatorContext>) -> Result<Action> {
    let ns = app.metadata.namespace.as_ref().unwrap();
    let apps = Api::<Application>::namespaced(ctx.k8s.clone(), &ns);
    let projs = Api::<Project>::namespaced(ctx.k8s.clone(), app.spec.project_namespace.as_ref().unwrap_or(ns));
    let secrets = Api::<Secret>::namespaced(ctx.k8s.clone(), &ns);
    let recorder = ctx.build_recorder();

    finalizer(&apps, APPLICATION_FINALIZER, app, |event| async {
        match event {
            Finalizer::Apply(app) => {
                info!("reconciling app {}", app.name_any());

                let mut management = ctx.zitadel.builder().build_management_client().await?;

                let state =
                    CurrentState::<Project, zitadel::api::zitadel::app::v1::App>::determine(
                        CurrentStateParameters {
                            resource: app.clone(),
                            resource_api: apps.clone(),
                            parent_api: projs.clone(),
                            parent_name: app.spec.project_name.clone(),
                            retriever: ApplicationStateRetriever {
                                management: management.clone(),
                            },
                            is_equal: |object, app: &Application| {
                                if object.name != app.spec.name {
                                    return false;
                                }
                                if let Some(config) = &object.config {
                                    match config {
                                        zitadel::api::zitadel::app::v1::app::Config::OidcConfig(
                                            oidc_config,
                                        ) => {
                                            if let ApplicationInnerSpec::Oidc(oidc) =
                                                &app.spec.inner
                                            {
                                                return oidc_config.redirect_uris == oidc.redirect_uris.iter().map(|u| u.to_string()).collect::<Vec<_>>() &&
                                                    oidc_config.response_types.iter().map(|r| r.clone().into()).collect::<Vec<ResponseType>>() == oidc.response_types &&
                                                    oidc_config.grant_types.iter().map(|g| g.clone().into()).collect::<Vec<GrantType>>() == oidc.grant_types &&
                                                    match (oidc_config.app_type, &oidc.app_type) {
                                                        (val, AppType::Web) if val == zitadel::api::zitadel::app::v1::OidcAppType::Web as i32 => true,
                                                        (val, AppType::UserAgent) if val == zitadel::api::zitadel::app::v1::OidcAppType::UserAgent as i32 => true,
                                                        (val, AppType::Native) if val == zitadel::api::zitadel::app::v1::OidcAppType::Native as i32 => true,
                                                        _ => false,
                                                    } &&
                                                    match (oidc_config.auth_method_type(), &oidc.auth_method) {
                                                        (zitadel::api::zitadel::app::v1::OidcAuthMethodType::Basic, OidcAuthMethodType::Basic) => true,
                                                        (zitadel::api::zitadel::app::v1::OidcAuthMethodType::Post, OidcAuthMethodType::Post) => true,
                                                        (zitadel::api::zitadel::app::v1::OidcAuthMethodType::None, OidcAuthMethodType::None) => true,
                                                        (zitadel::api::zitadel::app::v1::OidcAuthMethodType::PrivateKeyJwt, OidcAuthMethodType::PrivateKeyJwt) => true,
                                                        _ => false,
                                                    } &&
                                                    oidc_config.post_logout_redirect_uris == oidc.post_logout_redirect_uris.iter().map(|u| u.to_string()).collect::<Vec<_>>() &&
                                                    match (oidc_config.version, &oidc.version) {
                                                        (val, OidcVersion::V1_0) if val == zitadel::api::zitadel::app::v1::OidcVersion::OidcVersion10 as i32 => true,
                                                        _ => false,
                                                    } &&
                                                    match (oidc_config.access_token_type, &oidc.access_token_type) {
                                                        (val, OidcTokenType::Bearer) if val == zitadel::api::zitadel::app::v1::OidcTokenType::Bearer as i32 => true,
                                                        (val, OidcTokenType::Jwt) if val == zitadel::api::zitadel::app::v1::OidcTokenType::Jwt as i32 => true,
                                                        _ => false,
                                                    } &&
                                                    oidc_config.access_token_role_assertion == oidc.access_token_role_assertion &&
                                                    oidc_config.id_token_role_assertion == oidc.id_token_role_assertion &&
                                                    oidc_config.id_token_userinfo_assertion == oidc.id_token_userinfo_assertion &&
                                                    (oidc.clock_skew.is_none() || oidc_config.clock_skew == oidc.clock_skew.map(|d| d.into())) &&
                                                    oidc_config.additional_origins == oidc.additional_origins.iter().map(|u| u.to_string()).collect::<Vec<_>>() &&
                                                    oidc_config.skip_native_app_success_page == oidc.skip_native_app_success_page &&
                                                    oidc_config.back_channel_logout_uri == oidc.backchannel_logout_uri;
                                            } else {
                                                return false;
                                            }
                                        }
                                        zitadel::api::zitadel::app::v1::app::Config::ApiConfig(
                                            api_config,
                                        ) => {
                                            if let ApplicationInnerSpec::Api(api) = &app.spec.inner
                                            {
                                                return api_config.auth_method_type()
                                                    == api.method.into();
                                            } else {
                                                return false;
                                            }
                                        }
                                        zitadel::api::zitadel::app::v1::app::Config::SamlConfig(
                                            _saml_config,
                                        ) => unimplemented!("SAML not yet supported"),
                                    }
                                }
                                return true;
                            },
                        },
                    )
                    .await?;

                match state {
                    CurrentState::ExistsEqual(_, _) => {}
                    CurrentState::ExistsUnequal(application, proj) => {
                        debug!("app changed, updating");

                        let res = management
                            .update_app(create_request_with_org_id(
                                UpdateAppRequest {
                                    app_id: application.id.clone(),
                                    project_id: proj.id.clone(),
                                    name: app.spec.name.clone(),
                                },
                                proj.organization_id.clone(),
                            ))
                            .await;
                        if let Err(e) = res {
                            if e.message().contains("COMMAND-2m8vx") {
                                // no changes needed
                            } else {
                                return Result::Err(Error::ZitadelError(e));
                            }
                        }

                        let res = match &app.spec.inner {
                            ApplicationInnerSpec::Oidc(config) => {
                                management
                                    .update_oidc_app_config(create_request_with_org_id(
                                        UpdateOidcAppConfigRequest {
                                            project_id: proj.id.clone(),
                                            app_id: application.id.clone(),
                                            redirect_uris: config
                                                .redirect_uris
                                                .iter()
                                                .map(|u| u.to_string())
                                                .collect(),
                                            response_types: config
                                                .response_types
                                                .iter()
                                                .map(|r| r.clone().into())
                                                .collect(),
                                            grant_types: config
                                                .grant_types
                                                .iter()
                                                .map(|g| g.clone().into())
                                                .collect(),
                                            app_type: config.app_type.clone().into(),
                                            auth_method_type: config.auth_method.clone().into(),
                                            post_logout_redirect_uris: config
                                                .post_logout_redirect_uris
                                                .iter()
                                                .map(|u| u.to_string())
                                                .collect(),
                                            dev_mode: config.dev_mode,
                                            access_token_type: config.access_token_type.clone().into(),
                                            access_token_role_assertion: config
                                                .access_token_role_assertion,
                                            id_token_role_assertion: config.id_token_role_assertion,
                                            id_token_userinfo_assertion: config
                                                .id_token_userinfo_assertion,
                                            clock_skew: config.clock_skew.clone().map(|d| d.into()),
                                            additional_origins: config
                                                .additional_origins
                                                .iter()
                                                .map(|u| u.to_string())
                                                .collect(),
                                            skip_native_app_success_page: config
                                                .skip_native_app_success_page,
                                            back_channel_logout_uri: config
                                                .backchannel_logout_uri
                                                .clone(),
                                        },
                                        proj.organization_id.clone(),
                                    ))
                                    .await.map(|_| true)
                            }
                            ApplicationInnerSpec::Api(config) => {
                                let mut req = UpdateApiAppConfigRequest {
                                    project_id: proj.id,
                                    app_id: application.id,
                                    auth_method_type: 0,
                                };
                                req.set_auth_method_type(config.method.into());
                                management
                                    .update_api_app_config(create_request_with_org_id(
                                        req,
                                        proj.organization_id,
                                    ))
                                    .await.map(|_| true)
                            }
                        };
                        if let Err(e) = res {
                            if e.message().contains("COMMAND-1m88i") {
                                // no changes needed
                            } else {
                                return Result::Err(Error::ZitadelError(e));
                            }
                        }

                        recorder
                            .publish(
                                &Event {
                                    type_: EventType::Normal,
                                    reason: "Changed".to_string(),
                                    note: Some("Application updated".to_string()),
                                    action: "Updating".to_string(),
                                    secondary: None,
                                },
                                &app.object_ref(&()),
                            )
                            .await?;
                    }
                    CurrentState::NotExists(proj) => {
                        debug!("application not found, (re)creating");

                        let secret = secrets.get_opt(app.metadata.name.as_ref().unwrap()).await?;
                        if let Some(secret) = secret {
                            recorder
                                .publish(
                                    &Event {
                                        type_: EventType::Normal,
                                        reason: "Conflict".to_string(),
                                        note: Some(
                                            "Another secret with the same name already exists"
                                                .to_string(),
                                        ),
                                        action: "NotCreated".to_string(),
                                        secondary: Some(secret.object_ref(&())),
                                    },
                                    &app.object_ref(&()),
                                )
                                .await?;
                        } else {
                            let resp: AddAppResponse = match &app.spec.inner {
                                ApplicationInnerSpec::Oidc(config) => management
                                    .add_oidc_app(create_request_with_org_id(
                                        zitadel::api::zitadel::management::v1::AddOidcAppRequest {
                                            project_id: proj.id.clone(),
                                            name: app.spec.name.clone(),
                                            redirect_uris: config
                                                .redirect_uris
                                                .iter()
                                                .map(|u| u.to_string())
                                                .collect(),
                                            response_types: config
                                                .response_types
                                                .iter()
                                                .map(|r| r.clone().into())
                                                .collect(),
                                            grant_types: config
                                                .grant_types
                                                .iter()
                                                .map(|g| g.clone().into())
                                                .collect(),
                                            app_type: config.app_type.clone().into(),
                                            auth_method_type: config.auth_method.clone().into(),
                                            post_logout_redirect_uris: config
                                                .post_logout_redirect_uris
                                                .iter()
                                                .map(|u| u.to_string())
                                                .collect(),
                                            version: config.version.clone().into(),
                                            dev_mode: config.dev_mode,
                                            access_token_type: config.access_token_type.clone().into(),
                                            access_token_role_assertion: config
                                                .access_token_role_assertion,
                                            id_token_role_assertion: config.id_token_role_assertion,
                                            id_token_userinfo_assertion: config
                                                .id_token_userinfo_assertion,
                                            clock_skew: config.clock_skew.clone().map(|d| d.into()),
                                            additional_origins: config
                                                .additional_origins
                                                .iter()
                                                .map(|u| u.to_string())
                                                .collect(),
                                            skip_native_app_success_page: config
                                                .skip_native_app_success_page,
                                            back_channel_logout_uri: config
                                                .backchannel_logout_uri
                                                .clone(),
                                        },
                                        proj.organization_id.clone(),
                                    ))
                                    .await?
                                    .into_inner()
                                    .into(),
                                ApplicationInnerSpec::Api(config) => management
                                    .add_api_app(create_request_with_org_id(
                                        zitadel::api::zitadel::management::v1::AddApiAppRequest {
                                            project_id: proj.id.clone(),
                                            name: app.spec.name.clone(),
                                            auth_method_type: config.method.into(),
                                        },
                                        proj.organization_id.clone(),
                                    ))
                                    .await?
                                    .into_inner()
                                    .into(),
                            };

                            let issuer = management.get_oidc_information(GetOidcInformationRequest {}).await?.into_inner().issuer;
                            let discovery = CoreProviderMetadata::discover_async(
                                IssuerUrl::new(issuer).map_err(|e| Error::Other(format!("failed to discover OIDC provider metadata: {:?}", e)))?,
                                async_http_client
                            ).await.map_err(|e| Error::Other(format!("failed to discover OIDC provider metadata: {:?}", e)))?;

                            let mut secret_data = BTreeMap::new();
                            secret_data.insert("client_id".to_string(), resp.client_id);
                            secret_data.insert("client_secret".to_string(), resp.client_secret);
                            secret_data.insert("issuer".to_string(), discovery.issuer().to_string());
                            secret_data.insert("auth_endpoint".to_string(), discovery.authorization_endpoint().to_string());
                            secret_data.insert("jwks_uri".to_string(), discovery.jwks_uri().to_string());
                            if let Some(token_endpoint) = discovery.token_endpoint() {
                                secret_data.insert("token_endpoint".to_string(), token_endpoint.to_string());
                            }
                            if let Some(userinfo_endpoint) = discovery.userinfo_endpoint() {
                                secret_data.insert("userinfo_endpoint".to_string(), userinfo_endpoint.to_string());
                            }
                            let secret = Secret {
                                metadata: ObjectMeta {
                                    name: Some(app.metadata.name.as_ref().unwrap().clone()),
                                    namespace: app.metadata.namespace.clone(),
                                    owner_references: Some(vec![app
                                        .controller_owner_ref(&())
                                        .unwrap()]),
                                    ..Default::default()
                                },
                                string_data: Some(secret_data),
                                ..Default::default()
                            };
                            secrets.create(&Default::default(), &secret).await?;

                            patch_status(
                                &apps,
                                app.as_ref(),
                                ApplicationStatus {
                                    id: resp.app_id,
                                    project_id: proj.id.clone(),
                                    organization_id: proj.organization_id,
                                    phase: ApplicationPhase::Ready,
                                },
                            )
                            .await?;

                            recorder
                                .publish(
                                    &Event {
                                        type_: EventType::Normal,
                                        reason: "Created".to_string(),
                                        note: Some("Application created".to_string()),
                                        action: "Creating".to_string(),
                                        secondary: Some(secret.object_ref(&())),
                                    },
                                    &app.object_ref(&()),
                                )
                                .await?;
                        }
                    }
                    CurrentState::ParentNotFound => {
                        info!("project {} not found", app.spec.project_name);

                        recorder
                            .publish(
                                &Event {
                                    type_: EventType::Normal,
                                    reason: "Missing".to_string(),
                                    note: Some("Project does not exist".to_string()),
                                    action: "NotCreated".to_string(),
                                    secondary: None,
                                },
                                &app.object_ref(&()),
                            )
                            .await?;
                    }
                    CurrentState::ParentNotReady(_) => {
                        info!("project {} not ready", app.spec.project_name);

                        recorder
                            .publish(
                                &Event {
                                    type_: EventType::Normal,
                                    reason: "NotCreated".to_string(),
                                    note: Some("Project is not yet created".to_string()),
                                    action: "NotCreated".to_string(),
                                    secondary: None,
                                },
                                &app.object_ref(&()),
                            )
                            .await?;
                    }
                    CurrentState::FoundAdoptable(application, proj) => {
                        debug!("application found, attaching id to resource");

                        patch_status(
                            &apps,
                            app.as_ref(),
                            ApplicationStatus {
                                id: application.id.clone(),
                                project_id: proj.id.clone(),
                                organization_id: proj.organization_id,
                                phase: ApplicationPhase::Ready,
                            },
                        )
                        .await?;

                        recorder
                            .publish(
                                &Event {
                                    type_: EventType::Normal,
                                    reason: "Creating".to_string(),
                                    note: Some("Existing application adopted".to_string()),
                                    action: "Adopted".to_string(),
                                    secondary: None,
                                },
                                &app.object_ref(&()),
                            )
                            .await?;
                    }
                }

                Ok(Action::await_change())
            }
            Finalizer::Cleanup(app) => {
                info!("cleaning up application {}", app.name_any());

                let mut management = ctx.zitadel.builder().build_management_client().await?;

                if let Some(status) = &app.status {
                    let resp = management
                        .remove_app(create_request_with_org_id(
                            RemoveAppRequest {
                                app_id: status.id.clone(),
                                project_id: status.project_id.clone(),
                            },
                            status.organization_id.clone(),
                        ))
                        .await;

                    match resp {
                        Ok(_) => {
                            debug!("application removed");

                            recorder
                                .publish(
                                    &Event {
                                        type_: EventType::Normal,
                                        reason: "DeleteRequested".to_string(),
                                        note: Some(format!(
                                            "Application {} was deleted",
                                            app.name_any()
                                        )),
                                        action: "Deleting".to_string(),
                                        secondary: None,
                                    },
                                    &app.object_ref(&()),
                                )
                                .await?;
                        }
                        Err(e) if e.code() == Code::NotFound => {
                            debug!("application not found");
                        }
                        Err(e) => return Result::Err(Error::ZitadelError(e)),
                    }
                } else {
                    debug!("application never appears to have been created");
                }

                Ok(Action::await_change())
            }
        }
    })
    .await
    .map_err(|e| Error::FinalizerError(Box::new(e)))
}

fn error_policy(_: Arc<Application>, error: &Error, _: Arc<OperatorContext>) -> Action {
    warn!("reconcile failed: {:?}", error);
    Action::requeue(Duration::from_secs(60))
}

pub async fn run(context: Arc<OperatorContext>) {
    let apps = Api::<Application>::all(context.k8s.clone());
    let projs = Api::<Project>::all(context.k8s.clone());
    let secrets = Api::<Secret>::all(context.k8s.clone());
    let controller = Controller::new(apps, Config::default().any_semantic());
    let store = controller.store();
    controller
        .watches_stream(
            metadata_watcher(projs, Config::default()).touched_objects(),
            move |_proj| store.state().into_iter().map(|app| ObjectRef::from_obj(&*app)),
        )
        .owns(secrets, Config::default())
        .shutdown_on_signal()
        .run(reconcile, error_policy, context)
        .filter_map(|x| async move { std::result::Result::ok(x) })
        .for_each(|_| futures::future::ready(()))
        .await;
}
