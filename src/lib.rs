use std::collections::HashMap;
use std::ops::Deref;
use std::sync::{Arc, RwLock};
use std::thread;

use jsonwebtoken::{encode, Algorithm, EncodingKey, Header as JwtHeader};
use kube::{
    runtime::events::{Recorder, Reporter},
    Client,
};
use openidconnect::{
    core::{CoreProviderMetadata, CoreTokenType},
    reqwest::async_http_client,
    EmptyExtraTokenFields, HttpRequest, OAuth2TokenResponse, StandardTokenResponse,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::runtime::Builder;
use tonic::service::Interceptor;
use zitadel::api::clients::{ClientBuilder, ClientError};
use zitadel::credentials::{AuthenticationOptions, ServiceAccount};

#[derive(Error, Debug)]
pub enum Error {
    #[error("SerializationError: {0:?}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Kube Error: {0:?}")]
    KubeError(#[from] kube::Error),

    #[error("Finalizer Error: {0:?}")]
    // NB: awkward type because finalizer::Error embeds the reconciler error (which is this)
    // so boxing this error to break cycles
    FinalizerError(#[from] Box<kube::runtime::finalizer::Error<Error>>),

    #[error("Zitadel connection error: {0:?}")]
    ZitadelConnectionError(#[from] ClientError),

    #[error("Other error: {0}")]
    Other(String),

    #[error("Zitadel error: {0:?}")]
    ZitadelError(#[from] tonic::Status),
}
impl From<Box<dyn std::error::Error>> for Error {
    fn from(e: Box<dyn std::error::Error>) -> Self {
        match e.downcast::<ClientError>() {
            Ok(e) => Error::ZitadelConnectionError(*e),
            Err(e) => Error::Other(e.to_string()),
        }
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

// Mirror of the zitadel crate's private ServiceAccount fields
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ServiceAccountData {
    user_id: String,
    key_id: String,
    key: String,
}

#[derive(Serialize)]
struct JwtClaims {
    iss: String,
    sub: String,
    iat: i64,
    exp: i64,
    aud: String,
}

fn create_scopes(options: &AuthenticationOptions) -> String {
    let mut result = vec!["openid".to_string()];
    for role in &options.roles {
        let scope = format!("urn:zitadel:iam:org:project:role:{role}");
        if !result.contains(&scope) {
            result.push(scope);
        }
    }
    for p_id in &options.project_audiences {
        let scope = format!("urn:zitadel:iam:org:project:id:{p_id}:aud");
        if !result.contains(&scope) {
            result.push(scope);
        }
    }
    for scope in &options.scopes {
        if !result.contains(scope) {
            result.push(scope.clone());
        }
    }
    let api_scope = "urn:zitadel:iam:org:project:id:zitadel:aud".to_string();
    if options.api_access && !result.contains(&api_scope) {
        result.push(api_scope);
    }
    result.join(" ")
}

pub(crate) fn inject_custom_headers(
    headers: &mut openidconnect::http::HeaderMap,
    custom: &HashMap<String, String>,
) {
    for (k, v) in custom {
        headers.insert(
            openidconnect::http::header::HeaderName::from_bytes(k.as_bytes())
                .unwrap_or_else(|_| panic!("invalid header name: {k}")),
            openidconnect::http::header::HeaderValue::from_str(v)
                .unwrap_or_else(|_| panic!("invalid header value for {k}")),
        );
    }
}

pub(crate) async fn discover_metadata(
    base_url: &str,
    custom_headers: &HashMap<String, String>,
) -> std::result::Result<CoreProviderMetadata, String> {
    let discovery_url = format!(
        "{}/.well-known/openid-configuration",
        base_url.trim_end_matches('/')
    );
    let url = openidconnect::url::Url::parse(&discovery_url)
        .map_err(|e| format!("invalid discovery URL: {e}"))?;

    let mut headers = openidconnect::http::HeaderMap::new();
    headers.insert(
        openidconnect::http::header::ACCEPT,
        openidconnect::http::header::HeaderValue::from_static("application/json"),
    );
    inject_custom_headers(&mut headers, custom_headers);

    let response = async_http_client(HttpRequest {
        url,
        method: openidconnect::http::Method::GET,
        headers,
        body: Vec::new(),
    })
    .await
    .map_err(|e| format!("discovery request failed: {e}"))?;

    if response.status_code != openidconnect::http::StatusCode::OK {
        return Err(format!(
            "discovery returned HTTP {} (body: {})",
            response.status_code,
            String::from_utf8_lossy(&response.body)
        ));
    }

    serde_json::from_slice(&response.body)
        .map_err(|e| format!("discovery response parse failed: {e}"))
}

async fn authenticate_sa(
    sa_data: &ServiceAccountData,
    audience: &str,
    options: &AuthenticationOptions,
    custom_headers: &HashMap<String, String>,
) -> std::result::Result<String, String> {
    let metadata = discover_metadata(audience, custom_headers).await?;

    // Use the issuer from discovery as the JWT audience — Zitadel's external URL
    // may differ from the internal URL we connect to (audience parameter).
    let issuer = metadata.issuer().as_str();

    let key = EncodingKey::from_rsa_pem(sa_data.key.as_bytes())
        .map_err(|e| format!("invalid RSA key: {e}"))?;
    let mut header = JwtHeader::new(Algorithm::RS256);
    header.kid = Some(sa_data.key_id.clone());
    let now = time::OffsetDateTime::now_utc();
    let claims = JwtClaims {
        iss: sa_data.user_id.clone(),
        sub: sa_data.user_id.clone(),
        iat: now.unix_timestamp(),
        exp: (now + time::Duration::hours(1)).unix_timestamp(),
        aud: issuer.to_string(),
    };
    let jwt = encode(&header, &claims, &key)
        .map_err(|e| format!("JWT encoding failed: {e}"))?;

    let external_token_url = metadata
        .token_endpoint()
        .ok_or("OIDC document missing token endpoint")?;

    // Rewrite the token endpoint to use the internal base URL (audience) while
    // keeping the path from the discovery document. The Host header override
    // ensures Zitadel recognizes the request.
    let external_parsed = openidconnect::url::Url::parse(external_token_url.as_str())
        .map_err(|e| format!("invalid token URL: {e}"))?;
    let mut url = openidconnect::url::Url::parse(audience)
        .map_err(|e| format!("invalid audience URL: {e}"))?;
    url.set_path(external_parsed.path());
    url.set_query(external_parsed.query());

    let mut req_headers = openidconnect::http::HeaderMap::new();
    req_headers.insert(
        openidconnect::http::header::ACCEPT,
        openidconnect::http::header::HeaderValue::from_static("application/json"),
    );
    req_headers.insert(
        openidconnect::http::header::CONTENT_TYPE,
        openidconnect::http::header::HeaderValue::from_static("application/x-www-form-urlencoded"),
    );
    inject_custom_headers(&mut req_headers, custom_headers);

    let scopes = create_scopes(options);
    let body = serde_urlencoded::to_string([
        ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
        ("assertion", jwt.as_str()),
        ("scope", scopes.as_str()),
    ])
    .map_err(|e| format!("URL encoding failed: {e}"))?;

    let response = async_http_client(HttpRequest {
        url,
        method: openidconnect::http::Method::POST,
        headers: req_headers,
        body: body.into_bytes(),
    })
    .await
    .map_err(|e| format!("token request failed: {e}"))?;

    serde_json::from_slice::<StandardTokenResponse<EmptyExtraTokenFields, CoreTokenType>>(
        &response.body,
    )
    .map_err(|e| format!("token response parse failed: {e}"))
    .map(|r| r.access_token().secret().clone())
}

struct TokenState {
    token: String,
    expiry: time::OffsetDateTime,
}

struct CustomHeaderInterceptorInner {
    sa_data: ServiceAccountData,
    audience: String,
    auth_options: AuthenticationOptions,
    custom_headers: HashMap<String, String>,
    grpc_headers: Vec<(
        tonic::metadata::MetadataKey<tonic::metadata::Ascii>,
        tonic::metadata::MetadataValue<tonic::metadata::Ascii>,
    )>,
    state: RwLock<Option<TokenState>>,
}

#[derive(Clone)]
pub struct CustomHeaderInterceptor {
    inner: Arc<CustomHeaderInterceptorInner>,
}

impl Interceptor for CustomHeaderInterceptor {
    fn call(
        &mut self,
        mut request: tonic::Request<()>,
    ) -> std::result::Result<tonic::Request<()>, tonic::Status> {
        let meta = request.metadata_mut();
        if !meta.contains_key("authorization") {
            let state_guard = self.inner.state.read().unwrap();
            if let Some(state) = state_guard.deref() {
                if state.expiry > time::OffsetDateTime::now_utc() {
                    meta.insert(
                        "authorization",
                        format!("Bearer {}", state.token).parse().unwrap(),
                    );
                    for (key, value) in &self.inner.grpc_headers {
                        meta.insert(key.clone(), value.clone());
                    }
                    return Ok(request);
                }
            }
            drop(state_guard);

            let sa_data = self.inner.sa_data.clone();
            let audience = self.inner.audience.clone();
            let auth_options = self.inner.auth_options.clone();
            let custom_headers = self.inner.custom_headers.clone();

            let token = thread::spawn(move || {
                let rt = Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                rt.block_on(async {
                    authenticate_sa(&sa_data, &audience, &auth_options, &custom_headers).await
                })
            });

            let token = token
                .join()
                .map_err(|_| tonic::Status::internal("token fetch thread panicked"))?
                .map_err(tonic::Status::internal)?;

            let mut state_guard = self.inner.state.write().unwrap();
            *state_guard = Some(TokenState {
                token: token.clone(),
                expiry: time::OffsetDateTime::now_utc() + time::Duration::minutes(59),
            });

            meta.insert(
                "authorization",
                format!("Bearer {}", token).parse().unwrap(),
            );
        }

        for (key, value) in &self.inner.grpc_headers {
            meta.insert(key.clone(), value.clone());
        }

        Ok(request)
    }
}

#[derive(Clone)]
pub struct ZitadelBuilder {
    url: String,
    interceptor: CustomHeaderInterceptor,
}
impl ZitadelBuilder {
    pub fn new(
        url: String,
        sa: &ServiceAccount,
        auth_options: AuthenticationOptions,
        custom_headers: HashMap<String, String>,
    ) -> Self {
        let sa_data: ServiceAccountData =
            serde_json::from_str(&serde_json::to_string(sa).unwrap()).unwrap();

        let grpc_headers: Vec<_> = custom_headers
            .iter()
            .map(|(k, v)| {
                let key: tonic::metadata::MetadataKey<tonic::metadata::Ascii> = k
                    .parse()
                    .unwrap_or_else(|_| panic!("invalid header name: {k}"));
                let value: tonic::metadata::MetadataValue<tonic::metadata::Ascii> = v
                    .parse()
                    .unwrap_or_else(|_| panic!("invalid header value for {k}: {v}"));
                (key, value)
            })
            .collect();

        Self {
            url: url.clone(),
            interceptor: CustomHeaderInterceptor {
                inner: Arc::new(CustomHeaderInterceptorInner {
                    sa_data,
                    audience: url,
                    auth_options,
                    custom_headers,
                    grpc_headers,
                    state: RwLock::new(None),
                }),
            },
        }
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn builder(&self) -> ClientBuilder<CustomHeaderInterceptor> {
        ClientBuilder::new(&self.url).with_interceptor(self.interceptor.clone())
    }
}

#[derive(Clone)]
pub struct OperatorContext {
    pub k8s: Client,
    pub zitadel: ZitadelBuilder,
    pub operator_user_id: String,
    pub custom_headers: HashMap<String, String>,
}
impl OperatorContext {
    pub fn build_recorder(&self) -> Recorder {
        Recorder::new(
            self.k8s.clone(),
            Reporter {
                controller: "zitadel-operator".to_string(),
                instance: None, // TODO
            },
        )
    }
}

pub mod controllers;
pub mod schema;
pub(crate) mod util;
