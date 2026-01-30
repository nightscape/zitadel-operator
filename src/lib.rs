use kube::{
    runtime::events::{Recorder, Reporter},
    Client,
};
use thiserror::Error;
use zitadel::api::{
    clients::{ClientBuilder, ClientError},
    interceptors::ServiceAccountInterceptor,
};

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

#[derive(Clone)]
pub struct ZitadelBuilder {
    url: String,
    interceptor: ServiceAccountInterceptor,
}
impl ZitadelBuilder {
    pub fn new(url: String, interceptor: ServiceAccountInterceptor) -> Self {
        Self { url, interceptor }
    }
    pub fn builder(self: &Self) -> ClientBuilder<ServiceAccountInterceptor> {
        ClientBuilder::new(&self.url).with_interceptor(self.interceptor.clone())
    }
}

#[derive(Clone)]
pub struct OperatorContext {
    pub k8s: Client,
    pub zitadel: ZitadelBuilder,
    pub operator_user_id: String,
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
