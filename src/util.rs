use crate::Result;
use kube::{
    api::{Patch, PatchParams},
    Api, Resource, ResourceExt,
};
use schemars::JsonSchema;
use serde::{
    de::{self, DeserializeOwned},
    Serialize,
};
use serde_json::json;
use std::{env, fmt::Debug, sync::Arc};
use tonic::Request;

const DEFAULT_REQUEUE_SECS: u64 = 300;

pub fn requeue_secs() -> u64 {
    env::var("REQUEUE_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_REQUEUE_SECS)
}

pub async fn patch_status<T: Resource<DynamicType = ()> + de::DeserializeOwned, S: Serialize>(
    api: &Api<T>,
    resource: &T,
    status: S,
) -> Result<(), kube::Error> {
    api.patch_status(
        &resource.name_any(),
        &PatchParams::apply("cntrlr").force(),
        &Patch::Apply(json!({
            "apiVersion": T::api_version(&()),
            "kind": T::kind(&()),
            "status": status
        })),
    )
    .await
    .map(|_| ())
}

pub fn create_request_with_org_id<T>(req: T, org_id: String) -> Request<T> {
    let mut req = Request::new(req);
    req.metadata_mut().insert("x-zitadel-orgid", org_id.parse().unwrap());
    req
}

// TODO: replace by #[schemars(extend(...))] in schemars 1.0.0
pub fn schema_list_is_set<T: JsonSchema>(gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
    serde_json::from_value(serde_json::json!({
        "type": "array",
        "items": T::json_schema(gen),
        "x-kubernetes-list-type": "set"
    }))
    .unwrap()
}

pub trait IsReady {
    fn is_ready(&self) -> bool;
}
pub trait GetStatus {
    type Status;
    fn get_status(&self) -> &Option<Self::Status>;
}
impl<T: GetStatus> GetStatus for Arc<T> {
    type Status = T::Status;
    fn get_status(&self) -> &Option<Self::Status> {
        self.as_ref().get_status()
    }
}

pub trait CurrentStateRetriever<R: Resource + GetStatus, Object: Clone, Parent: Resource + GetStatus> {
    async fn get_object(&mut self, status: &<R as GetStatus>::Status) -> Result<Option<Object>>;
    async fn list_objects(&mut self, resource: &R, parent: &<Parent as GetStatus>::Status) -> Result<Vec<Object>>;
}

pub enum CurrentState<Parent: Resource + GetStatus, Object> {
    ExistsEqual(Object, Parent::Status),
    ExistsUnequal(Object, Parent::Status),
    NotExists(Parent::Status),
    ParentNotFound,
    ParentNotReady(Parent),
    FoundAdoptable(Object, Parent::Status),
}
pub struct CurrentStateParameters<
    R: Resource + GetStatus,
    Parent: Resource + DeserializeOwned + Clone + Debug + IsReady + GetStatus,
    Object: Clone,
    Retriever: CurrentStateRetriever<R, Object, Parent>,
> {
    pub resource: Arc<R>,
    #[allow(dead_code)]
    pub resource_api: Api<R>,
    pub parent_api: Api<Parent>,
    pub parent_name: String,
    pub retriever: Retriever,
    pub is_equal: fn(&Object, &R) -> bool,
}
impl<Parent: Resource + DeserializeOwned + Clone + Debug + IsReady + GetStatus, Object: Clone>
    CurrentState<Parent, Object>
{
    pub async fn determine<R: Resource + GetStatus, Retriever: CurrentStateRetriever<R, Object, Parent>>(
        mut parameters: CurrentStateParameters<R, Parent, Object, Retriever>,
    ) -> Result<CurrentState<Parent, Object>>
    where
        Parent::Status: Clone,
    {
        let parent = parameters.parent_api.get_opt(&parameters.parent_name).await?;
        match parent {
            None => Ok(Self::ParentNotFound),
            Some(parent) => match parent.get_status() {
                Some(parent_status) if parent.is_ready() => {
                    if let Some(status) = parameters.resource.get_status() {
                        let resp = parameters.retriever.get_object(&status).await?;
                        if let Some(resp) = resp {
                            if (parameters.is_equal)(&resp, &parameters.resource) {
                                return Ok(Self::ExistsEqual(resp, parent_status.clone()));
                            } else {
                                return Ok(Self::ExistsUnequal(resp, parent_status.clone()));
                            }
                        }
                    }
                    let matching = parameters
                        .retriever
                        .list_objects(&parameters.resource, parent_status)
                        .await?;
                    match &matching[..] {
                        [object] => return Ok(Self::FoundAdoptable(object.clone(), parent_status.clone())),
                        [] => return Ok(Self::NotExists(parent_status.clone())),
                        _ => panic!("found multiple objects"),
                    }
                }
                _ => Ok(Self::ParentNotReady(parent)),
            },
        }
    }
}
