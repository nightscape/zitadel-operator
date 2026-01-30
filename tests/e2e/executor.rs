use super::state_machine::{AppVariant, ReferenceState, Transition, ValidationError};
use super::TestFixture;
use anyhow::{Context, Result};
use k8s_openapi::api::core::v1::Secret;
use kube::{
    api::{DeleteParams, ListParams, Patch, PatchParams},
    Api,
};
use serde_json::json;
use std::collections::HashMap;
use std::time::Duration;
use tracing::{debug, info};
use zitadel::api::zitadel::org::v2::{ListOrganizationsRequest, OrganizationFieldName};
use zitadel::api::zitadel::management::v1::{
    AddHumanUserRequest, AddOrgMemberRequest, AddProjectRequest, AddProjectRoleRequest,
    AddUserGrantRequest, ListAppsRequest, ListProjectRolesRequest, ListProjectsRequest,
    ListUserGrantRequest, ListUsersRequest, UpdateProjectRequest, UpdateProjectRoleRequest,
};
use zitadel::api::zitadel::project::v1::PrivateLabelingSetting;

/// After an update-only transition (no status phase change to wait for),
/// sleep this long so the controller has time to reconcile.
const UPDATE_PROPAGATION_DELAY: Duration = Duration::from_secs(2);

fn requeue_secs() -> u64 {
    std::env::var("REQUEUE_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300)
}

use zitadel_operator::{
    schema::{
        Application, HumanUser, HumanUserPhase, Organization, OrganizationPhase, Project,
        ProjectPhase, ProjectRole, ProjectRolePhase, UserGrant, UserGrantPhase,
    },
    ZitadelBuilder,
};

fn assert_k8s_rejected<T: std::fmt::Debug>(
    result: std::result::Result<T, kube::Error>,
    errors: &[ValidationError],
) {
    let error_summary: String = errors
        .iter()
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    assert!(
        result.is_err(),
        "Expected K8s to reject resource with validation errors [{}] but patch succeeded",
        error_summary,
    );
    info!("K8s correctly rejected invalid resource: {}", error_summary);
}

fn request_with_org_id<T>(req: T, org_id: &str) -> tonic::Request<T> {
    let mut r = tonic::Request::new(req);
    r.metadata_mut()
        .insert("x-zitadel-orgid", org_id.parse().unwrap());
    r
}

pub struct SystemUnderTest {
    k8s: kube::Client,
    admin_zitadel: ZitadelBuilder,
    operator_user_id: String,
    zitadel_ids: HashMap<String, String>,
}

impl SystemUnderTest {
    pub fn new(fixture: &TestFixture) -> Self {
        Self {
            k8s: fixture.k8s_client.clone(),
            admin_zitadel: fixture.zitadel_builder.clone(),
            operator_user_id: fixture.operator_user_id.clone(),
            zitadel_ids: HashMap::new(),
        }
    }

    async fn resolve_org_zitadel_id(&self, k8s_name: &str) -> Result<String> {
        if let Some(id) = self.zitadel_ids.get(k8s_name) {
            return Ok(id.clone());
        }
        let orgs: Api<Organization> = Api::all(self.k8s.clone());
        let org = orgs.get(k8s_name).await.context("Failed to get org from K8s")?;
        Ok(org.status.as_ref().unwrap().id.clone())
    }

    async fn resolve_project_zitadel_id(&self, k8s_name: &str) -> Result<String> {
        if let Some(id) = self.zitadel_ids.get(k8s_name) {
            return Ok(id.clone());
        }
        let projects: Api<Project> = Api::namespaced(self.k8s.clone(), "default");
        let proj = projects.get(k8s_name).await.context("Failed to get project from K8s")?;
        Ok(proj.status.as_ref().unwrap().id.clone())
    }

    async fn resolve_user_zitadel_id(&self, k8s_name: &str) -> Result<String> {
        if let Some(id) = self.zitadel_ids.get(k8s_name) {
            return Ok(id.clone());
        }
        let users: Api<HumanUser> = Api::namespaced(self.k8s.clone(), "default");
        let user = users.get(k8s_name).await.context("Failed to get user from K8s")?;
        Ok(user.status.as_ref().unwrap().id.clone())
    }

    async fn resolve_org_id_for_project(&self, project_k8s_name: &str, ref_state: &ReferenceState) -> Result<String> {
        let org_k8s_name = ref_state.projects.get(project_k8s_name)
            .map(|p| p.org_k8s_name.clone())
            .context("Project not found in ref state")?;
        self.resolve_org_zitadel_id(&org_k8s_name).await
    }

    pub async fn apply(&mut self, transition: &Transition, ref_state: &ReferenceState) -> Result<()> {
        let validation_errors = transition.validation_errors();
        match transition {
            Transition::CreateOrg {
                k8s_name,
                display_name,
            } => {
                info!("Creating organization {} ({})", k8s_name, display_name);
                let orgs: Api<Organization> = Api::all(self.k8s.clone());

                let org = json!({
                    "apiVersion": "zitadel.org/v1alpha",
                    "kind": "Organization",
                    "metadata": {
                        "name": k8s_name
                    },
                    "spec": {
                        "name": display_name
                    }
                });

                let result = orgs
                    .patch(
                        k8s_name,
                        &PatchParams::apply("e2e-test").force(),
                        &Patch::Apply(&org),
                    )
                    .await;

                if validation_errors.is_empty() {
                    result.context("Failed to create organization")?;
                    self.wait_for_org_ready(k8s_name).await?;
                } else {
                    assert_k8s_rejected(result, &validation_errors);
                }
            }
            Transition::UpdateOrgName {
                k8s_name,
                new_display_name,
            } => {
                info!(
                    "Updating organization {} to {}",
                    k8s_name, new_display_name
                );
                let orgs: Api<Organization> = Api::all(self.k8s.clone());

                let org = json!({
                    "apiVersion": "zitadel.org/v1alpha",
                    "kind": "Organization",
                    "metadata": {
                        "name": k8s_name
                    },
                    "spec": {
                        "name": new_display_name
                    }
                });

                orgs.patch(
                    k8s_name,
                    &PatchParams::apply("e2e-test").force(),
                    &Patch::Apply(&org),
                )
                .await
                .context("Failed to update organization")?;

                tokio::time::sleep(UPDATE_PROPAGATION_DELAY).await;
            }
            Transition::DeleteOrg { k8s_name } => {
                info!("Deleting organization {}", k8s_name);

                // The operator doesn't cascade-delete child CRs, so we must
                // delete children first while the org still exists (finalizers
                // need the org to resolve ZITADEL context).
                self.delete_children_of_org(k8s_name).await?;

                let orgs: Api<Organization> = Api::all(self.k8s.clone());
                orgs.delete(k8s_name, &DeleteParams::default())
                    .await
                    .context("Failed to delete organization")?;

                self.wait_for_org_deleted(k8s_name).await?;
            }
            Transition::CreateProject {
                k8s_name,
                display_name,
                org_k8s_name,
                project_role_assertion,
            } => {
                info!(
                    "Creating project {} ({}) in org {} (role_assertion={})",
                    k8s_name, display_name, org_k8s_name, project_role_assertion
                );
                let projects: Api<Project> = Api::namespaced(self.k8s.clone(), "default");

                let project = json!({
                    "apiVersion": "zitadel.org/v1alpha",
                    "kind": "Project",
                    "metadata": {
                        "name": k8s_name,
                        "namespace": "default"
                    },
                    "spec": {
                        "name": display_name,
                        "organizationName": org_k8s_name,
                        "projectRoleAssertion": project_role_assertion
                    }
                });

                projects
                    .patch(
                        k8s_name,
                        &PatchParams::apply("e2e-test").force(),
                        &Patch::Apply(&project),
                    )
                    .await
                    .context("Failed to create project")?;

                self.wait_for_project_ready(k8s_name).await?;
            }
            Transition::UpdateProject {
                k8s_name,
                new_display_name,
                new_project_role_assertion,
            } => {
                info!(
                    "Updating project {} to {} (role_assertion={})",
                    k8s_name, new_display_name, new_project_role_assertion
                );
                let projects: Api<Project> = Api::namespaced(self.k8s.clone(), "default");

                let current = projects
                    .get(k8s_name)
                    .await
                    .context("Failed to get project")?;

                let project = json!({
                    "apiVersion": "zitadel.org/v1alpha",
                    "kind": "Project",
                    "metadata": {
                        "name": k8s_name,
                        "namespace": "default"
                    },
                    "spec": {
                        "name": new_display_name,
                        "organizationName": current.spec.organization_name,
                        "projectRoleAssertion": new_project_role_assertion
                    }
                });

                projects
                    .patch(
                        k8s_name,
                        &PatchParams::apply("e2e-test").force(),
                        &Patch::Apply(&project),
                    )
                    .await
                    .context("Failed to update project")?;

                tokio::time::sleep(UPDATE_PROPAGATION_DELAY).await;
            }
            Transition::DeleteProject { k8s_name } => {
                info!("Deleting project {}", k8s_name);

                self.delete_children_of_project(k8s_name).await?;

                let projects: Api<Project> = Api::namespaced(self.k8s.clone(), "default");
                projects
                    .delete(k8s_name, &DeleteParams::default())
                    .await
                    .context("Failed to delete project")?;

                self.wait_for_project_deleted(k8s_name).await?;
            }
            Transition::CreateProjectRole {
                k8s_name,
                role_key,
                display_name,
                group,
                project_k8s_name,
            } => {
                info!(
                    "Creating project role {} ({}) in project {} (group={:?})",
                    k8s_name, role_key, project_k8s_name, group
                );
                let roles: Api<ProjectRole> = Api::namespaced(self.k8s.clone(), "default");

                let role = json!({
                    "apiVersion": "zitadel.org/v1alpha",
                    "kind": "ProjectRole",
                    "metadata": {
                        "name": k8s_name,
                        "namespace": "default"
                    },
                    "spec": {
                        "key": role_key,
                        "displayName": display_name,
                        "group": group.clone().unwrap_or_default(),
                        "projectName": project_k8s_name
                    }
                });

                roles
                    .patch(
                        k8s_name,
                        &PatchParams::apply("e2e-test").force(),
                        &Patch::Apply(&role),
                    )
                    .await
                    .context("Failed to create project role")?;

                self.wait_for_project_role_ready(k8s_name).await?;
            }
            Transition::UpdateProjectRole {
                k8s_name,
                new_display_name,
                new_group,
            } => {
                info!(
                    "Updating project role {} to {} (group={:?})",
                    k8s_name, new_display_name, new_group
                );
                let roles: Api<ProjectRole> = Api::namespaced(self.k8s.clone(), "default");

                let current = roles
                    .get(k8s_name)
                    .await
                    .context("Failed to get project role")?;

                let role = json!({
                    "apiVersion": "zitadel.org/v1alpha",
                    "kind": "ProjectRole",
                    "metadata": {
                        "name": k8s_name,
                        "namespace": "default"
                    },
                    "spec": {
                        "key": current.spec.key,
                        "displayName": new_display_name,
                        "group": new_group.clone().unwrap_or_default(),
                        "projectName": current.spec.project_name
                    }
                });

                roles
                    .patch(
                        k8s_name,
                        &PatchParams::apply("e2e-test").force(),
                        &Patch::Apply(&role),
                    )
                    .await
                    .context("Failed to update project role")?;

                tokio::time::sleep(UPDATE_PROPAGATION_DELAY).await;
            }
            Transition::DeleteProjectRole { k8s_name } => {
                info!("Deleting project role {}", k8s_name);
                let roles: Api<ProjectRole> = Api::namespaced(self.k8s.clone(), "default");

                roles
                    .delete(k8s_name, &DeleteParams::default())
                    .await
                    .context("Failed to delete project role")?;

                self.wait_for_project_role_deleted(k8s_name).await?;
            }
            Transition::CreateHumanUser {
                k8s_name,
                username,
                given_name,
                family_name,
                nick_name,
                gender,
                preferred_language,
                org_k8s_name,
            } => {
                info!(
                    "Creating human user {} ({}) in org {}",
                    k8s_name, username, org_k8s_name
                );
                let users: Api<HumanUser> = Api::namespaced(self.k8s.clone(), "default");

                let mut profile = serde_json::Map::new();
                profile.insert("givenName".to_string(), json!(given_name));
                profile.insert("familyName".to_string(), json!(family_name));
                if let Some(nn) = nick_name {
                    profile.insert("nickName".to_string(), json!(nn));
                }
                if let Some(g) = gender {
                    profile.insert("gender".to_string(), json!(g));
                }
                if let Some(pl) = preferred_language {
                    profile.insert("preferredLanguage".to_string(), json!(pl));
                }

                let user = json!({
                    "apiVersion": "zitadel.org/v1alpha",
                    "kind": "HumanUser",
                    "metadata": {
                        "name": k8s_name,
                        "namespace": "default"
                    },
                    "spec": {
                        "username": username,
                        "organizationName": org_k8s_name,
                        "profile": profile,
                        "email": {
                            "email": username,
                            "isVerified": true
                        }
                    }
                });

                let result = users
                    .patch(
                        k8s_name,
                        &PatchParams::apply("e2e-test").force(),
                        &Patch::Apply(&user),
                    )
                    .await;

                if validation_errors.is_empty() {
                    result.context("Failed to create human user")?;
                    self.wait_for_human_user_ready(k8s_name).await?;
                } else {
                    assert_k8s_rejected(result, &validation_errors);
                }
            }
            Transition::DeleteHumanUser { k8s_name } => {
                info!("Deleting human user {}", k8s_name);
                let users: Api<HumanUser> = Api::namespaced(self.k8s.clone(), "default");

                users
                    .delete(k8s_name, &DeleteParams::default())
                    .await
                    .context("Failed to delete human user")?;

                self.wait_for_human_user_deleted(k8s_name).await?;
            }
            Transition::CreateUserGrant {
                k8s_name,
                user_k8s_name,
                project_k8s_name,
                role_keys,
            } => {
                info!(
                    "Creating user grant {} for user {} in project {} with roles {:?}",
                    k8s_name, user_k8s_name, project_k8s_name, role_keys
                );
                let grants: Api<UserGrant> = Api::namespaced(self.k8s.clone(), "default");

                let grant = json!({
                    "apiVersion": "zitadel.org/v1alpha",
                    "kind": "UserGrant",
                    "metadata": {
                        "name": k8s_name,
                        "namespace": "default"
                    },
                    "spec": {
                        "userName": user_k8s_name,
                        "projectName": project_k8s_name,
                        "roleKeys": role_keys
                    }
                });

                grants
                    .patch(
                        k8s_name,
                        &PatchParams::apply("e2e-test").force(),
                        &Patch::Apply(&grant),
                    )
                    .await
                    .context("Failed to create user grant")?;

                self.wait_for_user_grant_ready(k8s_name).await?;
            }
            Transition::UpdateUserGrantRoles {
                k8s_name,
                new_role_keys,
            } => {
                info!(
                    "Updating user grant {} roles to {:?}",
                    k8s_name, new_role_keys
                );
                let grants: Api<UserGrant> = Api::namespaced(self.k8s.clone(), "default");

                let current = grants
                    .get(k8s_name)
                    .await
                    .context("Failed to get user grant")?;

                let grant = json!({
                    "apiVersion": "zitadel.org/v1alpha",
                    "kind": "UserGrant",
                    "metadata": {
                        "name": k8s_name,
                        "namespace": "default"
                    },
                    "spec": {
                        "userName": current.spec.user_name,
                        "projectName": current.spec.project_name,
                        "roleKeys": new_role_keys
                    }
                });

                grants
                    .patch(
                        k8s_name,
                        &PatchParams::apply("e2e-test").force(),
                        &Patch::Apply(&grant),
                    )
                    .await
                    .context("Failed to update user grant")?;

                tokio::time::sleep(UPDATE_PROPAGATION_DELAY).await;
            }
            Transition::DeleteUserGrant { k8s_name } => {
                info!("Deleting user grant {}", k8s_name);
                let grants: Api<UserGrant> = Api::namespaced(self.k8s.clone(), "default");

                grants
                    .delete(k8s_name, &DeleteParams::default())
                    .await
                    .context("Failed to delete user grant")?;

                self.wait_for_user_grant_deleted(k8s_name).await?;
            }
            Transition::CreateApp {
                k8s_name,
                display_name,
                project_k8s_name,
                app_variant,
            } => {
                info!(
                    "Creating {:?} app {} ({}) in project {}",
                    app_variant, k8s_name, display_name, project_k8s_name
                );
                let apps: Api<Application> = Api::namespaced(self.k8s.clone(), "default");

                let app = match app_variant {
                    AppVariant::Oidc => json!({
                        "apiVersion": "zitadel.org/v1alpha",
                        "kind": "Application",
                        "metadata": {
                            "name": k8s_name,
                            "namespace": "default"
                        },
                        "spec": {
                            "name": display_name,
                            "projectName": project_k8s_name,
                            "oidc": {
                                "redirectUris": ["http://localhost:8080/callback"],
                                "responseTypes": ["Code"],
                                "grantTypes": ["AuthorizationCode"],
                                "devMode": false
                            }
                        }
                    }),
                    AppVariant::Api => json!({
                        "apiVersion": "zitadel.org/v1alpha",
                        "kind": "Application",
                        "metadata": {
                            "name": k8s_name,
                            "namespace": "default"
                        },
                        "spec": {
                            "name": display_name,
                            "projectName": project_k8s_name,
                            "api": {
                                "method": "Basic"
                            }
                        }
                    }),
                };

                apps.patch(
                    k8s_name,
                    &PatchParams::apply("e2e-test").force(),
                    &Patch::Apply(&app),
                )
                .await
                .context("Failed to create application")?;

                self.wait_for_app_ready(k8s_name).await?;
            }
            Transition::UpdateApp {
                k8s_name,
                new_display_name,
                new_dev_mode,
            } => {
                info!(
                    "Updating app {} to {} (devMode={})",
                    k8s_name, new_display_name, new_dev_mode
                );
                let apps: Api<Application> = Api::namespaced(self.k8s.clone(), "default");

                let current = apps
                    .get(k8s_name)
                    .await
                    .context("Failed to get application")?;

                let app = json!({
                    "apiVersion": "zitadel.org/v1alpha",
                    "kind": "Application",
                    "metadata": {
                        "name": k8s_name,
                        "namespace": "default"
                    },
                    "spec": {
                        "name": new_display_name,
                        "projectName": current.spec.project_name,
                        "oidc": {
                            "redirectUris": ["http://localhost:8080/callback"],
                            "responseTypes": ["Code"],
                            "grantTypes": ["AuthorizationCode"],
                            "devMode": new_dev_mode
                        }
                    }
                });

                apps.patch(
                    k8s_name,
                    &PatchParams::apply("e2e-test").force(),
                    &Patch::Apply(&app),
                )
                .await
                .context("Failed to update application")?;

                tokio::time::sleep(UPDATE_PROPAGATION_DELAY).await;
            }
            Transition::DeleteApp { k8s_name } => {
                info!("Deleting app {}", k8s_name);
                let apps: Api<Application> = Api::namespaced(self.k8s.clone(), "default");

                apps.delete(k8s_name, &DeleteParams::default())
                    .await
                    .context("Failed to delete application")?;

                self.wait_for_app_deleted(k8s_name).await?;
            }

            // --- Zitadel-direct operations ---

            Transition::ZitadelCreateOrg { k8s_name, display_name } => {
                info!("ZitadelCreate org {} ({})", k8s_name, display_name);
                let mut organization = self.admin_zitadel.builder().build_organization_client().await
                    .map_err(|e| anyhow::anyhow!("{:?}", e))?;

                let resp = organization.add_organization(
                    zitadel::api::zitadel::org::v2::AddOrganizationRequest {
                        name: display_name.clone(),
                        admins: Vec::new(),
                    },
                ).await.map_err(|e| anyhow::anyhow!("{:?}", e))?.into_inner();

                let new_org_id = resp.organization_id.clone();

                let mut management = self.admin_zitadel.builder().build_management_client().await
                    .map_err(|e| anyhow::anyhow!("{:?}", e))?;
                management.add_org_member(request_with_org_id(
                    AddOrgMemberRequest {
                        user_id: self.operator_user_id.clone(),
                        roles: vec!["ORG_OWNER".to_string()],
                    },
                    &new_org_id,
                )).await.map_err(|e| anyhow::anyhow!("{:?}", e))?;
                info!("Added operator SA as ORG_OWNER of new org {}", new_org_id);

                self.zitadel_ids.insert(k8s_name.clone(), new_org_id);
            }

            Transition::ZitadelCreateProject { k8s_name, display_name, org_k8s_name, project_role_assertion } => {
                info!("ZitadelCreate project {} ({}) in org {}", k8s_name, display_name, org_k8s_name);
                let mut management = self.admin_zitadel.builder().build_management_client().await
                    .map_err(|e| anyhow::anyhow!("{:?}", e))?;
                let org_id = self.resolve_org_zitadel_id(org_k8s_name).await?;

                let resp = management.add_project(request_with_org_id(
                    AddProjectRequest {
                        name: display_name.clone(),
                        project_role_assertion: *project_role_assertion,
                        project_role_check: false,
                        has_project_check: false,
                        private_labeling_setting: PrivateLabelingSetting::Unspecified.into(),
                    },
                    &org_id,
                )).await.map_err(|e| anyhow::anyhow!("{:?}", e))?.into_inner();

                self.zitadel_ids.insert(k8s_name.clone(), resp.id);
            }

            Transition::ZitadelCreateProjectRole { k8s_name, role_key, display_name, group, project_k8s_name } => {
                info!("ZitadelCreate project role {} ({}) in project {}", k8s_name, role_key, project_k8s_name);
                let mut management = self.admin_zitadel.builder().build_management_client().await
                    .map_err(|e| anyhow::anyhow!("{:?}", e))?;
                let project_id = self.resolve_project_zitadel_id(project_k8s_name).await?;
                let org_id = self.resolve_org_id_for_project(project_k8s_name, ref_state).await?;

                management.add_project_role(request_with_org_id(
                    AddProjectRoleRequest {
                        project_id: project_id.clone(),
                        role_key: role_key.clone(),
                        display_name: display_name.clone(),
                        group: group.clone().unwrap_or_default(),
                    },
                    &org_id,
                )).await.map_err(|e| anyhow::anyhow!("{:?}", e))?;
            }

            Transition::ZitadelCreateHumanUser { k8s_name, username, given_name, family_name, nick_name, gender, preferred_language, org_k8s_name } => {
                info!("ZitadelCreate human user {} ({}) in org {}", k8s_name, username, org_k8s_name);
                let mut management = self.admin_zitadel.builder().build_management_client().await
                    .map_err(|e| anyhow::anyhow!("{:?}", e))?;
                let org_id = self.resolve_org_zitadel_id(org_k8s_name).await?;

                let display_name_val = format!("{} {}", given_name, family_name);
                let gender_val: i32 = match gender.as_deref() {
                    Some("Female") => zitadel::api::zitadel::user::v1::Gender::Female as i32,
                    Some("Male") => zitadel::api::zitadel::user::v1::Gender::Male as i32,
                    Some("Diverse") => zitadel::api::zitadel::user::v1::Gender::Diverse as i32,
                    _ => zitadel::api::zitadel::user::v1::Gender::Unspecified as i32,
                };

                let resp = management.add_human_user(request_with_org_id(
                    AddHumanUserRequest {
                        user_name: username.clone(),
                        profile: Some(
                            zitadel::api::zitadel::management::v1::add_human_user_request::Profile {
                                first_name: given_name.clone(),
                                last_name: family_name.clone(),
                                nick_name: nick_name.clone().unwrap_or_default(),
                                display_name: display_name_val,
                                preferred_language: preferred_language.clone().unwrap_or_else(|| "en".to_string()),
                                gender: gender_val,
                            },
                        ),
                        email: Some(
                            zitadel::api::zitadel::management::v1::add_human_user_request::Email {
                                email: username.clone(),
                                is_email_verified: true,
                            },
                        ),
                        phone: None,
                        initial_password: String::new(),
                    },
                    &org_id,
                )).await.map_err(|e| anyhow::anyhow!("{:?}", e))?.into_inner();

                self.zitadel_ids.insert(k8s_name.clone(), resp.user_id);
            }

            Transition::ZitadelCreateUserGrant { k8s_name, user_k8s_name, project_k8s_name, role_keys } => {
                info!("ZitadelCreate user grant {} for user {} in project {}", k8s_name, user_k8s_name, project_k8s_name);
                let mut management = self.admin_zitadel.builder().build_management_client().await
                    .map_err(|e| anyhow::anyhow!("{:?}", e))?;
                let user_id = self.resolve_user_zitadel_id(user_k8s_name).await?;
                let project_id = self.resolve_project_zitadel_id(project_k8s_name).await?;
                let org_id = self.resolve_org_id_for_project(project_k8s_name, ref_state).await?;

                let resp = management.add_user_grant(request_with_org_id(
                    AddUserGrantRequest {
                        user_id: user_id.clone(),
                        project_id: project_id.clone(),
                        project_grant_id: String::new(),
                        role_keys: role_keys.clone(),
                    },
                    &org_id,
                )).await.map_err(|e| anyhow::anyhow!("{:?}", e))?.into_inner();

                self.zitadel_ids.insert(k8s_name.clone(), resp.user_grant_id);
            }

            Transition::ZitadelCreateApp { k8s_name, display_name, project_k8s_name, app_variant } => {
                info!("ZitadelCreate {:?} app {} ({}) in project {}", app_variant, k8s_name, display_name, project_k8s_name);
                let mut management = self.admin_zitadel.builder().build_management_client().await
                    .map_err(|e| anyhow::anyhow!("{:?}", e))?;
                let project_id = self.resolve_project_zitadel_id(project_k8s_name).await?;
                let org_id = self.resolve_org_id_for_project(project_k8s_name, ref_state).await?;

                let app_id = match app_variant {
                    AppVariant::Oidc => {
                        let resp = management.add_oidc_app(request_with_org_id(
                            zitadel::api::zitadel::management::v1::AddOidcAppRequest {
                                project_id: project_id.clone(),
                                name: display_name.clone(),
                                redirect_uris: vec!["http://localhost:8080/callback".to_string()],
                                response_types: vec![zitadel::api::zitadel::app::v1::OidcResponseType::Code as i32],
                                grant_types: vec![zitadel::api::zitadel::app::v1::OidcGrantType::AuthorizationCode as i32],
                                app_type: zitadel::api::zitadel::app::v1::OidcAppType::Web as i32,
                                auth_method_type: zitadel::api::zitadel::app::v1::OidcAuthMethodType::Basic as i32,
                                post_logout_redirect_uris: vec![],
                                version: zitadel::api::zitadel::app::v1::OidcVersion::OidcVersion10 as i32,
                                dev_mode: false,
                                access_token_type: zitadel::api::zitadel::app::v1::OidcTokenType::Bearer as i32,
                                access_token_role_assertion: false,
                                id_token_role_assertion: false,
                                id_token_userinfo_assertion: false,
                                clock_skew: None,
                                additional_origins: vec![],
                                skip_native_app_success_page: false,
                                back_channel_logout_uri: String::new(),
                            },
                            &org_id,
                        )).await.map_err(|e| anyhow::anyhow!("{:?}", e))?.into_inner();
                        resp.app_id
                    }
                    AppVariant::Api => {
                        let resp = management.add_api_app(request_with_org_id(
                            zitadel::api::zitadel::management::v1::AddApiAppRequest {
                                project_id: project_id.clone(),
                                name: display_name.clone(),
                                auth_method_type: zitadel::api::zitadel::app::v1::ApiAuthMethodType::Basic as i32,
                            },
                            &org_id,
                        )).await.map_err(|e| anyhow::anyhow!("{:?}", e))?.into_inner();
                        resp.app_id
                    }
                };

                self.zitadel_ids.insert(k8s_name.clone(), app_id);
            }

            Transition::ZitadelUpdateProject { k8s_name, new_project_role_assertion } => {
                info!("ZitadelUpdate project {} (pra={})", k8s_name, new_project_role_assertion);
                let mut management = self.admin_zitadel.builder().build_management_client().await
                    .map_err(|e| anyhow::anyhow!("{:?}", e))?;
                let project_id = self.resolve_project_zitadel_id(k8s_name).await?;
                let org_id = self.resolve_org_id_for_project(k8s_name, ref_state).await?;

                // Fetch current project to preserve other fields
                let current = management.get_project_by_id(request_with_org_id(
                    zitadel::api::zitadel::management::v1::GetProjectByIdRequest { id: project_id.clone() },
                    &org_id,
                )).await.map_err(|e| anyhow::anyhow!("{:?}", e))?.into_inner().project.unwrap();

                management.update_project(request_with_org_id(
                    UpdateProjectRequest {
                        id: project_id,
                        name: current.name,
                        project_role_assertion: *new_project_role_assertion,
                        project_role_check: current.project_role_check,
                        has_project_check: current.has_project_check,
                        private_labeling_setting: current.private_labeling_setting,
                    },
                    &org_id,
                )).await.map_err(|e| anyhow::anyhow!("{:?}", e))?;

                if !ref_state.zitadel_only.contains(k8s_name) {
                    let wait_secs = requeue_secs() + 2;
                    info!("Waiting {}s for periodic reconcile to auto-fix drift", wait_secs);
                    tokio::time::sleep(Duration::from_secs(wait_secs)).await;
                }
            }

            Transition::ZitadelUpdateProjectRole { k8s_name, new_display_name, new_group } => {
                info!("ZitadelUpdate project role {} to {} (group={:?})", k8s_name, new_display_name, new_group);
                let mut management = self.admin_zitadel.builder().build_management_client().await
                    .map_err(|e| anyhow::anyhow!("{:?}", e))?;

                let role_ref = ref_state.project_roles.get(k8s_name)
                    .context("Role not found in ref state")?;
                let project_id = self.resolve_project_zitadel_id(&role_ref.project_k8s_name).await?;
                let org_id = self.resolve_org_id_for_project(&role_ref.project_k8s_name, ref_state).await?;

                management.update_project_role(request_with_org_id(
                    UpdateProjectRoleRequest {
                        project_id,
                        role_key: role_ref.role_key.clone(),
                        display_name: new_display_name.clone(),
                        group: new_group.clone().unwrap_or_default(),
                    },
                    &org_id,
                )).await.map_err(|e| anyhow::anyhow!("{:?}", e))?;

                if !ref_state.zitadel_only.contains(k8s_name) {
                    let wait_secs = requeue_secs() + 2;
                    info!("Waiting {}s for periodic reconcile to auto-fix drift", wait_secs);
                    tokio::time::sleep(Duration::from_secs(wait_secs)).await;
                }
            }
        }
        Ok(())
    }

    pub async fn verify(&self, expected: &ReferenceState) -> Result<()> {
        let mut org_client = self
            .admin_zitadel
            .builder()
            .build_organization_client()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to build org client: {:?}", e))?;

        let actual_orgs = org_client
            .list_organizations(ListOrganizationsRequest {
                queries: vec![],
                query: None,
                sorting_column: OrganizationFieldName::Unspecified as i32,
            })
            .await?
            .into_inner();

        // Exclude system org and the default org created at ZITADEL init
        let test_orgs: Vec<_> = actual_orgs
            .result
            .iter()
            .filter(|o| o.name != "ZITADEL" && o.name != "E2E")
            .collect();

        debug!(
            "Found {} orgs in ZITADEL (excluding system), expected {}",
            test_orgs.len(),
            expected.organizations.len()
        );

        assert_eq!(
            test_orgs.len(),
            expected.organizations.len(),
            "Organization count mismatch: ZITADEL has {:?}, expected {:?}",
            test_orgs.iter().map(|o| &o.name).collect::<Vec<_>>(),
            expected
                .organizations
                .values()
                .map(|o| &o.display_name)
                .collect::<Vec<_>>()
        );

        for (_k8s_name, expected_org) in &expected.organizations {
            let found = test_orgs.iter().any(|o| o.name == expected_org.display_name);
            assert!(
                found,
                "Expected org with display name '{}' not found in ZITADEL",
                expected_org.display_name
            );
        }

        // Build org_id map: display_name -> zitadel id
        let org_id_map: HashMap<String, String> = test_orgs
            .iter()
            .map(|o| (o.name.clone(), o.id.clone()))
            .collect();

        let mut management = self
            .admin_zitadel
            .builder()
            .build_management_client()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to build management client: {:?}", e))?;

        // Group expected resources by org
        for (_k8s_name, expected_org) in &expected.organizations {
            let org_id = &org_id_map[&expected_org.display_name];

            // Verify projects in this org
            let expected_projects: Vec<_> = expected
                .projects
                .iter()
                .filter(|(_, p)| {
                    expected
                        .organizations
                        .get(&p.org_k8s_name)
                        .map(|o| o.display_name == expected_org.display_name)
                        .unwrap_or(false)
                })
                .collect();

            let actual_projects = management
                .list_projects(request_with_org_id(
                    ListProjectsRequest {
                        query: None,
                        queries: vec![],
                    },
                    org_id,
                ))
                .await?
                .into_inner()
                .result;

            assert_eq!(
                actual_projects.len(),
                expected_projects.len(),
                "Project count mismatch in org '{}': ZITADEL has {:?}, expected {:?}",
                expected_org.display_name,
                actual_projects.iter().map(|p| &p.name).collect::<Vec<_>>(),
                expected_projects.iter().map(|(_, p)| &p.display_name).collect::<Vec<_>>()
            );

            // Build project_id map: display_name -> zitadel project id
            let project_id_map: HashMap<String, String> = actual_projects
                .iter()
                .map(|p| (p.name.clone(), p.id.clone()))
                .collect();

            for (_proj_k8s, expected_proj) in &expected_projects {
                let actual = actual_projects
                    .iter()
                    .find(|p| p.name == expected_proj.display_name);
                assert!(
                    actual.is_some(),
                    "Expected project '{}' not found in org '{}'",
                    expected_proj.display_name, expected_org.display_name
                );
                let actual = actual.unwrap();
                assert_eq!(
                    actual.project_role_assertion, expected_proj.project_role_assertion,
                    "project_role_assertion mismatch for project '{}'",
                    expected_proj.display_name
                );
            }

            // Verify project roles per project in this org
            for (proj_k8s_name, expected_proj) in &expected_projects {
                let project_id = &project_id_map[&expected_proj.display_name];

                let expected_roles: Vec<_> = expected
                    .project_roles
                    .values()
                    .filter(|r| &r.project_k8s_name == *proj_k8s_name)
                    .collect();

                let actual_roles = management
                    .list_project_roles(request_with_org_id(
                        ListProjectRolesRequest {
                            project_id: project_id.clone(),
                            query: None,
                            queries: vec![],
                        },
                        org_id,
                    ))
                    .await?
                    .into_inner()
                    .result;

                assert_eq!(
                    actual_roles.len(),
                    expected_roles.len(),
                    "Role count mismatch for project '{}': ZITADEL has {:?}, expected {:?}",
                    expected_proj.display_name,
                    actual_roles.iter().map(|r| &r.key).collect::<Vec<_>>(),
                    expected_roles.iter().map(|r| &r.role_key).collect::<Vec<_>>()
                );

                for expected_role in &expected_roles {
                    let actual = actual_roles
                        .iter()
                        .find(|r| r.key == expected_role.role_key);
                    assert!(
                        actual.is_some(),
                        "Expected role key '{}' not found in project '{}'",
                        expected_role.role_key, expected_proj.display_name
                    );
                    let actual = actual.unwrap();
                    assert_eq!(
                        actual.display_name, expected_role.display_name,
                        "Role display_name mismatch for key '{}'",
                        expected_role.role_key
                    );
                    assert_eq!(
                        actual.group,
                        expected_role.group.clone().unwrap_or_default(),
                        "Role group mismatch for key '{}'",
                        expected_role.role_key
                    );
                }

                // Verify apps per project
                let expected_apps: Vec<_> = expected
                    .applications
                    .values()
                    .filter(|a| &a.project_k8s_name == *proj_k8s_name)
                    .collect();

                let actual_apps = management
                    .list_apps(request_with_org_id(
                        ListAppsRequest {
                            project_id: project_id.clone(),
                            query: None,
                            queries: vec![],
                        },
                        org_id,
                    ))
                    .await?
                    .into_inner()
                    .result;

                assert_eq!(
                    actual_apps.len(),
                    expected_apps.len(),
                    "App count mismatch for project '{}': ZITADEL has {:?}, expected {:?}",
                    expected_proj.display_name,
                    actual_apps.iter().map(|a| &a.name).collect::<Vec<_>>(),
                    expected_apps.iter().map(|a| &a.display_name).collect::<Vec<_>>()
                );

                for expected_app in &expected_apps {
                    let actual = actual_apps
                        .iter()
                        .find(|a| a.name == expected_app.display_name);
                    assert!(
                        actual.is_some(),
                        "Expected app '{}' not found in project '{}'",
                        expected_app.display_name, expected_proj.display_name
                    );
                    let actual = actual.unwrap();
                    if expected_app.app_variant == AppVariant::Oidc {
                        if let Some(zitadel::api::zitadel::app::v1::app::Config::OidcConfig(ref oidc)) =
                            actual.config
                        {
                            assert_eq!(
                                oidc.dev_mode, expected_app.dev_mode,
                                "dev_mode mismatch for OIDC app '{}'",
                                expected_app.display_name
                            );
                        }
                    }
                }
            }

            // Verify users in this org
            let expected_users: Vec<_> = expected
                .human_users
                .values()
                .filter(|u| {
                    expected
                        .organizations
                        .get(&u.org_k8s_name)
                        .map(|o| o.display_name == expected_org.display_name)
                        .unwrap_or(false)
                })
                .collect();

            let actual_users = management
                .list_users(request_with_org_id(
                    ListUsersRequest {
                        query: None,
                        sorting_column: 0,
                        queries: vec![],
                    },
                    org_id,
                ))
                .await?
                .into_inner()
                .result;

            assert_eq!(
                actual_users.len(),
                expected_users.len(),
                "User count mismatch in org '{}': ZITADEL has {:?}, expected {:?}",
                expected_org.display_name,
                actual_users.iter().map(|u| &u.user_name).collect::<Vec<_>>(),
                expected_users.iter().map(|u| &u.username).collect::<Vec<_>>()
            );

            for expected_user in &expected_users {
                let actual = actual_users
                    .iter()
                    .find(|u| u.user_name == expected_user.username);
                assert!(
                    actual.is_some(),
                    "Expected user '{}' not found in org '{}'",
                    expected_user.username, expected_org.display_name
                );
                let actual = actual.unwrap();
                if let Some(zitadel::api::zitadel::user::v1::user::Type::Human(ref human)) =
                    actual.r#type
                {
                    if let Some(ref profile) = human.profile {
                        assert_eq!(
                            profile.first_name, expected_user.given_name,
                            "given_name mismatch for user '{}'",
                            expected_user.username
                        );
                        assert_eq!(
                            profile.last_name, expected_user.family_name,
                            "family_name mismatch for user '{}'",
                            expected_user.username
                        );
                        if let Some(ref nn) = expected_user.nick_name {
                            assert_eq!(
                                profile.nick_name, *nn,
                                "nick_name mismatch for user '{}'",
                                expected_user.username
                            );
                        }
                        if let Some(ref pl) = expected_user.preferred_language {
                            assert_eq!(
                                profile.preferred_language, *pl,
                                "preferred_language mismatch for user '{}'",
                                expected_user.username
                            );
                        }
                        if let Some(ref g) = expected_user.gender {
                            let expected_gender = match g.as_str() {
                                "Female" => zitadel::api::zitadel::user::v1::Gender::Female as i32,
                                "Male" => zitadel::api::zitadel::user::v1::Gender::Male as i32,
                                "Diverse" => zitadel::api::zitadel::user::v1::Gender::Diverse as i32,
                                _ => zitadel::api::zitadel::user::v1::Gender::Unspecified as i32,
                            };
                            assert_eq!(
                                profile.gender, expected_gender,
                                "gender mismatch for user '{}'",
                                expected_user.username
                            );
                        }
                    }
                }
            }

            // Verify user grants in this org
            let expected_grants: Vec<_> = expected
                .user_grants
                .values()
                .filter(|g| {
                    // A grant belongs to an org if its project belongs to this org
                    expected
                        .projects
                        .get(&g.project_k8s_name)
                        .and_then(|p| expected.organizations.get(&p.org_k8s_name))
                        .map(|o| o.display_name == expected_org.display_name)
                        .unwrap_or(false)
                })
                .collect();

            let actual_grants = management
                .list_user_grants(request_with_org_id(
                    ListUserGrantRequest {
                        query: None,
                        queries: vec![],
                    },
                    org_id,
                ))
                .await?
                .into_inner()
                .result;

            assert_eq!(
                actual_grants.len(),
                expected_grants.len(),
                "Grant count mismatch in org '{}': ZITADEL has {}, expected {}",
                expected_org.display_name,
                actual_grants.len(),
                expected_grants.len()
            );

            for expected_grant in &expected_grants {
                // Find the expected user's username
                let expected_username = expected
                    .human_users
                    .get(&expected_grant.user_k8s_name)
                    .map(|u| u.username.clone())
                    .unwrap_or_default();
                // Find expected project's display name
                let expected_project_name = expected
                    .projects
                    .get(&expected_grant.project_k8s_name)
                    .map(|p| p.display_name.clone())
                    .unwrap_or_default();

                // Look up project_id for matching
                let project_id = project_id_map.get(&expected_project_name);

                let actual = actual_grants.iter().find(|g| {
                    project_id
                        .map(|pid| g.project_id == *pid)
                        .unwrap_or(false)
                        && g.user_name == expected_username
                });

                assert!(
                    actual.is_some(),
                    "Expected grant for user '{}' in project '{}' not found in org '{}'",
                    expected_username, expected_project_name, expected_org.display_name
                );

                let actual = actual.unwrap();
                let mut actual_roles: Vec<String> = actual.role_keys.clone();
                actual_roles.sort();
                let mut expected_roles: Vec<String> = expected_grant.role_keys.clone();
                expected_roles.sort();
                assert_eq!(
                    actual_roles, expected_roles,
                    "Role keys mismatch for grant (user='{}', project='{}')",
                    expected_username, expected_project_name
                );
            }
        }

        // Verify K8s Secrets exist for operator-managed applications (not zitadel_only)
        let secrets: Api<Secret> = Api::namespaced(self.k8s.clone(), "default");
        for (app_k8s_name, _app_ref) in &expected.applications {
            if expected.zitadel_only.contains(app_k8s_name) {
                continue;
            }
            let secret = secrets.get_opt(app_k8s_name).await?;
            assert!(
                secret.is_some(),
                "Expected K8s Secret '{}' for operator-managed application not found",
                app_k8s_name
            );
        }

        info!("Deep verify passed: all orgs, projects, roles, users, grants, apps, and secrets match");
        Ok(())
    }

    async fn delete_children_of_org(&self, org_k8s_name: &str) -> Result<()> {
        // Delete human users belonging to this org
        let users: Api<HumanUser> = Api::namespaced(self.k8s.clone(), "default");
        for user in users.list(&ListParams::default()).await? {
            if let Some(name) = &user.metadata.name {
                if user.spec.organization_name == org_k8s_name {
                    info!("Cascade-deleting human user {} (org {})", name, org_k8s_name);
                    let _ = users.delete(name, &DeleteParams::default()).await;
                    self.wait_for_human_user_deleted(name).await?;
                }
            }
        }

        // Delete projects belonging to this org (which cascade-deletes their children)
        let projects: Api<Project> = Api::namespaced(self.k8s.clone(), "default");
        for project in projects.list(&ListParams::default()).await? {
            if let Some(name) = &project.metadata.name {
                if project.spec.organization_name == org_k8s_name {
                    info!("Cascade-deleting project {} (org {})", name, org_k8s_name);
                    self.delete_children_of_project(name).await?;
                    let _ = projects.delete(name, &DeleteParams::default()).await;
                    self.wait_for_project_deleted(name).await?;
                }
            }
        }

        Ok(())
    }

    async fn delete_children_of_project(&self, project_k8s_name: &str) -> Result<()> {
        // Delete apps
        let apps: Api<Application> = Api::namespaced(self.k8s.clone(), "default");
        for app in apps.list(&ListParams::default()).await? {
            if let Some(name) = &app.metadata.name {
                if app.spec.project_name == project_k8s_name {
                    info!("Cascade-deleting app {} (project {})", name, project_k8s_name);
                    let _ = apps.delete(name, &DeleteParams::default()).await;
                    self.wait_for_app_deleted(name).await?;
                }
            }
        }

        // Delete user grants
        let grants: Api<UserGrant> = Api::namespaced(self.k8s.clone(), "default");
        for grant in grants.list(&ListParams::default()).await? {
            if let Some(name) = &grant.metadata.name {
                if grant.spec.project_name == project_k8s_name {
                    info!("Cascade-deleting user grant {} (project {})", name, project_k8s_name);
                    let _ = grants.delete(name, &DeleteParams::default()).await;
                    self.wait_for_user_grant_deleted(name).await?;
                }
            }
        }

        // Delete project roles
        let roles: Api<ProjectRole> = Api::namespaced(self.k8s.clone(), "default");
        for role in roles.list(&ListParams::default()).await? {
            if let Some(name) = &role.metadata.name {
                if role.spec.project_name == project_k8s_name {
                    info!("Cascade-deleting project role {} (project {})", name, project_k8s_name);
                    let _ = roles.delete(name, &DeleteParams::default()).await;
                    self.wait_for_project_role_deleted(name).await?;
                }
            }
        }

        Ok(())
    }

    async fn wait_for_org_ready(&self, name: &str) -> Result<()> {
        let orgs: Api<Organization> = Api::all(self.k8s.clone());

        tokio::time::timeout(Duration::from_secs(90), async {
            loop {
                if let Ok(Some(org)) = orgs.get_opt(name).await {
                    if let Some(status) = &org.status {
                        if status.phase == OrganizationPhase::Ready && !status.id.is_empty() {
                            return Ok(());
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        })
        .await
        .context("Timeout waiting for organization to be ready")?
    }

    async fn wait_for_org_deleted(&self, name: &str) -> Result<()> {
        let orgs: Api<Organization> = Api::all(self.k8s.clone());

        tokio::time::timeout(Duration::from_secs(90), async {
            loop {
                if orgs.get_opt(name).await?.is_none() {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        })
        .await
        .context("Timeout waiting for organization to be deleted")?
    }

    async fn wait_for_project_ready(&self, name: &str) -> Result<()> {
        let projects: Api<Project> = Api::namespaced(self.k8s.clone(), "default");

        tokio::time::timeout(Duration::from_secs(90), async {
            loop {
                if let Ok(Some(proj)) = projects.get_opt(name).await {
                    if let Some(status) = &proj.status {
                        if status.phase == ProjectPhase::Ready && !status.id.is_empty() {
                            return Ok(());
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        })
        .await
        .context("Timeout waiting for project to be ready")?
    }

    async fn wait_for_project_deleted(&self, name: &str) -> Result<()> {
        let projects: Api<Project> = Api::namespaced(self.k8s.clone(), "default");

        tokio::time::timeout(Duration::from_secs(90), async {
            loop {
                if projects.get_opt(name).await?.is_none() {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        })
        .await
        .context("Timeout waiting for project to be deleted")?
    }

    async fn wait_for_project_role_ready(&self, name: &str) -> Result<()> {
        let roles: Api<ProjectRole> = Api::namespaced(self.k8s.clone(), "default");

        tokio::time::timeout(Duration::from_secs(90), async {
            loop {
                if let Ok(Some(role)) = roles.get_opt(name).await {
                    if let Some(status) = &role.status {
                        if status.phase == ProjectRolePhase::Ready && !status.project_id.is_empty()
                        {
                            return Ok(());
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        })
        .await
        .context("Timeout waiting for project role to be ready")?
    }

    async fn wait_for_project_role_deleted(&self, name: &str) -> Result<()> {
        let roles: Api<ProjectRole> = Api::namespaced(self.k8s.clone(), "default");

        tokio::time::timeout(Duration::from_secs(90), async {
            loop {
                if roles.get_opt(name).await?.is_none() {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        })
        .await
        .context("Timeout waiting for project role to be deleted")?
    }

    async fn wait_for_human_user_ready(&self, name: &str) -> Result<()> {
        let users: Api<HumanUser> = Api::namespaced(self.k8s.clone(), "default");

        tokio::time::timeout(Duration::from_secs(90), async {
            loop {
                if let Ok(Some(user)) = users.get_opt(name).await {
                    if let Some(status) = &user.status {
                        if status.phase == HumanUserPhase::Ready && !status.id.is_empty() {
                            return Ok(());
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        })
        .await
        .context("Timeout waiting for human user to be ready")?
    }

    async fn wait_for_human_user_deleted(&self, name: &str) -> Result<()> {
        let users: Api<HumanUser> = Api::namespaced(self.k8s.clone(), "default");

        tokio::time::timeout(Duration::from_secs(90), async {
            loop {
                if users.get_opt(name).await?.is_none() {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        })
        .await
        .context("Timeout waiting for human user to be deleted")?
    }

    async fn wait_for_user_grant_ready(&self, name: &str) -> Result<()> {
        let grants: Api<UserGrant> = Api::namespaced(self.k8s.clone(), "default");

        tokio::time::timeout(Duration::from_secs(90), async {
            loop {
                if let Ok(Some(grant)) = grants.get_opt(name).await {
                    if let Some(status) = &grant.status {
                        if status.phase == UserGrantPhase::Ready && !status.id.is_empty() {
                            return Ok(());
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        })
        .await
        .context("Timeout waiting for user grant to be ready")?
    }

    async fn wait_for_user_grant_deleted(&self, name: &str) -> Result<()> {
        let grants: Api<UserGrant> = Api::namespaced(self.k8s.clone(), "default");

        tokio::time::timeout(Duration::from_secs(90), async {
            loop {
                if grants.get_opt(name).await?.is_none() {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        })
        .await
        .context("Timeout waiting for user grant to be deleted")?
    }

    async fn wait_for_app_ready(&self, name: &str) -> Result<()> {
        let apps: Api<Application> = Api::namespaced(self.k8s.clone(), "default");

        tokio::time::timeout(Duration::from_secs(90), async {
            loop {
                if let Ok(Some(app)) = apps.get_opt(name).await {
                    if let Some(status) = &app.status {
                        if !status.id.is_empty() {
                            return Ok(());
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        })
        .await
        .context("Timeout waiting for application to be ready")?
    }

    async fn wait_for_app_deleted(&self, name: &str) -> Result<()> {
        let apps: Api<Application> = Api::namespaced(self.k8s.clone(), "default");

        tokio::time::timeout(Duration::from_secs(90), async {
            loop {
                if apps.get_opt(name).await?.is_none() {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        })
        .await
        .context("Timeout waiting for application to be deleted")?
    }
}
