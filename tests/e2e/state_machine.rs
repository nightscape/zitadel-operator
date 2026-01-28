use proptest::prelude::*;
use proptest_state_machine::ReferenceStateMachine;
use std::collections::HashMap;

#[derive(Clone, Debug, Default)]
pub struct ReferenceState {
    pub organizations: HashMap<String, OrgRef>,
    pub projects: HashMap<String, ProjectRef>,
    pub project_roles: HashMap<String, ProjectRoleRef>,
    pub human_users: HashMap<String, HumanUserRef>,
    pub user_grants: HashMap<String, UserGrantRef>,
    pub applications: HashMap<String, AppRef>,
}

#[derive(Clone, Debug)]
pub struct OrgRef {
    pub display_name: String,
}

#[derive(Clone, Debug)]
pub struct ProjectRef {
    pub display_name: String,
    pub org_k8s_name: String,
    pub project_role_assertion: bool,
}

#[derive(Clone, Debug)]
pub struct ProjectRoleRef {
    pub role_key: String,
    pub display_name: String,
    pub group: Option<String>,
    pub project_k8s_name: String,
}

#[derive(Clone, Debug)]
pub struct HumanUserRef {
    pub username: String,
    pub given_name: String,
    pub family_name: String,
    pub nick_name: Option<String>,
    pub gender: Option<String>,
    pub preferred_language: Option<String>,
    pub org_k8s_name: String,
}

#[derive(Clone, Debug)]
pub struct UserGrantRef {
    pub user_k8s_name: String,
    pub project_k8s_name: String,
    pub role_keys: Vec<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum AppVariant {
    Oidc,
    Api,
}

#[derive(Clone, Debug)]
pub struct AppRef {
    pub display_name: String,
    pub project_k8s_name: String,
    pub app_variant: AppVariant,
    pub dev_mode: bool,
}

// --- Validity checking ---

#[derive(Clone, Debug)]
pub struct ValidationError {
    pub field: String,
    pub message: String,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.field, self.message)
    }
}

const VALID_GENDERS: &[&str] = &["Female", "Male", "Diverse", "Unspecified"];

impl Transition {
    pub fn validation_errors(&self) -> Vec<ValidationError> {
        let mut errors = vec![];
        match self {
            Transition::CreateOrg { display_name, .. } => {
                if display_name.is_empty() {
                    errors.push(ValidationError {
                        field: "spec.name".into(),
                        message: "must not be empty".into(),
                    });
                }
            }
            Transition::CreateHumanUser {
                username,
                given_name,
                family_name,
                gender,
                ..
            } => {
                if username.is_empty() {
                    errors.push(ValidationError {
                        field: "spec.username".into(),
                        message: "must not be empty".into(),
                    });
                }
                if given_name.is_empty() {
                    errors.push(ValidationError {
                        field: "spec.profile.givenName".into(),
                        message: "must not be empty".into(),
                    });
                }
                if family_name.is_empty() {
                    errors.push(ValidationError {
                        field: "spec.profile.familyName".into(),
                        message: "must not be empty".into(),
                    });
                }
                if let Some(g) = gender {
                    if !VALID_GENDERS.contains(&g.as_str()) {
                        errors.push(ValidationError {
                            field: "spec.profile.gender".into(),
                            message: format!("invalid value: {}", g),
                        });
                    }
                }
            }
            _ => {}
        }
        errors
    }
}

// --- Transitions ---

#[derive(Clone, Debug)]
pub enum Transition {
    CreateOrg {
        k8s_name: String,
        display_name: String,
    },
    UpdateOrgName {
        k8s_name: String,
        new_display_name: String,
    },
    DeleteOrg {
        k8s_name: String,
    },
    CreateProject {
        k8s_name: String,
        display_name: String,
        org_k8s_name: String,
        project_role_assertion: bool,
    },
    UpdateProject {
        k8s_name: String,
        new_display_name: String,
        new_project_role_assertion: bool,
    },
    DeleteProject {
        k8s_name: String,
    },
    CreateProjectRole {
        k8s_name: String,
        role_key: String,
        display_name: String,
        group: Option<String>,
        project_k8s_name: String,
    },
    UpdateProjectRole {
        k8s_name: String,
        new_display_name: String,
        new_group: Option<String>,
    },
    DeleteProjectRole {
        k8s_name: String,
    },
    CreateHumanUser {
        k8s_name: String,
        username: String,
        given_name: String,
        family_name: String,
        nick_name: Option<String>,
        gender: Option<String>,
        preferred_language: Option<String>,
        org_k8s_name: String,
    },
    DeleteHumanUser {
        k8s_name: String,
    },
    CreateUserGrant {
        k8s_name: String,
        user_k8s_name: String,
        project_k8s_name: String,
        role_keys: Vec<String>,
    },
    UpdateUserGrantRoles {
        k8s_name: String,
        new_role_keys: Vec<String>,
    },
    DeleteUserGrant {
        k8s_name: String,
    },
    CreateApp {
        k8s_name: String,
        display_name: String,
        project_k8s_name: String,
        app_variant: AppVariant,
    },
    UpdateApp {
        k8s_name: String,
        new_display_name: String,
        new_dev_mode: bool,
    },
    DeleteApp {
        k8s_name: String,
    },
}

// --- Strategies ---

pub struct OperatorStateMachine;

fn k8s_name_strategy() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9]{2,10}"
}

fn display_name_strategy() -> impl Strategy<Value = String> {
    "[A-Z][a-zA-Z0-9]{2,20}"
}

fn role_key_strategy() -> impl Strategy<Value = String> {
    "[a-z]{3,8}:[a-z]{3,8}"
}

fn username_strategy() -> impl Strategy<Value = String> {
    "[a-z]{3,8}@example\\.com"
}

fn name_strategy() -> impl Strategy<Value = String> {
    "[A-Z][a-z]{2,10}"
}

fn gender_strategy() -> impl Strategy<Value = String> {
    proptest::sample::select(vec![
        "Female".to_string(),
        "Male".to_string(),
        "Diverse".to_string(),
    ])
}

fn language_strategy() -> impl Strategy<Value = String> {
    proptest::sample::select(vec![
        "en".to_string(),
        "de".to_string(),
        "fr".to_string(),
    ])
}

// Strategies that sometimes produce CRD-invalid values (~20% of the time).
// The ValidityCheck impl above mirrors the CRD schema constraints so the
// reference state machine knows to skip these transitions.

fn display_name_sometimes_invalid() -> BoxedStrategy<String> {
    prop_oneof![
        4 => display_name_strategy(),
        1 => Just(String::new()),
    ]
    .boxed()
}

fn username_sometimes_invalid() -> BoxedStrategy<String> {
    prop_oneof![
        4 => username_strategy(),
        1 => Just(String::new()),
    ]
    .boxed()
}

fn name_sometimes_invalid() -> BoxedStrategy<String> {
    prop_oneof![
        4 => name_strategy(),
        1 => Just(String::new()),
    ]
    .boxed()
}

fn gender_sometimes_invalid() -> BoxedStrategy<Option<String>> {
    prop_oneof![
        4 => proptest::option::of(gender_strategy()),
        1 => Just(Some("InvalidGender".to_string())),
    ]
    .boxed()
}

impl ReferenceStateMachine for OperatorStateMachine {
    type State = ReferenceState;
    type Transition = Transition;

    fn init_state() -> BoxedStrategy<Self::State> {
        Just(ReferenceState::default()).boxed()
    }

    fn transitions(state: &Self::State) -> BoxedStrategy<Self::Transition> {
        let mut strategies: Vec<BoxedStrategy<Transition>> = vec![];

        // CreateOrg (sometimes generates empty display_name → CRD rejects)
        strategies.push(
            (k8s_name_strategy(), display_name_sometimes_invalid())
                .prop_filter_map("org name not already used", {
                    let orgs = state.organizations.clone();
                    move |(k, d)| {
                        if orgs.contains_key(&k) {
                            None
                        } else {
                            Some(Transition::CreateOrg {
                                k8s_name: k,
                                display_name: d,
                            })
                        }
                    }
                })
                .boxed(),
        );

        // Org operations
        for org_name in state.organizations.keys() {
            let org_name_clone = org_name.clone();
            strategies.push(Just(Transition::DeleteOrg { k8s_name: org_name_clone }).boxed());

            let org_name_clone = org_name.clone();
            strategies.push(
                display_name_strategy()
                    .prop_map(move |d| Transition::UpdateOrgName {
                        k8s_name: org_name_clone.clone(),
                        new_display_name: d,
                    })
                    .boxed(),
            );
        }

        // CreateProject
        if !state.organizations.is_empty() {
            let org_names: Vec<String> = state.organizations.keys().cloned().collect();
            let projects = state.projects.clone();
            strategies.push(
                (
                    k8s_name_strategy(),
                    display_name_strategy(),
                    proptest::sample::select(org_names),
                    proptest::bool::ANY,
                )
                    .prop_filter_map("project name not already used", move |(k, d, o, pra)| {
                        if projects.contains_key(&k) {
                            None
                        } else {
                            Some(Transition::CreateProject {
                                k8s_name: k,
                                display_name: d,
                                org_k8s_name: o,
                                project_role_assertion: pra,
                            })
                        }
                    })
                    .boxed(),
            );
        }

        // Project operations
        for project_name in state.projects.keys() {
            let project_name_clone = project_name.clone();
            strategies.push(Just(Transition::DeleteProject { k8s_name: project_name_clone }).boxed());

            let project_name_clone = project_name.clone();
            strategies.push(
                (display_name_strategy(), proptest::bool::ANY)
                    .prop_map(move |(d, pra)| Transition::UpdateProject {
                        k8s_name: project_name_clone.clone(),
                        new_display_name: d,
                        new_project_role_assertion: pra,
                    })
                    .boxed(),
            );
        }

        // CreateProjectRole
        if !state.projects.is_empty() {
            let project_names: Vec<String> = state.projects.keys().cloned().collect();
            let roles = state.project_roles.clone();
            strategies.push(
                (
                    k8s_name_strategy(),
                    role_key_strategy(),
                    display_name_strategy(),
                    proptest::option::of(display_name_strategy()),
                    proptest::sample::select(project_names),
                )
                    .prop_filter_map("role name not already used", move |(k, rk, d, g, p)| {
                        if roles.contains_key(&k) {
                            None
                        } else {
                            Some(Transition::CreateProjectRole {
                                k8s_name: k,
                                role_key: rk,
                                display_name: d,
                                group: g,
                                project_k8s_name: p,
                            })
                        }
                    })
                    .boxed(),
            );
        }

        // ProjectRole operations
        for role_name in state.project_roles.keys() {
            let role_name_clone = role_name.clone();
            strategies.push(Just(Transition::DeleteProjectRole { k8s_name: role_name_clone }).boxed());

            let role_name_clone = role_name.clone();
            strategies.push(
                (display_name_strategy(), proptest::option::of(display_name_strategy()))
                    .prop_map(move |(d, g)| Transition::UpdateProjectRole {
                        k8s_name: role_name_clone.clone(),
                        new_display_name: d,
                        new_group: g,
                    })
                    .boxed(),
            );
        }

        // CreateHumanUser (sometimes generates invalid field values → CRD rejects)
        if !state.organizations.is_empty() {
            let org_names: Vec<String> = state.organizations.keys().cloned().collect();
            let users = state.human_users.clone();
            strategies.push(
                (
                    k8s_name_strategy(),
                    username_sometimes_invalid(),
                    name_sometimes_invalid(),
                    name_sometimes_invalid(),
                    proptest::option::of(display_name_strategy()),
                    gender_sometimes_invalid(),
                    proptest::option::of(language_strategy()),
                    proptest::sample::select(org_names),
                )
                    .prop_filter_map("user name not already used", move |(k, u, gn, fn_, nn, ge, pl, o)| {
                        if users.contains_key(&k) {
                            None
                        } else {
                            Some(Transition::CreateHumanUser {
                                k8s_name: k,
                                username: u,
                                given_name: gn,
                                family_name: fn_,
                                nick_name: nn,
                                gender: ge,
                                preferred_language: pl,
                                org_k8s_name: o,
                            })
                        }
                    })
                    .boxed(),
            );
        }

        // HumanUser operations
        for user_name in state.human_users.keys() {
            let user_name_clone = user_name.clone();
            strategies.push(Just(Transition::DeleteHumanUser { k8s_name: user_name_clone }).boxed());
        }

        // CreateUserGrant (needs both user and project with roles)
        if !state.human_users.is_empty() && !state.projects.is_empty() {
            let user_names: Vec<String> = state.human_users.keys().cloned().collect();
            let grants = state.user_grants.clone();
            let roles = state.project_roles.clone();

            // Get role keys per project
            let roles_by_project: HashMap<String, Vec<String>> = roles
                .values()
                .fold(HashMap::new(), |mut acc, r| {
                    acc.entry(r.project_k8s_name.clone())
                        .or_default()
                        .push(r.role_key.clone());
                    acc
                });

            if !roles_by_project.is_empty() {
                let projects_with_roles: Vec<String> = roles_by_project.keys().cloned().collect();
                strategies.push(
                    (
                        k8s_name_strategy(),
                        proptest::sample::select(user_names),
                        proptest::sample::select(projects_with_roles.clone()),
                    )
                        .prop_filter_map("grant name not already used", {
                            let grants = grants.clone();
                            let roles_by_project = roles_by_project.clone();
                            move |(k, u, p)| {
                                if grants.contains_key(&k) {
                                    None
                                } else {
                                    let role_keys = roles_by_project.get(&p).cloned().unwrap_or_default();
                                    if role_keys.is_empty() {
                                        None
                                    } else {
                                        Some(Transition::CreateUserGrant {
                                            k8s_name: k,
                                            user_k8s_name: u,
                                            project_k8s_name: p,
                                            role_keys,
                                        })
                                    }
                                }
                            }
                        })
                        .boxed(),
                );
            }
        }

        // UserGrant operations
        for (grant_name, grant_ref) in &state.user_grants {
            let grant_name_clone = grant_name.clone();
            strategies.push(Just(Transition::DeleteUserGrant { k8s_name: grant_name_clone }).boxed());

            // UpdateUserGrantRoles: pick a new subset of roles for this grant's project
            let role_keys: Vec<String> = state
                .project_roles
                .values()
                .filter(|r| r.project_k8s_name == grant_ref.project_k8s_name)
                .map(|r| r.role_key.clone())
                .collect();
            if !role_keys.is_empty() {
                let grant_name_clone = grant_name.clone();
                let len = role_keys.len();
                strategies.push(
                    proptest::sample::subsequence(role_keys, 1..=len)
                        .prop_map(move |keys| Transition::UpdateUserGrantRoles {
                            k8s_name: grant_name_clone.clone(),
                            new_role_keys: keys,
                        })
                        .boxed(),
                );
            }
        }

        // CreateApp
        if !state.projects.is_empty() {
            let project_names: Vec<String> = state.projects.keys().cloned().collect();
            let apps = state.applications.clone();
            strategies.push(
                (
                    k8s_name_strategy(),
                    display_name_strategy(),
                    proptest::sample::select(project_names),
                    proptest::sample::select(vec![AppVariant::Oidc, AppVariant::Api]),
                )
                    .prop_filter_map("app name not already used", move |(k, d, p, v)| {
                        if apps.contains_key(&k) {
                            None
                        } else {
                            Some(Transition::CreateApp {
                                k8s_name: k,
                                display_name: d,
                                project_k8s_name: p,
                                app_variant: v,
                            })
                        }
                    })
                    .boxed(),
            );
        }

        // App operations
        for (app_name, app_ref) in &state.applications {
            let app_name_clone = app_name.clone();
            strategies.push(Just(Transition::DeleteApp { k8s_name: app_name_clone }).boxed());

            // UpdateApp: only for OIDC apps (API apps have no updatable config beyond auth method)
            if app_ref.app_variant == AppVariant::Oidc {
                let app_name_clone = app_name.clone();
                strategies.push(
                    (display_name_strategy(), proptest::bool::ANY)
                        .prop_map(move |(d, dm)| Transition::UpdateApp {
                            k8s_name: app_name_clone.clone(),
                            new_display_name: d,
                            new_dev_mode: dm,
                        })
                        .boxed(),
                );
            }
        }

        prop::strategy::Union::new(strategies).boxed()
    }

    fn apply(mut state: Self::State, transition: &Self::Transition) -> Self::State {
        if !transition.validation_errors().is_empty() {
            return state;
        }
        match transition {
            Transition::CreateOrg {
                k8s_name,
                display_name,
            } => {
                state.organizations.insert(
                    k8s_name.clone(),
                    OrgRef {
                        display_name: display_name.clone(),
                    },
                );
            }
            Transition::UpdateOrgName {
                k8s_name,
                new_display_name,
            } => {
                if let Some(org) = state.organizations.get_mut(k8s_name) {
                    org.display_name = new_display_name.clone();
                }
            }
            Transition::DeleteOrg { k8s_name } => {
                state.organizations.remove(k8s_name);
                // Cascade delete users in this org
                let users_to_remove: Vec<String> = state
                    .human_users
                    .iter()
                    .filter(|(_, u)| &u.org_k8s_name == k8s_name)
                    .map(|(k, _)| k.clone())
                    .collect();
                for user_name in &users_to_remove {
                    state.human_users.remove(user_name);
                    // Remove grants for this user
                    let grants_to_remove: Vec<String> = state
                        .user_grants
                        .iter()
                        .filter(|(_, g)| &g.user_k8s_name == user_name)
                        .map(|(k, _)| k.clone())
                        .collect();
                    for grant_name in grants_to_remove {
                        state.user_grants.remove(&grant_name);
                    }
                }
                // Cascade delete projects
                let projects_to_remove: Vec<String> = state
                    .projects
                    .iter()
                    .filter(|(_, p)| &p.org_k8s_name == k8s_name)
                    .map(|(k, _)| k.clone())
                    .collect();
                for project_name in &projects_to_remove {
                    state.projects.remove(project_name);
                    // Remove roles for this project
                    let roles_to_remove: Vec<String> = state
                        .project_roles
                        .iter()
                        .filter(|(_, r)| &r.project_k8s_name == project_name)
                        .map(|(k, _)| k.clone())
                        .collect();
                    for role_name in roles_to_remove {
                        state.project_roles.remove(&role_name);
                    }
                    // Remove grants for this project
                    let grants_to_remove: Vec<String> = state
                        .user_grants
                        .iter()
                        .filter(|(_, g)| &g.project_k8s_name == project_name)
                        .map(|(k, _)| k.clone())
                        .collect();
                    for grant_name in grants_to_remove {
                        state.user_grants.remove(&grant_name);
                    }
                    // Remove apps
                    let apps_to_remove: Vec<String> = state
                        .applications
                        .iter()
                        .filter(|(_, a)| &a.project_k8s_name == project_name)
                        .map(|(k, _)| k.clone())
                        .collect();
                    for app_name in apps_to_remove {
                        state.applications.remove(&app_name);
                    }
                }
            }
            Transition::CreateProject {
                k8s_name,
                display_name,
                org_k8s_name,
                project_role_assertion,
            } => {
                state.projects.insert(
                    k8s_name.clone(),
                    ProjectRef {
                        display_name: display_name.clone(),
                        org_k8s_name: org_k8s_name.clone(),
                        project_role_assertion: *project_role_assertion,
                    },
                );
            }
            Transition::UpdateProject {
                k8s_name,
                new_display_name,
                new_project_role_assertion,
            } => {
                if let Some(proj) = state.projects.get_mut(k8s_name) {
                    proj.display_name = new_display_name.clone();
                    proj.project_role_assertion = *new_project_role_assertion;
                }
            }
            Transition::DeleteProject { k8s_name } => {
                state.projects.remove(k8s_name);
                // Cascade delete roles
                let roles_to_remove: Vec<String> = state
                    .project_roles
                    .iter()
                    .filter(|(_, r)| &r.project_k8s_name == k8s_name)
                    .map(|(k, _)| k.clone())
                    .collect();
                for role_name in roles_to_remove {
                    state.project_roles.remove(&role_name);
                }
                // Cascade delete grants
                let grants_to_remove: Vec<String> = state
                    .user_grants
                    .iter()
                    .filter(|(_, g)| &g.project_k8s_name == k8s_name)
                    .map(|(k, _)| k.clone())
                    .collect();
                for grant_name in grants_to_remove {
                    state.user_grants.remove(&grant_name);
                }
                // Cascade delete apps
                let apps_to_remove: Vec<String> = state
                    .applications
                    .iter()
                    .filter(|(_, a)| &a.project_k8s_name == k8s_name)
                    .map(|(k, _)| k.clone())
                    .collect();
                for app_name in apps_to_remove {
                    state.applications.remove(&app_name);
                }
            }
            Transition::CreateProjectRole {
                k8s_name,
                role_key,
                display_name,
                group,
                project_k8s_name,
            } => {
                state.project_roles.insert(
                    k8s_name.clone(),
                    ProjectRoleRef {
                        role_key: role_key.clone(),
                        display_name: display_name.clone(),
                        group: group.clone(),
                        project_k8s_name: project_k8s_name.clone(),
                    },
                );
            }
            Transition::UpdateProjectRole {
                k8s_name,
                new_display_name,
                new_group,
            } => {
                if let Some(role) = state.project_roles.get_mut(k8s_name) {
                    role.display_name = new_display_name.clone();
                    role.group = new_group.clone();
                }
            }
            Transition::DeleteProjectRole { k8s_name } => {
                state.project_roles.remove(k8s_name);
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
                state.human_users.insert(
                    k8s_name.clone(),
                    HumanUserRef {
                        username: username.clone(),
                        given_name: given_name.clone(),
                        family_name: family_name.clone(),
                        nick_name: nick_name.clone(),
                        gender: gender.clone(),
                        preferred_language: preferred_language.clone(),
                        org_k8s_name: org_k8s_name.clone(),
                    },
                );
            }
            Transition::DeleteHumanUser { k8s_name } => {
                state.human_users.remove(k8s_name);
                // Cascade delete grants
                let grants_to_remove: Vec<String> = state
                    .user_grants
                    .iter()
                    .filter(|(_, g)| &g.user_k8s_name == k8s_name)
                    .map(|(k, _)| k.clone())
                    .collect();
                for grant_name in grants_to_remove {
                    state.user_grants.remove(&grant_name);
                }
            }
            Transition::CreateUserGrant {
                k8s_name,
                user_k8s_name,
                project_k8s_name,
                role_keys,
            } => {
                state.user_grants.insert(
                    k8s_name.clone(),
                    UserGrantRef {
                        user_k8s_name: user_k8s_name.clone(),
                        project_k8s_name: project_k8s_name.clone(),
                        role_keys: role_keys.clone(),
                    },
                );
            }
            Transition::UpdateUserGrantRoles {
                k8s_name,
                new_role_keys,
            } => {
                if let Some(grant) = state.user_grants.get_mut(k8s_name) {
                    grant.role_keys = new_role_keys.clone();
                }
            }
            Transition::DeleteUserGrant { k8s_name } => {
                state.user_grants.remove(k8s_name);
            }
            Transition::CreateApp {
                k8s_name,
                display_name,
                project_k8s_name,
                app_variant,
            } => {
                state.applications.insert(
                    k8s_name.clone(),
                    AppRef {
                        display_name: display_name.clone(),
                        project_k8s_name: project_k8s_name.clone(),
                        app_variant: app_variant.clone(),
                        dev_mode: false,
                    },
                );
            }
            Transition::UpdateApp {
                k8s_name,
                new_display_name,
                new_dev_mode,
            } => {
                if let Some(app) = state.applications.get_mut(k8s_name) {
                    app.display_name = new_display_name.clone();
                    app.dev_mode = *new_dev_mode;
                }
            }
            Transition::DeleteApp { k8s_name } => {
                state.applications.remove(k8s_name);
            }
        }
        state
    }

    fn preconditions(state: &Self::State, transition: &Self::Transition) -> bool {
        match transition {
            Transition::CreateOrg { k8s_name, .. } => !state.organizations.contains_key(k8s_name),
            Transition::UpdateOrgName { k8s_name, .. } => state.organizations.contains_key(k8s_name),
            Transition::DeleteOrg { k8s_name } => state.organizations.contains_key(k8s_name),
            Transition::CreateProject {
                k8s_name,
                org_k8s_name,
                ..
            } => {
                !state.projects.contains_key(k8s_name)
                    && state.organizations.contains_key(org_k8s_name)
            }
            Transition::UpdateProject { k8s_name, .. } => state.projects.contains_key(k8s_name),
            Transition::DeleteProject { k8s_name } => state.projects.contains_key(k8s_name),
            Transition::CreateProjectRole {
                k8s_name,
                project_k8s_name,
                ..
            } => {
                !state.project_roles.contains_key(k8s_name)
                    && state.projects.contains_key(project_k8s_name)
            }
            Transition::UpdateProjectRole { k8s_name, .. } => {
                state.project_roles.contains_key(k8s_name)
            }
            Transition::DeleteProjectRole { k8s_name } => state.project_roles.contains_key(k8s_name),
            Transition::CreateHumanUser {
                k8s_name,
                org_k8s_name,
                ..
            } => {
                !state.human_users.contains_key(k8s_name)
                    && state.organizations.contains_key(org_k8s_name)
            }
            Transition::DeleteHumanUser { k8s_name } => state.human_users.contains_key(k8s_name),
            Transition::CreateUserGrant {
                k8s_name,
                user_k8s_name,
                project_k8s_name,
                ..
            } => {
                !state.user_grants.contains_key(k8s_name)
                    && state.human_users.contains_key(user_k8s_name)
                    && state.projects.contains_key(project_k8s_name)
            }
            Transition::UpdateUserGrantRoles { k8s_name, .. } => {
                state.user_grants.contains_key(k8s_name)
            }
            Transition::DeleteUserGrant { k8s_name } => state.user_grants.contains_key(k8s_name),
            Transition::CreateApp {
                k8s_name,
                project_k8s_name,
                ..
            } => {
                !state.applications.contains_key(k8s_name)
                    && state.projects.contains_key(project_k8s_name)
            }
            Transition::UpdateApp { k8s_name, .. } => state.applications.contains_key(k8s_name),
            Transition::DeleteApp { k8s_name } => state.applications.contains_key(k8s_name),
        }
    }
}
