pub mod executor;
pub mod state_machine;

use anyhow::{anyhow, Context, Result};
use k8s_openapi::api::{apps::v1::Deployment, core::v1::Secret};
use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use kube::{
    api::{DeleteParams, ListParams, Patch, PatchParams},
    runtime::wait::{await_condition, conditions},
    Api, Client, CustomResourceExt, ResourceExt,
};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use testcontainers::{core::{ContainerPort, WaitFor}, runners::AsyncRunner, ContainerAsync, GenericImage, ImageExt};
use tokio::process::Command;
use tokio::sync::OnceCell;
use tracing::info;
use zitadel::api::interceptors::ServiceAccountInterceptor;
use zitadel::credentials::{AuthenticationOptions, ServiceAccount};
use zitadel_operator::{
    controllers::{application, human_user, organization, project, project_role, user_grant},
    schema::{Application, HumanUser, Organization, Project, ProjectRole, UserGrant},
    OperatorContext, ZitadelBuilder,
};

static FIXTURE: OnceCell<TestFixture> = OnceCell::const_new();
static CONTAINER_ID: std::sync::OnceLock<String> = std::sync::OnceLock::new();

const K3S_IMAGE: &str = "rancher/k3s";
const K3S_TAG: &str = "v1.31.4-k3s1";
const KUBE_SECURE_PORT: u16 = 6443;
const E2E_CONTAINER_LABEL: &str = "zitadel-e2e-test";

pub struct TestFixture {
    pub k8s_client: Client,
    pub zitadel_builder: ZitadelBuilder,
    pub zitadel_url: String,
    _k3s: ContainerAsync<GenericImage>,
    _kubeconfig_path: PathBuf,
}

impl TestFixture {
    pub async fn get_or_init() -> &'static Self {
        FIXTURE
            .get_or_init(|| async { Self::init().await.expect("fixture init failed") })
            .await
    }

    async fn init() -> Result<Self> {
        let conf_dir = std::env::temp_dir().join("zitadel-e2e-k3s");
        let _ = std::fs::remove_dir_all(&conf_dir);
        std::fs::create_dir_all(&conf_dir)?;

        // testcontainers-rs has no Ryuk reaper (unlike the Java version),
        // and static OnceCell values are never dropped, so containers from
        // previous runs leak. Kill any leftovers before starting a new one.
        cleanup_stale_containers();

        info!("Starting K3s container...");
        // Use GenericImage to avoid the conf_mount issue on macOS
        // The testcontainers-modules K3s with_conf_mount causes K3s to fail writing kubeconfig
        let image = GenericImage::new(K3S_IMAGE, K3S_TAG)
            .with_exposed_port(ContainerPort::Tcp(KUBE_SECURE_PORT))
            .with_exposed_port(ContainerPort::Tcp(30080))  // For ZITADEL NodePort
            .with_wait_for(WaitFor::message_on_stderr("Node controller sync successful"));

        let k3s: ContainerAsync<GenericImage> = image
            .with_privileged(true)
            .with_userns_mode("host")
            .with_startup_timeout(Duration::from_secs(120))
            .with_cmd(vec!["server", "--disable=traefik"])
            .with_label(E2E_CONTAINER_LABEL, "true")
            .start()
            .await
            .context("Failed to start K3s container")?;

        let container_id = k3s.id();
        CONTAINER_ID.set(container_id.to_string()).unwrap();
        register_exit_cleanup();

        info!("Reading kubeconfig via docker cp...");
        let kubeconfig_tmp = conf_dir.join("k3s.yaml");

        // Extract kubeconfig using docker cp
        let output = std::process::Command::new("docker")
            .args(["cp", &format!("{}:/etc/rancher/k3s/k3s.yaml", container_id), kubeconfig_tmp.to_str().unwrap()])
            .output()
            .context("Failed to run docker cp")?;

        if !output.status.success() {
            return Err(anyhow!("Failed to copy kubeconfig: {}", String::from_utf8_lossy(&output.stderr)));
        }

        let kubeconfig = std::fs::read_to_string(&kubeconfig_tmp)?;
        let host_port = k3s.get_host_port_ipv4(ContainerPort::Tcp(KUBE_SECURE_PORT)).await?;
        let kubeconfig = kubeconfig.replace("127.0.0.1:6443", &format!("127.0.0.1:{}", host_port));

        // Save kubeconfig for helm CLI
        let kubeconfig_path = conf_dir.join("kubeconfig.yaml");
        std::fs::write(&kubeconfig_path, &kubeconfig)?;
        info!("Kubeconfig saved to {:?}", kubeconfig_path);

        // Create kube client
        let kubeconfig_parsed = kube::config::Kubeconfig::from_yaml(&kubeconfig)?;
        let config =
            kube::Config::from_custom_kubeconfig(kubeconfig_parsed, &Default::default()).await?;
        let k8s_client = Client::try_from(config)?;

        // Resolve the host port for the ZITADEL NodePort before installing,
        // so we can configure ExternalPort to match (OIDC discovery must return reachable URLs)
        let zitadel_host_port = k3s.get_host_port_ipv4(ContainerPort::Tcp(30080)).await?;
        let zitadel_url = format!("http://localhost:{}", zitadel_host_port);
        info!("ZITADEL will be available at {}", zitadel_url);

        // Deploy PostgreSQL using plain manifest (postgres:16-alpine)
        info!("Deploying PostgreSQL...");
        let pg_manifest_path = conf_dir.join("postgres.yaml");
        std::fs::write(&pg_manifest_path, include_str!("../fixtures/e2e-postgres.yaml"))?;
        run_kubectl(&kubeconfig_path, &["apply", "-f", pg_manifest_path.to_str().unwrap()]).await?;
        wait_for_statefulset(&k8s_client, "default", "db-postgresql").await?;
        info!("PostgreSQL is ready");

        // Install ZITADEL via Helm
        info!("Installing ZITADEL via Helm...");
        run_helm(&kubeconfig_path, &["repo", "add", "zitadel", "https://charts.zitadel.com"]).await?;
        run_helm(&kubeconfig_path, &["repo", "update"]).await?;

        let zitadel_values = include_str!("../fixtures/e2e-zitadel-values.yaml")
            .replace("ExternalPort: 8080", &format!("ExternalPort: {}", zitadel_host_port));
        let values_path = conf_dir.join("zitadel-values.yaml");
        std::fs::write(&values_path, &zitadel_values)?;

        run_helm(
            &kubeconfig_path,
            &[
                "upgrade", "--install", "zitadel",
                "--namespace", "default",
                "--wait",
                "--timeout", "10m",
                "-f", values_path.to_str().unwrap(),
                "zitadel/zitadel",
            ],
        )
        .await?;

        // The chart ignores nodePort, so patch the service to use our exposed port
        let node_port_str = "30080";
        run_kubectl(
            &kubeconfig_path,
            &[
                "patch", "svc", "zitadel", "-n", "default", "-p",
                &format!(r#"{{"spec":{{"ports":[{{"port":8080,"nodePort":{}}}]}}}}"#, node_port_str),
            ],
        )
        .await?;

        info!("Waiting for ZITADEL to be ready...");
        wait_for_zitadel_ready_default_ns(&k8s_client).await?;
        info!("ZITADEL available at {}", zitadel_url);

        // Get the service account JSON from the secret created by Helm
        info!("Retrieving service account...");
        let sa_json = get_zitadel_service_account(&k8s_client).await?;

        info!("Applying CRDs...");
        apply_crds(&k8s_client).await?;

        let zitadel_builder = create_zitadel_builder(&zitadel_url, &sa_json)?;

        // Wait for CRD storage to be fully ready (not just "established"),
        // otherwise controllers hit 429s during initial watch setup and enter
        // 60-second error backoff.
        wait_for_crd_storage_ready(&k8s_client).await?;

        info!("Starting controllers...");
        let ctx = Arc::new(OperatorContext {
            k8s: k8s_client.clone(),
            zitadel: zitadel_builder.clone(),
        });
        start_controllers(ctx);

        info!("Test fixture ready");
        Ok(TestFixture {
            k8s_client,
            zitadel_builder,
            zitadel_url,
            _k3s: k3s,
            _kubeconfig_path: kubeconfig_path,
        })
    }

    pub async fn cleanup(&self) -> Result<()> {
        info!("Cleaning up test state...");

        // Delete + wait per group in reverse dependency order.
        // Finalizers need parent resources to still exist (e.g. human user finalizer
        // looks up the org), so we must fully remove children before deleting parents.
        // Namespaced resources use Api::namespaced (Api::all doesn't support delete).
        let c = &self.k8s_client;

        let apps: Api<Application> = Api::namespaced(c.clone(), "default");
        delete_all_crs(&apps).await?;
        wait_until_empty(&apps).await?;

        let user_grants: Api<UserGrant> = Api::namespaced(c.clone(), "default");
        delete_all_crs(&user_grants).await?;
        wait_until_empty(&user_grants).await?;

        let human_users: Api<HumanUser> = Api::namespaced(c.clone(), "default");
        delete_all_crs(&human_users).await?;
        wait_until_empty(&human_users).await?;

        let project_roles: Api<ProjectRole> = Api::namespaced(c.clone(), "default");
        delete_all_crs(&project_roles).await?;
        wait_until_empty(&project_roles).await?;

        let projects: Api<Project> = Api::namespaced(c.clone(), "default");
        delete_all_crs(&projects).await?;
        wait_until_empty(&projects).await?;

        let orgs: Api<Organization> = Api::all(c.clone());
        delete_all_crs(&orgs).await?;
        wait_until_empty(&orgs).await?;

        Ok(())
    }
}

extern "C" fn remove_container_on_exit() {
    if let Some(id) = CONTAINER_ID.get() {
        let _ = std::process::Command::new("docker")
            .args(["rm", "-f", id])
            .output();
    }
}

fn register_exit_cleanup() {
    extern "C" { fn atexit(cb: extern "C" fn()) -> std::os::raw::c_int; }
    unsafe { atexit(remove_container_on_exit) };
}

fn cleanup_stale_containers() {
    let output = std::process::Command::new("docker")
        .args(["ps", "-q", "--filter", &format!("label={}", E2E_CONTAINER_LABEL)])
        .output();
    let ids = match output {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        _ => return,
    };
    if ids.is_empty() {
        return;
    }
    let id_list: Vec<&str> = ids.lines().collect();
    info!("Removing {} stale e2e container(s) from previous runs", id_list.len());
    let mut args = vec!["rm", "-f"];
    args.extend(&id_list);
    let _ = std::process::Command::new("docker").args(&args).output();
}

async fn run_helm(kubeconfig: &PathBuf, args: &[&str]) -> Result<()> {
    let output = Command::new("helm")
        .args(args)
        .env("KUBECONFIG", kubeconfig)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .context("Failed to run helm command")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(anyhow!(
            "Helm command failed: {:?}\nstdout: {}\nstderr: {}",
            args,
            stdout,
            stderr
        ));
    }
    Ok(())
}

async fn run_kubectl(kubeconfig: &PathBuf, args: &[&str]) -> Result<()> {
    let output = Command::new("kubectl")
        .args(args)
        .env("KUBECONFIG", kubeconfig)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .context("Failed to run kubectl")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(anyhow!(
            "kubectl failed: {:?}\nstdout: {}\nstderr: {}",
            args,
            stdout,
            stderr
        ));
    }
    Ok(())
}

async fn wait_for_statefulset(client: &Client, namespace: &str, name: &str) -> Result<()> {
    use k8s_openapi::api::apps::v1::StatefulSet;
    let sts: Api<StatefulSet> = Api::namespaced(client.clone(), namespace);

    tokio::time::timeout(Duration::from_secs(300), async {
        loop {
            if let Ok(Some(s)) = sts.get_opt(name).await {
                if let Some(status) = s.status {
                    if status.ready_replicas.unwrap_or(0) >= 1 {
                        return Ok::<_, anyhow::Error>(());
                    }
                }
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    })
    .await
    .context(format!("Timeout waiting for StatefulSet {}", name))?
}

async fn wait_for_zitadel_ready_default_ns(client: &Client) -> Result<()> {
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), "default");

    tokio::time::timeout(Duration::from_secs(300), async {
        loop {
            if let Ok(Some(deployment)) = deployments.get_opt("zitadel").await {
                if let Some(status) = deployment.status {
                    if status.ready_replicas.unwrap_or(0) >= 1 {
                        return Ok::<_, anyhow::Error>(());
                    }
                }
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    })
    .await
    .context("Timeout waiting for ZITADEL")?
}

async fn get_zitadel_service_account(client: &Client) -> Result<String> {
    let secrets: Api<Secret> = Api::namespaced(client.clone(), "default");

    // The ZITADEL Helm chart creates a secret named "zitadel-admin-sa" with the machine key
    tokio::time::timeout(Duration::from_secs(120), async {
        loop {
            // Try the helm-generated secret name pattern
            for secret_name in ["e2e-operator", "zitadel-admin-sa"] {
                if let Ok(Some(secret)) = secrets.get_opt(secret_name).await {
                    if let Some(data) = secret.data {
                        for key in ["e2e-operator.json", "zitadel-admin-sa.json", "key.json"] {
                            if let Some(sa_data) = data.get(key) {
                                let json = String::from_utf8(sa_data.0.clone())?;
                                if json.contains("keyId") {
                                    info!("Found service account in secret {} key {}", secret_name, key);
                                    return Ok::<_, anyhow::Error>(json);
                                }
                            }
                        }
                    }
                }
            }

            // List all secrets to find the machine key
            let secret_list = secrets.list(&ListParams::default()).await?;
            for secret in secret_list {
                let name = secret.metadata.name.clone().unwrap_or_default();
                if let Some(data) = secret.data {
                    for (key, value) in data {
                        if let Ok(json) = String::from_utf8(value.0.clone()) {
                            if json.contains("keyId") && json.contains("userId") {
                                info!("Found service account in secret {} key {}", name, key);
                                return Ok::<_, anyhow::Error>(json);
                            }
                        }
                    }
                }
            }

            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    })
    .await
    .context("Timeout getting service account - no secret with machine key found")?
}

async fn apply_crds(client: &Client) -> Result<()> {
    let crds: Api<CustomResourceDefinition> = Api::all(client.clone());

    let crd_list = vec![
        Organization::crd(),
        Project::crd(),
        ProjectRole::crd(),
        HumanUser::crd(),
        UserGrant::crd(),
        Application::crd(),
    ];

    for crd in &crd_list {
        let name = crd.metadata.name.clone().unwrap();
        crds.patch(
            &name,
            &PatchParams::apply("test-fixture").force(),
            &Patch::Apply(crd),
        )
        .await?;
    }

    for crd in &crd_list {
        let name = crd.metadata.name.clone().unwrap();
        await_condition(crds.clone(), &name, conditions::is_crd_established()).await?;
    }

    Ok(())
}

fn create_zitadel_builder(zitadel_url: &str, sa_json: &str) -> Result<ZitadelBuilder> {
    let sa = ServiceAccount::load_from_json(sa_json)
        .map_err(|e| anyhow!("Failed to load service account: {:?}", e))?;

    let interceptor = ServiceAccountInterceptor::new(
        zitadel_url,
        &sa,
        Some(AuthenticationOptions {
            api_access: true,
            ..Default::default()
        }),
    );

    Ok(ZitadelBuilder::new(zitadel_url.to_string(), interceptor))
}

fn start_controllers(ctx: Arc<OperatorContext>) {
    unsafe {
        std::env::set_var("ZITADEL_DELETE_ORG", "1");
    }

    tokio::spawn(organization::run(ctx.clone()));
    tokio::spawn(project::run(ctx.clone()));
    tokio::spawn(project_role::run(ctx.clone()));
    tokio::spawn(human_user::run(ctx.clone()));
    tokio::spawn(user_grant::run(ctx.clone()));
    tokio::spawn(application::run(ctx.clone()));
}

async fn wait_for_crd_storage_ready(client: &Client) -> Result<()> {
    info!("Waiting for CRD storage to be ready...");

    let orgs: Api<Organization> = Api::all(client.clone());
    let projects: Api<Project> = Api::namespaced(client.clone(), "default");
    let roles: Api<ProjectRole> = Api::namespaced(client.clone(), "default");
    let users: Api<HumanUser> = Api::namespaced(client.clone(), "default");
    let grants: Api<UserGrant> = Api::namespaced(client.clone(), "default");
    let apps: Api<Application> = Api::namespaced(client.clone(), "default");

    let lp = ListParams::default().limit(1);

    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let results = tokio::join!(
                orgs.list(&lp),
                projects.list(&lp),
                roles.list(&lp),
                users.list(&lp),
                grants.list(&lp),
                apps.list(&lp),
            );

            if results.0.is_ok()
                && results.1.is_ok()
                && results.2.is_ok()
                && results.3.is_ok()
                && results.4.is_ok()
                && results.5.is_ok()
            {
                info!("All CRD storage ready");
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    })
    .await
    .context("Timeout waiting for CRD storage to be ready")?
}

async fn delete_all_crs<T>(api: &Api<T>) -> Result<()>
where
    T: kube::Resource<DynamicType = ()>
        + Clone
        + std::fmt::Debug
        + serde::de::DeserializeOwned
        + serde::Serialize,
{
    // Retry listing in case CRD storage is still initializing (429)
    let list = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match api.list(&ListParams::default()).await {
                Ok(list) => return Ok::<_, anyhow::Error>(list),
                Err(kube::Error::Api(ref e)) if e.code == 429 => {
                    info!("CRD storage initializing, retrying...");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                Err(e) => return Err(e.into()),
            }
        }
    })
    .await
    .context("Timeout waiting for CRD storage")??;
    for item in list {
        let name = item.name_any();
        let namespace = item.namespace();
        if let Some(ns) = namespace {
            info!("Deleting {}/{}", ns, name);
        } else {
            info!("Deleting {}", name);
        }
        let _ = api.delete(&name, &DeleteParams::default()).await;
    }
    Ok(())
}

async fn wait_until_empty<T>(api: &Api<T>) -> Result<()>
where
    T: kube::Resource<DynamicType = ()> + Clone + std::fmt::Debug + serde::de::DeserializeOwned,
{
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let list = api.list(&ListParams::default()).await?;
            if list.items.is_empty() {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    })
    .await
    .context("Timeout waiting for resources to be deleted")?
}
