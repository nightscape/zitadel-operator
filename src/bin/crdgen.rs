use kube::CustomResourceExt;
use zitadel_operator::schema::{
    Application, EmailProviderSmtp, HumanUser, IdentityProvider, MachineUser, Organization,
    Project, ProjectRole, UserGrant,
};

fn main() {
    println!("{}", serde_yaml::to_string(&Organization::crd()).unwrap());
    println!("---\n{}", serde_yaml::to_string(&Project::crd()).unwrap());
    println!("---\n{}", serde_yaml::to_string(&ProjectRole::crd()).unwrap());
    println!("---\n{}", serde_yaml::to_string(&HumanUser::crd()).unwrap());
    println!("---\n{}", serde_yaml::to_string(&UserGrant::crd()).unwrap());
    println!("---\n{}", serde_yaml::to_string(&Application::crd()).unwrap());
    println!("---\n{}", serde_yaml::to_string(&MachineUser::crd()).unwrap());
    println!("---\n{}", serde_yaml::to_string(&EmailProviderSmtp::crd()).unwrap());
    println!("---\n{}", serde_yaml::to_string(&IdentityProvider::crd()).unwrap());
}
