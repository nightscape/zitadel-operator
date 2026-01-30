# ZITADEL Operator

This repository contains an operator for managing ZITADEL resources such as organizations, projects and applications
from within a Kubernetes cluster. It automates the lifecycle using custom resources, making it easy to integrate
identity management into your cloud-native workflows.

## Features

* Manage ZITADEL organizations, projects, human users, project roles, user grants, and applications via Kubernetes custom resources
* Automatically generate Kubernetes `Secret`s with application client ID, client secret, and OIDC discovery endpoints
* Adopt existing ZITADEL resources: when a CRD is created whose name matches an existing ZITADEL resource, the operator adopts it instead of creating a duplicate
* Periodic reconciliation: the operator re-checks ZITADEL state at a configurable interval, automatically fixing drift between CRD spec and ZITADEL (set `REQUEUE_SECS`, default 300)
* Property-based E2E tests using `proptest` state machine testing, including Zitadel-direct gRPC operations that validate adoption and drift correction

## Getting Started (Development)

1. Clone this repository
2. Install [Task](https://taskfile.dev/docs/installation), Docker and Rust
3. Setup local development environment:

```bash
task setup
```

This will:
* Install (if needed) Kind and mkcert
* Create a local Kubernetes cluster
* Generate TLS certificates
* Bootstrap ZITADEL and dependencies

You can now begin developing. Some useful commands:

* `task --list` - List all available tasks
* `task cluster:apply-crd` - Apply the CRD to the Kind cluster
* `task run` - Run the operator locally
* `task test:integration` - Run interactive integration tests
