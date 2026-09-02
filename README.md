# ZITADEL Operator

This repository contains an operator for managing ZITADEL resources such as organizations, projects and applications
from within a Kubernetes cluster. It automates the lifecycle using custom resources, making it easy to integrate
identity management into your cloud-native workflows.

## Features

* Manage ZITADEL organizations, projects, human users, project roles, user grants, identity providers, and applications via Kubernetes custom resources
* Hook into ZITADEL [Actions v2](docs/action-handlers.md) with `ActionHandler`: rewrite the payload of an API call with a jq program, or grant a project role to a user the call creates
* Automatically generate Kubernetes `Secret`s with application client ID, client secret, and OIDC discovery endpoints
* Adopt existing ZITADEL resources: when a CRD is created whose name matches an existing ZITADEL resource, the operator adopts it instead of creating a duplicate
* Periodic reconciliation: the operator re-checks ZITADEL state at a configurable interval, automatically fixing drift between CRD spec and ZITADEL (set `REQUEUE_SECS`, default 300)
* Property-based E2E tests using `proptest` state machine testing, including Zitadel-direct gRPC operations that validate adoption and drift correction

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `ZITADEL_URL` | *(none)* | ZITADEL base URL. Required. |
| `ZITADEL_SECRET_NAME` | *(none)* | Secret holding the service account JSON. Required. |
| `ZITADEL_SECRET_NAMESPACE` | `zitadel` | Namespace of that secret |
| `ZITADEL_HEADERS` | *(none)* | Extra headers on every ZITADEL call, as `key=value,key=value` |
| `REQUEUE_SECS` | `300` | Reconciliation interval |
| `ZITADEL_DELETE_ORG` | `0` | Set to `1` to delete the ZITADEL organization when an `Organization` resource is removed. Off by default, so deleting the resource leaves the organization standing. |
| `ACTION_HANDLER_URL` | *(none)* | Base URL ZITADEL uses to reach the operator's action handler server. Required once an `ActionHandler` exists — see [Action handlers](docs/action-handlers.md). |
| `ACTION_HANDLER_PORT` | `8090` | Port the action handler server listens on |
| `ZITADEL_LOG` | `info` | Log filter |
| `ZITADEL_LOG_ALL` | `0` | Set to `1` to keep the noisy `DEBUG` output from HTTP and gRPC libraries |

## Documentation

* [Action handlers](docs/action-handlers.md) — hooking into ZITADEL Actions v2

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
