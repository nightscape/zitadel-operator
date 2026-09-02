# Action handlers

An `ActionHandler` hooks into [Zitadel Actions v2](https://zitadel.com/docs/guides/integrate/actions/usage).
The operator registers a Zitadel *target* pointing at its own HTTP server plus an
*execution* for the condition, then serves the calls itself: it runs a
[jq](https://jqlang.github.io/jq/) program over the payload Zitadel sends and
hands back what Zitadel should use in place of the original.

## Why this exists

Two Zitadel behaviours have no configuration answer, only an Actions v2 one.

**A federated user can be impossible to create.** When Login V2 auto-creates a
user it calls `zitadel.user.v2.UserService/AddHumanUser` with an `idpLinks`
entry whose `userName` it derives from the token's `preferred_username` claim
and nothing else. A provider that omits that claim leaves the field empty, and
Zitadel rejects its own request:

```
invalid AddHumanUserRequest.IdpLinks[0]: invalid IDPLink.UserName:
value length must be between 1 and 200 runes
```

The login ends at `/ui/v2/login/idp/jwt/failure?error=user_creation_failed`, so
`IdentityProvider`'s `autoRegister: true` does not work against such a provider.

**A freshly created user may not be able to get a token.** With
`projectRoleCheck: true` on the project, a user without a grant is refused:
`Errors.User.GrantRequired (OIDC-foSyH49RvL)`.

Zitadel's v1 Actions (the JS flows and triggers) do **not** run on this path —
Login V2 goes through the v2 API, which only Actions v2 sees.

## Deploying

The operator serves handlers from the same process as its controllers. Two
environment variables configure it:

| Variable | Default | Meaning |
| --- | --- | --- |
| `ACTION_HANDLER_URL` | *(none)* | Base URL Zitadel uses to reach the operator, e.g. `http://zitadel-operator.zitadel.svc.cluster.local:8090`. Required once any `ActionHandler` exists; without it reconciliation fails, because Zitadel has no address to call. |
| `ACTION_HANDLER_PORT` | `8090` | Port the server listens on. |

Zitadel must be able to reach that URL, so the operator needs a `Service` in
front of the port, and the URL must be resolvable from Zitadel rather than from
the operator.

Handlers are inert until an `ActionHandler` exists: no custom resource means no
target, no execution, and no change to how Zitadel behaves.

## The resource

```yaml
apiVersion: zitadel.org/v1alpha
kind: ActionHandler
metadata:
  name: fill-idp-username
  namespace: example
spec:
  condition:
    request:
      method: /zitadel.user.v2.UserService/AddHumanUser
  transform: |
    if (.request.idpLinks[0].userName // "") == "" then
      .request.idpLinks[0].userName = .request.idpLinks[0].userId
    else . end
```

### `condition` (required)

Exactly one of `request`, `response`, `event` or `function`.

| Member | Fires | Can change |
| --- | --- | --- |
| `request: {method}` | before the call | the request |
| `response: {method}` | after the call | the response |
| `event: {event}` | on an event | nothing — Zitadel ignores the answer |
| `function: {name}` | at a named extension point | untested, see [Limitations](#limitations) |

Setting none or several is rejected with a `Warning` event on the resource.

### `when` (optional)

A jq predicate deciding whether the handler applies to this payload. Truthiness
follows jq: everything but `false` and `null`. A handler without a `when`
applies to every call matching its condition.

```yaml
when: '.request.idpLinks[0].idpId == "388841422012287118"'
```

### `transform` (optional)

A jq program mapping the payload Zitadel sent to the payload it should use. It
receives and returns the **whole envelope**; the operator extracts the member
Zitadel reads back.

### `grantRoles` (optional)

The one side effect a handler may have: grant a project role to the user the
payload names.

```yaml
grantRoles:
  projectName: my-project        # Project resource by metadata.name
  projectNamespace: other-ns     # optional, defaults to the handler's namespace
  roleKeys: [user]
  userIdFrom: .response.userId   # optional, this is the default
```

The organization comes from the referenced `Project`'s status, so the project
must be managed by this operator. The grant is idempotent — a user who already
holds it is left alone.

`grantRoles` belongs on a `response` or `event` condition. On a `request`
condition the user does not exist yet and the call carries no id to grant to, so
the operator rejects that combination rather than letting it fail per login.

## The payload

Zitadel posts JSON shaped like this
([source](https://github.com/zitadel/zitadel/blob/main/internal/api/grpc/server/middleware/execution_interceptor.go)):

```json
{
  "fullMethod": "/zitadel.user.v2.UserService/AddHumanUser",
  "instanceID": "344648897353744526",
  "orgID": "344648897353810062",
  "projectID": "344648897353875598",
  "userID": "344648897354465422",
  "headers": { "...": ["..."] },
  "request": { "...": "the call's request" },
  "response": { "...": "the call's response, on a response condition only" }
}
```

Members come from `protojson`, so they are camelCase. `response` is present only
for a response condition.

### What the handler answers with

A request execution unmarshals the answer into the **request**, and a response
execution into the **response**. The operator therefore answers with that member
alone, never the whole envelope — returning the envelope would silently do
nothing.

Zitadel reads a response body only when it got one (`if len(resp) > 0`), so an
**empty body means "keep what you had"**. That is what the operator sends
whenever nothing changed or anything went wrong.

Do not let a transform produce `forwardedStatusCode` or `forwardedErrorMessage`
at the top level: Zitadel reads those as an instruction to fail the call.

## Failure policy

This code sits in the login path, so no failure may change what Zitadel does.
Every one of these answers with an empty body and logs loudly:

* the payload is not JSON
* the `ActionHandler` does not exist, or its spec is not coherent
* a jq program does not compile, throws, or produces no output

Targets are registered with `interruptOnError: false`, so a handler that is
down or slow cannot break the call it hooked. Failing closed here would block
every user creation on the instance.

A failing `transform` does **not** cancel `grantRoles` on the same resource;
the two are independent.

## Security

The endpoint can write a role grant, so a caller that is not Zitadel must not
reach that effect.

Zitadel signs each payload with the target's signing key, as
`ZITADEL-Signature: t=<unix>,v1=<hex>` over `<unix>.<body>` using HMAC-SHA256.
The operator verifies it. A call that fails verification is still **answered
normally**, but `grantRoles` is skipped — refusing to answer would break logins,
whereas skipping the grant only costs the effect.

Zitadel reveals a target's signing key only when it mints one, so the operator
stores it in a `Secret` named `<handler-name>-action-handler` (field
`signingKey`) beside the handler, owned by it so deletion takes it along. The
server reads that Secret when its in-process cache is cold, which is what lets a
freshly started operator verify the very first call it receives. If the key is
lost entirely, the next reconcile rotates it.

The timestamp is deliberately **not** checked against a tolerance: a replayed
grant is the grant the payload already asked for, and clock skew rejecting a
real call is the worse failure.

## Reconciliation

The controller ensures a target named `k8s/<namespace>/<name>` pointing at
`<ACTION_HANDLER_URL>/handlers/<namespace>/<name>`, and an execution for the
condition. It adopts an existing target with that name rather than creating a
duplicate.

A condition's target list is derived from **every** `ActionHandler` claiming it,
not just the one being reconciled, because Zitadel's `SetExecution` replaces the
list outright and two handlers would otherwise erase each other. Deleting a
handler re-derives the list from the rest and removes its target.

`status` carries `targetId`, the `condition` currently registered in Zitadel
(so a changed spec can rebuild the execution it leaves), and `phase`.

## Examples

Repair an IdP link with no username, so `autoRegister` works against a provider
that sends no `preferred_username`:

```yaml
apiVersion: zitadel.org/v1alpha
kind: ActionHandler
metadata:
  name: fill-idp-username
  namespace: example
spec:
  condition:
    request:
      method: /zitadel.user.v2.UserService/AddHumanUser
  transform: |
    if (.request.idpLinks[0].userName // "") == "" then
      .request.idpLinks[0].userName = .request.idpLinks[0].userId
    else . end
```

Give a user created through one specific provider a default role, so a project
with `projectRoleCheck` will issue them a token:

```yaml
apiVersion: zitadel.org/v1alpha
kind: ActionHandler
metadata:
  name: grant-default-role
  namespace: example
spec:
  condition:
    response:
      method: /zitadel.user.v2.UserService/AddHumanUser
  when: '.request.idpLinks[0].idpId == "388841422012287118"'
  grantRoles:
    projectName: my-project
    roleKeys: [user]
```

## Limitations

* **`function` conditions are untested.** Zitadel's payload for a function
  execution is shaped by the function; the operator answers with the whole
  transform output rather than a member of it, which is a guess.
* **No live verification yet.** The payload shape and the response contract
  above are read from Zitadel's source, and request and response conditions
  carry unit tests over recorded payload shapes. No condition has yet been
  observed against a running Zitadel.
* **The rejection of `grantRoles` on a `request` condition is enforced by the
  operator, not the API server.** It surfaces as a reconcile error and a
  `Warning` event rather than a rejected `kubectl apply`.
* **A multi-output jq program keeps only its first output.**
