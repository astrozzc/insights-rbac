# Local Validation Script Guidelines

Use a validation script when a feature needs proof against a running local
integration stack: API behavior, background replication, Kessel authorization,
or another service boundary. These scripts complement unit and integration
tests; they are not a replacement for them.

## Location and naming

Place scripts below `scripts/validations/`, grouped by the surface they test:

```text
scripts/validations/
└── api/
    └── v2-crud.sh
```

Use a descriptive, feature-oriented name such as `workspace-move.sh` or
`role-binding-inheritance.sh`. Do not put a pull-request number in a reusable
script name. The all-validation Make command discovers every `*.sh` file
recursively, so no registry needs updating.

## Script contract

- Use Bash and start with `#!/usr/bin/env bash` and `set -euo pipefail`.
- Require an already-running local Docker/Podman stack unless the script starts
  it explicitly. Never target shared, staging, or production environments.
- Provide `--help` and document every optional environment variable, including
  its default.
- Create unique resources using a run identifier. Never rely on or overwrite
  user-created test resources.
- Register `trap cleanup EXIT` before creating data. Cleanup must remove only
  resources, authorization tuples, and settings that the script created.
- If the script temporarily enables a feature gate or V2 write activation,
  remember whether it changed the value and restore only values it enabled.
- Do not print identity headers, tokens, passwords, or other secrets.

## What to validate

Make each scenario explain and prove one observable behavior. Display:

1. The endpoint and input.
2. The expected HTTP status and relevant response field.
3. The reason the scenario matters.
4. A clear `PASS` or `FAIL` result.

For V2 writes that replicate to Kessel, an HTTP success response is not enough.
Wait for the expected direct SpiceDB tuple, assert it exists, and print it. For
deletes, wait until the tuple is absent and report that removal. Use the
persisted `t_*` relation names, for example:

```text
rbac/workspace:<workspace-id> t_binding rbac/role_binding:<binding-id>
rbac/role_binding:<binding-id> t_role rbac/role:<role-id>
rbac/role_binding:<binding-id> t_subject rbac/principal:<domain>/<user-id>
```

Replication is asynchronous. Use a bounded polling loop with a useful failure
message rather than a fixed sleep. Read-only scenarios should print the
relevant existing tuples when available, but must not create state solely to
make a read check pass.

## Local authorization

The local development identity may not have the Kessel permissions needed for
V2 role or role-binding writes. A self-contained validator may create a
short-lived local authorization graph only when it:

- uses uniquely named role and role-binding resources;
- grants the minimum relations required by the scenario;
- removes all of those tuples in cleanup; and
- states this temporary access clearly in its output and documentation.

Prefer permissions scoped to the resource used in the scenario. For example,
a role bound to the Default Workspace needs a permission with Default/Workspace
scope; a tenant-scoped RBAC permission cannot be used for that binding.

## Output

Output should be readable during a local debugging session:

- Group requests into numbered scenarios.
- Use consistent markers for success, failure, and Kessel tuple checks.
- Support terminal colors automatically, with a plain-text fallback for CI or
  redirected output. Honor `NO_COLOR`; use `COLOR=always` only when a caller
  wants forced color.
- On failure, print the HTTP response body or the expected relation details
  needed to diagnose the problem.

## Verification and execution

Before adding a script, run its syntax and help checks:

```bash
bash -n scripts/validations/<area>/<script>.sh
scripts/validations/<area>/<script>.sh --help
```

Then run it against the local full stack. Execute one validation directly:

```bash
scripts/validations/api/v2-crud.sh
```

Run all validation scripts in lexical order:

```bash
make docker-local-full-validate
```

Document the validation in the relevant feature PR: the stack command used,
the script command, the scenarios exercised, and any local-only setup it
temporarily performs.
