---
sidebar_position: 4
title: Validate
---

# Validate

`kubeapt validate` evaluates ValidatingAdmissionPolicies (VAP) and bindings against Kubernetes resources. It can operate on a live cluster or on local manifests and produces table or JSON reports that are suitable for audits and CI.

## Inputs and scope

You can validate resources from the cluster or from local files:

- Cluster resources: omit `--resource` and kubeapt will fetch matching resources from the cluster.
- Local resources: use `--resource` to point at a file or directory of YAML/JSON resources.
- Policies and bindings:
  - `--bundle <name>` uses a downloaded bundle.
  - `--policies` / `--bindings` use local manifest files or directories.
  - `--policy-name` selects a single policy from downloaded policy versions.

Namespace filtering:

- `--all-namespaces` evaluates all namespaces.
- `--namespaces` accepts a comma-separated list.
- `--namespace-selector` selects namespaces by label.

## Filtering policies by resource

`--policyresource` (alias `--pr`, shorthand `-R`) narrows the policy set to only the policies whose `matchConstraints` target the named resource. Values are the **plural** resource names — the same form used in a policy's `spec.matchConstraints.resourceRules.resources` (for example `pods` or `deployments`), not the Kind:

```bash
# Only evaluate policies that target Pods
kubeapt validate --bundle my-bundle --pr pods

# Multiple resources, comma-separated
kubeapt validate --bundle my-bundle --policyresource pods,deployments
```

This works with any policy source (`--bundle`, `--policies`, `--policy-name`, or the live cluster). Behavior:

- Matching is case-insensitive and compares on the base resource, so a policy that targets `pods/status` is kept by `--pr pods`.
- A policy whose rule uses the `*` (or `*/*`) wildcard targets every resource and is always kept.
- Any binding that references a filtered-out policy is dropped, and when validating cluster resources only the retained resource kinds are fetched.
- If no policy in the set targets the requested resource, the command exits with an error.

> `-pr` (a single dash) is not a valid shorthand — flag shorthands are a single character, so `-pr` would be read as `-p r`. Use `-R`, or the `--pr` long alias.

### Group-aware filtering with `--policy-resources`

`--policyresource` matches on the resource plural alone, so it cannot tell apart resources that share a plural across API groups — for example `networkpolicies` in `networking.k8s.io` versus `projectcalico.org`. When the group matters, use `--policy-resources`, which takes `group/version/resource` selectors:

```bash
# Only the built-in NetworkPolicy and core Service policies — not Calico's
kubeapt validate --bundle my-bundle \
  --policy-resources networking.k8s.io/v1/networkpolicies,/v1/services
```

Selector forms (comma-separated):

- `group/version/resource` — e.g. `networking.k8s.io/v1/networkpolicies`.
- `group/resource` — version defaults to any, e.g. `projectcalico.org/networkpolicies`.
- `/version/resource` or `/resource` — a leading empty group selects the **core** group, e.g. `/v1/services`.
- `resource` — a bare resource matches that resource in **any** group.

Matching is an exact comparison against the policy's `matchConstraints` (group + plural resource), with no Kind→resource conversion, so it needs no cluster. The group is matched literally (the empty string is the core group); the version is **not used for selection** (matching is on group + resource only, so any version you write is accepted but ignored); and a policy rule using an `apiGroups`/`resources` wildcard (`*`) is always kept. `--policy-resources` and `--policyresource` cannot be combined.

The same selection is available to Go callers as the `scanner.WithPolicyResources([]scanner.GVR{…})` option, so embedders get group-aware policy selection without going through the CLI.

## Views

`--view` controls how results are grouped:

- `policy` (default): policy/binding level summaries.
- `namespace`: compliance per namespace.
- `resource`: violations grouped by resource.

If you use a bundle, the default view is `namespace`. Otherwise it is `policy`.

## Report modes

`--report` determines how much detail is included:

- `summary` (default): compliance counts only.
- `all`: adds full violation details.

## Output formats

`--format` controls the report output:

- `table` (default) prints styled tables and optional violation sections.
- `json` prints a structured JSON report.

You can write output to a file with `--output`. When writing to a file, table output is rendered without color and progress indicators are disabled for JSON.

### Table output (policy view)

- `Policy Compliance Overview` table with `Policy`, `Binding`, `Mode`, `Total`, `Compliant`, `NonCompliant`.
- `Resources by Kind` table with totals for each resource kind.
- `Violations` section when `--report all` is used.

### Table output (namespace view)

- `Namespace` table with `Total`, `Compliant`, `NonCompliant`.
- `Resources by Kind` table.
- `Violations` section when `--report all` is used.

### Table output (resource view)

- Resource table with `Resource`, `Violations (Bindings)`, `Violations`, `Policies`.
- `Violations` section when `--report all` is used.

### JSON output

JSON output is wrapped in an envelope with metadata and results:

- `metadata.command`: the full command line.
- `metadata.view`: `policies`, `namespaces`, or `resources`.
- `metadata.kubernetes`: cluster name, namespaces evaluated, and resource totals.
- `metadata.time`: start and stop epoch timestamps.
- `results`: view-specific report payloads including `report`, `format`, and the data arrays.

## PSA evaluation

If you validate the `pod-security-admission` bundle, you must specify a PSA level:

```bash
kubeapt validate --bundle pod-security-admission --psa-level baseline
```

Supported levels are `baseline` and `restricted`.

## CI behavior

`--pipeline` makes the command exit non-zero when violations are detected in the chosen view. Use this to fail CI runs on admission policy regressions.

## Logging

- `--log-level` sets the CLI log level (`debug`, `info`, `warn`, `error`).
- `--log-file` captures warning/audit logs to a file during validation.
