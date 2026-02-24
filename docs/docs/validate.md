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
