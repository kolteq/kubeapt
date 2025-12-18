# Kubernetes Admission Policy Toolkit - kubeapt

Kubeapt is a command-line utility by KolTEQ GmbH that validates Kubernetes admission hardening. It inspects ValidatingAdmissionPolicies (VAP), Pod Security Admission (PSA) labels, and common admission integrations both from local manifests and against a live cluster.

## Features
- Validate VAP policies/bindings against local or remote resources with CEL execution and reporting modes.
- Audit PSA namespace labels from manifests or live clusters, with Pod Security label mapping (`pod-security.kubernetes.io/*` ↔ `pss.kolteq.com/*`).
- Scan a cluster for PSA adoption, Kyverno/OPA deployments, built-in admission plugins, and webhook targets.
- Produce JSON or table-based compliance summaries, detailed violation logs, and resource inventories.
- Flexible resource loading from files, directories, or live API queries with namespace selection helpers.

## Installation
```bash
go install github.com/kolteq/kubeapt@v0.1.1
```

Alternatively run from source within this repository:
```bash
go run ./main.go <command>
```

## Usage
Top-level commands:
- `validate vap` – evaluate ValidatingAdmissionPolicies/Bindings
- `validate psa` – summarize Pod Security Admission levels per namespace (KolTEQ labels highlighted)
- `scan` – inspect a cluster for admission hardening components

Global flags shared by validate subcommands:
- `--pipeline` – non-zero exit on violations (intended for CI/CD)
- `-A, --all-namespaces` – evaluate all namespaces (remote resources only)
- `-n, --namespaces` – comma-separated namespace filter (remote resources only)
- `-o, --output` – select `table` (default) or `json` report format

### Validate VAP
```bash
go run main.go validate vap \
  --policies ./policies \
  --bindings ./bindings \
  --resources ./resources \
  --report summary|all \
  [--remote-policies] [--remote-resources] [--ignore-selectors]
```
Key capabilities:
- Load policies/bindings/resources from files or directories (YAML/JSON) or directly from the API server.
- Respect ValidatingAdmissionPolicyBindings, selectors, match resources, namespaces, and CEL expressions.
- `--report all` prints detailed violation logs; `summary` prints compliance totals.
- `--ignore-selectors` applies policies across all matching resource kinds.

Example:
```bash
go run main.go validate vap \
  --policies ./examples/policies \
  --resources ./examples/workloads \
  --report summary
```
Possible output:
```
Policy Compliance
───────────────────────────────────────────────
Policy                       Binding   Compliant   Non-Compliant
restricted-image-registry   default    4           1

Resources by Kind
──────────────────
Kind       Total
Pod        5
Namespace  1
```

### Validate PSA
```bash
go run main.go validate psa \
  [--resources ./manifests] \
  [--remote-namespaces]
```
Highlights:
- Summarize namespace PSA levels (enforce/audit/warn). Levels sourced from KolTEQ labels show as `restricted (KolTEQ)`.
- Pull namespace labels with `--remote-namespaces` or rely on local manifests when available.
- Uses the same PSA table format as the scan command; no violation listing for PSA.

Example:
```bash
go run main.go validate psa \
  --resources ./examples/workloads
```
Possible output:
```
PSA Namespace Levels
────────────────────────────────────────
Namespace   Enforce       Audit   Warn
dev         baseline      -       -
prod        restricted    -       restricted (KolTEQ)
```

### Scan
```bash
go run main.go scan
```
Outputs:
- PSA namespace summary table (enforce/audit/warn labels).
- Presence of ValidatingAdmissionPolicies, Kyverno, or OPA Gatekeeper deployments.
- Enabled/disabled built-in admission plugins gleaned from the kube-apiserver pod.
- Full listing of validating/mutating webhook configurations and their targets.

Example:
```bash
go run main.go scan
```
Possible output:
```
[1/3] Inspecting namespaces and admission controllers...
PSA Namespace Levels
────────────────────────────────────────
Namespace   Enforce       Audit   Warn
default     baseline      -       -
prod        restricted    audit   warn (KolTEQ)

ValidatingAdmissionPolicies present: 2
Kyverno detected in cluster

[2/3] Inspecting built-in admission plugins...
Enabled admission plugins:
NamespaceLifecycle, MutatingAdmissionWebhook, ValidatingAdmissionWebhook, PodSecurity

[3/3] Inspecting registered webhooks...
Validating Webhook Configurations
──────────────────────────────────────────
Config        Webhook        Target
kyverno       validate-pods  kyverno/kyverno-svc/validate
```

## Development
- Format code with `gofmt` before submitting changes.
- Run `go test ./...` where possible; remote Kubernetes operations require kubeconfig access.
- Use the provided logging helpers under `internal/logging` for structured output.

## Roadmap
1. Add worked CI/CD examples demonstrating pipeline usage.
2. Provide an official Dockerfile for containerized execution.

## Contributing
Pull requests and issues are welcome. Please include relevant tests or sample manifests to illustrate validation scenarios.

For questions contact <hello@kolteq.com>.
