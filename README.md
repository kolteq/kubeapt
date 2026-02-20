![kubeapt logo](logo.png)

# Kubernetes Admission Policy Toolkit - kubeapt

Kubeapt is a command-line utility by KolTEQ GmbH that validates Kubernetes admission hardening. It inspects ValidatingAdmissionPolicies (VAP), Pod Security Admission (PSA) labels, and common admission integrations both from local manifests and against a live cluster.

## Table of Contents
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  - [Bundle list](#bundle-list)
  - [Bundle download](#bundle-download)
  - [Validate](#validate)
  - [Validate PSA Bundle](#validate-psa-bundle)
  - [Scan](#scan)
  - [Development](#development)
  - [Roadmap](#roadmap)
  - [Contributing](#contributing)

## Features
- Validate admission policies/bindings against cluster resources (default) or local manifests with CEL execution and reporting modes.
- Evaluate PSA compliance using the `pod-security-admission` bundle and PSA levels (baseline/restricted).
- Scan a cluster for PSA adoption, Kyverno/OPA deployments, built-in admission plugins, and webhook targets.
- Produce JSON or table-based compliance summaries, detailed violation logs, and resource inventories.
- Flexible resource loading from files, directories, or live API queries with namespace selection helpers.

## Installation
```bash
go install github.com/kolteq/kubeapt@latest
```

Alternatively run from source within this repository:
```bash
go run ./main.go <command>
```

### Docker

```
docker build -t kubeapt .
docker run -it --rm --name kubeapt --net=host -v <PATH_TO_KUBECONFIG>:<PATH_TO_KUBECONFIG> kubeapt --kubeconfig <PATH_TO_KUBECONFIG> <scan/validate>
```

## Usage
Top-level commands:
- `validate` – evaluate ValidatingAdmissionPolicies/Bindings
- `scan` – inspect a cluster for admission hardening components
- `bundle` - manage policy bundles (list, PSA download/deploy/delete)

Global flags shared by validate:
- `--pipeline` – non-zero exit on violations (intended for CI/CD)
- `-A, --all-namespaces` – evaluate all namespaces (remote resources only)
- `-n, --namespaces` – comma-separated namespace filter (remote resources only)
- `-f, --format` – select `table` (default) or `json` report format
- `--output` – write the report to a file path

### Bundle list
```bash
go run main.go bundle list
```
Lists all available policy bundles and their versions from the KolTEQ bundle index.

### Bundle download
```bash
go run main.go bundle download <bundle-name> [--version vX.Y.Z]
```
Downloads `bundle.json`, the bundle source tarball plus checksum, and extracts the bundle into `~/.config/kubeapt/bundles/<bundle-name>/<bundle-version>`.

### Validate
```bash
go run main.go validate \
  --policies ./policies \
  --bindings ./bindings \
  --resource ./resources \
  --report summary|all \
  [--ignore-bindings]
```
Key capabilities:
- Load policies/bindings/resources from files or directories (YAML/JSON) or directly from the API server (default).
- Respect ValidatingAdmissionPolicyBindings, selectors, match resources, namespaces, and CEL expressions.
- `--report all` prints detailed violation logs; `summary` prints compliance totals.
- `--ignore-bindings` applies policies across all matching resource kinds (bindings become optional).

Example:
```bash
go run main.go validate \
  --policies ./examples/policies \
  --resource ./examples/workloads \
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

### Validate PSA Bundle
```bash
go run main.go validate \
  --bundle pod-security-admission \
  --psa-level baseline \
  [--resource ./manifests]
```
Highlights:
- Summarize namespace PSA levels (enforce/audit/warn). Levels sourced from KolTEQ labels show as `restricted (KolTEQ)`.
- Uses the same PSA table format as the scan command; no violation listing for PSA.

Example:
```bash
go run main.go validate \
  --bundle pod-security-admission \
  --psa-level restricted \
  --resource ./examples/workloads
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

## Star History
[![Star History Chart](https://starchart.cc/kolteq/kubeapt.svg)](https://starchart.cc/kolteq/kubeapt)
