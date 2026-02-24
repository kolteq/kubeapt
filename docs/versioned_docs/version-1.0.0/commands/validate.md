---
title: kubeapt validate
---

# kubeapt validate

Validate admission policies and bindings against resources from a cluster or local files. Use the flags below to select bundles, policies, and the resources to evaluate.

## Usage

```bash
kubeapt validate [flags]
```

## Subcommands

None.

## Arguments

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| --pipeline | bool | false | Indicate the command runs inside CI/CD |
| -A, --all-namespaces | bool | false | Use all namespaces instead of the active one |
| -n, --namespaces | string |  | Comma separated list of namespaces to evaluate |
| --namespace-selector | string |  | Label selector to choose namespaces (e.g. env=prod) |
| -f, --format | string | table | Specify the report output format: table or json |
| --report | string | summary | Specify the final report type: summary or all |
| --output | string |  | Write the report to a file path instead of stdout |
| --bundle | string |  | Policy bundle name to use for policies/bindings |
| --bundle-version | string |  | Bundle version to use with --bundle (defaults to latest) |
| -p, --policies | string |  | Specify the file or folder to the ValidatingAdmissionPolicy YAML file |
| -P, --policy-name | string |  | Policy name to use from downloaded policies |
| -b, --bindings | string |  | Specify the file or folder to the ValidatingAdmissionPolicyBinding YAML file |
| -r, --resource | string |  | Specify the file or folder to the resource YAML file to validate |
| --psa-level | string |  | PSA level to evaluate when using the pod-security-admission bundle: baseline or restricted |
| --log-file | string |  | Optional file to capture WARN/AUDIT output |
| --ignore-bindings | bool | false | Ignore binding match rules and match policies on all selected resources |
| --view | string |  | Report view: policy, namespace, or resource |
| --log-level | string | info | Set logging level (debug, info, warn, error) |
| --kubeconfig | string |  | Path to kubeconfig file |
| -h, --help | bool | false | Show help for this command |
