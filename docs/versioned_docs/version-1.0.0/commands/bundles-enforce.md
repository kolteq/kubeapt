---
title: kubeapt bundles enforce
---

# kubeapt bundles enforce

Set or remove the bundle enforce label on one or more namespaces. Provide the bundle name as the required argument.

## Usage

```bash
kubeapt bundles enforce <bundle-name> [flags]
```

## Subcommands

None.

## Arguments

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| -n, --namespace | string |  | Namespace to label |
| -A, --all-namespaces | bool | false | Apply the label to all namespaces |
| --namespace-selector | string |  | Label selector to choose namespaces (e.g. env=prod) |
| --overwrite | bool | false | Overwrite an existing bundle label |
| --remove | bool | false | Remove the bundle label instead of setting it |
| --psa-level | string |  | PSA level for pod-security-admission: baseline or restricted |
| --log-level | string | info | Set logging level (debug, info, warn, error) |
| --kubeconfig | string |  | Path to kubeconfig file |
| -h, --help | bool | false | Show help for this command |
