---
title: kubeapt bundles uninstall
---

# kubeapt bundles uninstall

Uninstall a policy bundle from the cluster. Provide the bundle name as the required argument.

## Usage

```bash
kubeapt bundles uninstall <bundle-name> [flags]
```

## Subcommands

None.

## Arguments

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| --version | string |  | Bundle version to uninstall (defaults to latest) |
| --dry-run | bool | false | Preview changes without applying them |
| --log-level | string | info | Set logging level (debug, info, warn, error) |
| --kubeconfig | string |  | Path to kubeconfig file |
| -h, --help | bool | false | Show help for this command |
