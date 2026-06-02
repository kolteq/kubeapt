---
title: kubeapt bundles install
---

# kubeapt bundles install

Install a policy bundle into the cluster. Provide the bundle name as the required argument.

## Usage

```bash
kubeapt bundles install <bundle-name> [flags]
```

## Subcommands

None.

## Arguments

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| --version | string |  | Bundle version to install (defaults to latest) |
| --overwrite | bool | false | Overwrite existing bindings |
| --dry-run | bool | false | Preview changes without applying them |
| --log-level | string | info | Set logging level (debug, info, warn, error) |
| --kubeconfig | string |  | Path to kubeconfig file |
| -h, --help | bool | false | Show help for this command |
