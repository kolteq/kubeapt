---
title: kubeapt policies uninstall
---

# kubeapt policies uninstall

Uninstall a policy from the cluster. Provide the policy name as the required argument.

## Usage

```bash
kubeapt policies uninstall <policy-name> [flags]
```

## Subcommands

None.

## Arguments

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| --version | string |  | Policy version to use (defaults to latest) |
| --dry-run | bool | false | Preview changes without applying them |
| --log-level | string | info | Set logging level (debug, info, warn, error) |
| --kubeconfig | string |  | Path to kubeconfig file |
| -h, --help | bool | false | Show help for this command |
