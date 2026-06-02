---
title: kubeapt bundles
---

# kubeapt bundles

Manage policy bundles, including download, install, and namespace labeling. Choose a subcommand below.

## Usage

```bash
kubeapt bundles <command> [flags]
```

## Subcommands

| Command | Description |
| --- | --- |
| `download` | Download a policy bundle |
| `install` | Install a policy bundle into the cluster |
| `list` | List available policy bundles and versions |
| `audit` | Set the bundle audit label on a namespace |
| `enforce` | Set the bundle enforce label on a namespace |
| `warn` | Set the bundle warn label on a namespace |
| `remove` | Remove a policy bundle version from local storage |
| `show` | Show policies and bindings for a bundle |
| `uninstall` | Uninstall a policy bundle from the cluster |

## Arguments

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| --log-level | string | info | Set logging level (debug, info, warn, error) |
| --kubeconfig | string |  | Path to kubeconfig file |
| -h, --help | bool | false | Show help for this command |
