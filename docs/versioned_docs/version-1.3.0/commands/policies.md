---
title: kubeapt policies
---

# kubeapt policies

Manage individual policies, including download, install, and uninstall. Choose a subcommand below.

## Usage

```bash
kubeapt policies <command> [flags]
```

## Subcommands

| Command | Description |
| --- | --- |
| `list` | List available policy versions |
| `download` | Download policies into local storage |
| `remove` | Remove policies from local storage |
| `install` | Install a policy into the cluster |
| `uninstall` | Uninstall a policy from the cluster |
| `show` | Show policy details |

## Arguments

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| --log-level | string | info | Set logging level (debug, info, warn, error) |
| --kubeconfig | string |  | Path to kubeconfig file |
| -h, --help | bool | false | Show help for this command |
