---
title: kubeapt
---

# kubeapt

Kubeapt is the command-line interface for validating admission policies, scanning clusters, and managing policy bundles and policies. Run a subcommand with the global flags below.

## Usage

```bash
kubeapt [command] [flags]
```

## Subcommands

| Command | Description |
| --- | --- |
| `validate` | Validate admission policies against resources |
| `scan` | Scan the connected cluster for admission safeguards |
| `bundles` | Manage policy bundles |
| `policies` | Manage policies |

## Arguments

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| --log-level | string | info | Set logging level (debug, info, warn, error) |
| --kubeconfig | string |  | Path to kubeconfig file |
| --version | bool | false | Show version and exit |
| -h, --help | bool | false | Show help for this command |
