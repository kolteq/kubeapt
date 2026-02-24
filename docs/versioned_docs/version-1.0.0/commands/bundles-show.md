---
title: kubeapt bundles show
---

# kubeapt bundles show

Show the policies and bindings contained in a bundle. Provide the bundle name as the required argument.

## Usage

```bash
kubeapt bundles show <bundle-name> [flags]
```

## Subcommands

None.

## Arguments

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| --version | string |  | Bundle version to show (defaults to latest) |
| -f, --format | string | table | Output format: table, yaml, or json |
| --log-level | string | info | Set logging level (debug, info, warn, error) |
| --kubeconfig | string |  | Path to kubeconfig file |
| -h, --help | bool | false | Show help for this command |
