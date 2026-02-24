---
title: kubeapt policies show
---

# kubeapt policies show

Show policy details or list policy summaries when no name is provided. Optionally specify a version and output format.

## Usage

```bash
kubeapt policies show [policy-name] [flags]
```

## Subcommands

None.

## Arguments

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| --version | string |  | Policy version to use (defaults to latest) |
| -f, --format | string | table | Output format: table, yaml, or json |
| --log-level | string | info | Set logging level (debug, info, warn, error) |
| --kubeconfig | string |  | Path to kubeconfig file |
| -h, --help | bool | false | Show help for this command |
