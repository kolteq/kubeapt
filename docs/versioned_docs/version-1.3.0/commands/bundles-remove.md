---
title: kubeapt bundles remove
---

# kubeapt bundles remove

Remove a downloaded policy bundle version from local storage. Provide the bundle name as the required argument.

## Usage

```bash
kubeapt bundles remove <bundle-name> [flags]
```

## Subcommands

None.

## Arguments

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| --version | string |  | Bundle version to remove (defaults to latest downloaded) |
| --log-level | string | info | Set logging level (debug, info, warn, error) |
| --kubeconfig | string |  | Path to kubeconfig file |
| -h, --help | bool | false | Show help for this command |
