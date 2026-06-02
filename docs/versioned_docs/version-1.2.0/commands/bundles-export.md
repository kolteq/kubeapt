---
title: kubeapt bundles export
---

# kubeapt bundles export

Export an installed policy bundle as a portable `.tar.gz` archive plus a matching `.sha256` sidecar, ready to transfer to an offline or air-gapped host and re-installed there with [`kubeapt bundles import`](./bundles-import.md).

The exported archive contains exactly `bundle.json`, `policies.yaml`, and `bindings.yaml` at the root — the same shape the importer expects.

## Usage

```bash
kubeapt bundles export <bundle-name> [flags]
```

## Subcommands

None.

## Arguments

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| --version | string |  | Bundle version to export (defaults to the latest installed) |
| --output | string |  | Output path (defaults to `<bundle>-<version>.tar.gz` in the current directory) |
| --log-level | string | info | Set logging level (debug, info, warn, error) |
| --kubeconfig | string |  | Path to kubeconfig file |
| -h, --help | bool | false | Show help for this command |

## Example

```bash
kubeapt bundles export pod-security-admission --output ./transfer/
# writes ./transfer/pod-security-admission-v1.36.0.tar.gz and pod-security-admission-v1.36.0.tar.gz.sha256
```
