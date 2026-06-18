---
title: kubeapt bundles import
---

# kubeapt bundles import

Install a policy bundle from a local `.tar.gz` archive instead of downloading it from the public index. Built for offline and air-gapped environments.

The archive must contain `bundle.json`, `policies.yaml`, and `bindings.yaml` at its root. `bundle.json` declares the bundle name and version, so the import command can determine the destination directory without extra flags.

Every import is checksum-verified. By default the command looks for a sibling `<archive>.sha256` file; pass `--checksum <hex>` to supply the expected SHA-256 inline.

## Usage

```bash
kubeapt bundles import --from <archive> [flags]
```

## Subcommands

None.

## Arguments

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| --from | string |  | Path to a bundle archive (`.tar.gz`). Required. |
| --checksum | string |  | Expected SHA-256 of the archive (hex). Overrides any sidecar file. |
| --force | bool | false | Overwrite an existing bundle version on disk |
| --log-level | string | info | Set logging level (debug, info, warn, error) |
| --kubeconfig | string |  | Path to kubeconfig file |
| -h, --help | bool | false | Show help for this command |

## Example

```bash
kubeapt bundles export pod-security-admission --version v1.36.0 --output pod-security-admission-v1.36.0.tar.gz
# transfer pod-security-admission-v1.36.0.tar.gz + .sha256 to the air-gapped host
kubeapt bundles import --from pod-security-admission-v1.36.0.tar.gz
```

See [Air-gapped installs](../air-gapped.md) for the full workflow.
