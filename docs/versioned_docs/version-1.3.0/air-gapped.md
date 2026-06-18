---
sidebar_position: 7
title: Air-gapped installs
---

# Air-gapped installs

KubeAPT runs end-to-end without network access once policy bundles are present on disk. This guide walks through the two-machine workflow: build a portable archive on a connected host, transfer it, and install it on the air-gapped host.

## What works offline

- `kubeapt scan` — inspects namespaces, admission controllers, webhooks, and posture using the connected cluster's API only. No outbound HTTP.
- `kubeapt validate` — runs entirely against local manifests and locally installed bundles. The version resolver no longer queries the public bundle index; if `--bundle X` is used without `--bundle-version`, kubeapt picks the highest version present in `~/.config/kubeapt/bundles/<X>/`.
- `kubeapt bundles import` and `kubeapt bundles export` — file-based, no network.
- The embedded Go API (`pkg/policies`, `pkg/scanner`) — see [Embedding KubeAPT](./embedding.md).

## What still needs network

- `kubeapt bundles download` and `kubeapt policies download` — these explicitly fetch from the public index and are the only kubeapt commands that reach out. Use them on a connected host to seed the air-gap.

## Workflow

### 1. On a connected host: download and export

```bash
# Fetch the bundle from the public index
kubeapt bundles download pod-security-admission --version v1.36.0

# Pack it into a portable archive plus checksum
kubeapt bundles export pod-security-admission --version v1.36.0 \
  --output pod-security-admission-v1.36.0.tar.gz
```

`bundles export` writes:

```text
pod-security-admission-v1.36.0.tar.gz
pod-security-admission-v1.36.0.tar.gz.sha256
```

The `.sha256` sidecar follows the standard `<hex>  <filename>` shape produced by `sha256sum`. Transfer both files together.

#### Alternative: grab the assets directly from GitHub

Bundle releases are also published on GitHub at [github.com/kolteq/kubernetes-security-policies/releases](https://github.com/kolteq/kubernetes-security-policies/releases), tagged `vap_<bundle-name>@<version>`. This is useful when the connected host does not have `kubeapt` installed (for example, a CI runner).

For pod-security-admission v1.36.0, the release page is:

```text
https://github.com/kolteq/kubernetes-security-policies/releases/tag/vap_pod-security-admission@v1.36.0
```

Each release contains the same three artifacts the `download` command consumes:

- `bundle.json` — bundle metadata and source list
- the policy source archive (`.tar.gz`)
- the matching `.sha256` sidecar

You can either place them into `~/.config/kubeapt/bundles/pod-security-admission/v1.36.0/` and run `kubeapt bundles export` from a host that does have kubeapt installed, or pack `bundle.json`, `policies.yaml`, and `bindings.yaml` into a `.tar.gz` yourself — any archive with those three files at the root is accepted by `kubeapt bundles import`.

### 2. Transfer

Copy both files to the air-gapped host through whatever medium your environment allows — removable media, internal artifact server, signed registry, etc.

### 3. On the air-gapped host: import

```bash
kubeapt bundles import --from pod-security-admission-v1.36.0.tar.gz
```

Import verifies the SHA-256 against the sidecar before touching the local cache. If the sidecar is missing, supply the expected checksum inline:

```bash
kubeapt bundles import \
  --from pod-security-admission-v1.36.0.tar.gz \
  --checksum 9a8b...c0d1
```

A bundle that's already installed is refused unless you pass `--force`:

```bash
kubeapt bundles import --from pod-security-admission-v1.36.0.tar.gz --force
```

After import the bundle lives at `~/.config/kubeapt/bundles/<name>/<version>/` exactly as if it had been downloaded, and all downstream commands (`validate`, `bundles install`, `bundles enforce`, etc.) work without further changes.

## Manual placement

If you'd rather not use an archive at all, the on-disk layout is plain files. Place them at:

```text
~/.config/kubeapt/bundles/<name>/<version>/
  bundle.json
  policies.yaml
  bindings.yaml
```

Anything found there is treated as installed. The `bundles import` command is the supported path because it verifies integrity, but the layout itself is stable.
