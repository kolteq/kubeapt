---
sidebar_position: 2
title: Install
---

# Install

## Requirements

- Go 1.25+ to build from source.
- Cluster access (kubeconfig or in-cluster config) for `scan`, `validate`, and install/uninstall commands.

## Go install

```bash
go install github.com/kolteq/kubeapt@latest
```

## Run from source

```bash
go run ./cmd/kubeapt <command>
```

## Docker

```bash
docker build -t kubeapt .
docker run -it --rm --name kubeapt --net=host \
  -v <PATH_TO_KUBECONFIG>:<PATH_TO_KUBECONFIG> \
  kubeapt --kubeconfig <PATH_TO_KUBECONFIG> <command>
```

## Kubeconfig and cluster access

kubeapt uses in-cluster config when available. Otherwise it loads the default kubeconfig (usually `~/.kube/config`). Use `--kubeconfig` to point to a different file.

## Local cache

Downloaded bundles and policy versions are stored under the kubeapt config directory:

- Linux: `~/.config/kubeapt`
- Windows: `%USERPROFILE%\.config\kubeapt` (for example `C:\Users\you\.config\kubeapt`)

Paths under this directory include:

- `<config-dir>/bundles/<bundle>/<version>`
- `<config-dir>/policies/<version>`
