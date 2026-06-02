---
title: kubeapt scan
---

# kubeapt scan

Scan the connected cluster for admission safeguards, including namespace PSA posture, built-in admission plugins, and registered webhooks. Run it against the current kubeconfig context.

`scan` does not reach outside the cluster — there are no outbound HTTP calls, so it is safe to run on air-gapped or restricted-network hosts.

## Usage

```bash
kubeapt scan [flags]
```

## Subcommands

None.

## Arguments

| Flag | Type | Default | Description |
| --- | --- | --- | --- |
| --log-level | string | info | Set logging level (debug, info, warn, error) |
| --kubeconfig | string |  | Path to kubeconfig file |
| -h, --help | bool | false | Show help for this command |
