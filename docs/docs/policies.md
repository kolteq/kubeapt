---
sidebar_position: 6
title: Policies
---

# Policies

The `policies` command group manages standalone ValidatingAdmissionPolicies that are distributed in versioned releases.

## What you can do

- `policies list`: list available policy versions.
- `policies download`: download a policy version to local storage.
- `policies show`: inspect a policy or list policy summaries.
- `policies install` / `policies uninstall`: apply or remove a policy in a cluster.
- `policies remove`: delete a downloaded policy version from local storage.

## Output

### `policies list`

Table output includes:

- `Latest`: latest version in the remote index.
- `Versions`: available versions.
- `Downloaded`: marks downloaded versions with `x`.

### `policies show`

When a policy name is provided, the default table view prints the policy annotations:

- `displayName`
- `description`
- `resource`
- `severity`
- `remediation`
- `product`

When no policy name is provided, kubeapt prints a summary table with:

- `Name`, `Display Name`, `Description`, `Product`

`--format yaml|json` prints raw policy resources instead of tables.

## Local storage

Downloaded policy versions are stored under:

- `~/.config/kubeapt/policies/<version>`

## Where to find policies

Browse available policies and versions at:

https://kolteq.com/policies
