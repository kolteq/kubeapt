---
sidebar_position: 5
title: Bundles
---

# Bundles

Bundles are curated sets of ValidatingAdmissionPolicies and bindings. kubeapt can list, download, show, install, uninstall, and remove bundles.

## What you can do

- `bundles list`: see available bundle names and versions.
- `bundles download`: fetch a bundle into local storage.
- `bundles show`: review a bundle's policies and bindings.
- `bundles install` / `bundles uninstall`: apply or remove bundle resources in a cluster.
- `bundles remove`: delete a downloaded bundle version from local storage.
- `bundles audit|enforce|warn`: set bundle labels on namespaces.

## Output

### `bundles list`

Table output includes:

- `Bundle`: bundle name.
- `Origin`: `remote` if the bundle exists in the published index, `local-only` if it is only present on your machine.
- `Latest`: latest version in the remote index.
- `Versions`: available versions.
- `Downloaded`: marks downloaded versions with `x`.
- `Installed`: marks installed versions with `x`.

### `bundles show`

Default table output lists policies, bindings, and the binding mode:

- `Policy`: policy name.
- `Bindings`: binding names (one per line).
- `Mode`: validation actions (for example, `Deny` or `Deny,Warn`).

`--format yaml|json` prints the raw bundle resources instead of the table.

### `bundles install` and `bundles uninstall`

- `--dry-run` previews changes without applying them.
- `--overwrite` can replace existing bindings when installing.

## Namespace labels

Bundles can define labels used for PSA and other admission posture controls. The label commands set the bundle-specific label key on namespaces:

- `bundles audit <bundle>`
- `bundles enforce <bundle>`
- `bundles warn <bundle>`

For the `pod-security-admission` bundle, you must pass `--psa-level baseline|restricted` when setting labels.

## Local storage

Downloaded bundles are stored under:

- `~/.config/kubeapt/bundles/<bundle>/<version>`

## Custom bundles

You can add your own bundle without publishing it to the remote index.

1) Create the folder: `~/.config/kubeapt/bundles/<name>/<version>/`
2) Add at least:
   - `policies.yaml` — ValidatingAdmissionPolicy objects
   - `bindings.yaml` — ValidatingAdmissionPolicyBinding objects (required by commands even if empty; use an empty file if you have no bindings)
3) (Optional but needed for namespace labeling commands) Add `bundle.json` with label keys:

```json
{
  "name": "<name>",
  "version": "<version>",
  "labels": {
    "audit": "example.com/audit",
    "enforce": "example.com/enforce",
    "warn": "example.com/warn"
  }
}
```

4) To have installations show up under “Installed”, include on each binding:
   - `metadata.labels.bundle: <name>`
   - `metadata.annotations.policy-bundle.kolteq.com/version: <version>`

After the files are in place, `kubeapt bundles list` will show the bundle with `Origin` = `local-only`, and you can `show`, `install`, `enforce|audit|warn`, and `validate` against it.

## Where to find bundles

Browse available bundles and versions at:

https://kolteq.com/policies
