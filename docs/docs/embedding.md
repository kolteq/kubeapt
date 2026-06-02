---
sidebar_position: 8
title: Embedding KubeAPT
---

# Embedding KubeAPT as a Go library

KubeAPT exposes its scanner and policy-loading logic as importable Go packages under `pkg/`, so you can run scans in-process from another Go program — no subprocess, no shelling out.

The public surface is intentionally small and sealed: external consumers see only `pkg/types`, `pkg/policies`, and `pkg/scanner`. Internal CEL evaluation, manifest normalization, and matcher details remain in `internal/` and can change between releases without breaking embedders.

## Quick start

```go
package main

import (
    "context"
    "fmt"
    "os"

    "github.com/kolteq/kubeapt/pkg/policies"
    "github.com/kolteq/kubeapt/pkg/scanner"
    "github.com/kolteq/kubeapt/pkg/types"
)

func main() {
    bundle, err := policies.LoadDir("/path/to/bundle/dir")
    if err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }

    sc, err := scanner.New(bundle)
    if err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }

    manifests := []types.Manifest{
        {
            "apiVersion": "v1",
            "kind":       "Pod",
            "metadata":   map[string]any{"name": "demo", "namespace": "default"},
        },
    }

    result, err := sc.Scan(context.Background(), manifests)
    if err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }

    for _, f := range result.Findings {
        fmt.Printf("[%s] %s %s/%s — %s\n",
            f.Severity, f.Resource.Kind, f.Resource.Namespace, f.Resource.Name, f.Message)
    }
}
```

## Packages

### `pkg/types`

Shared primitives: `Manifest` (a type alias for `map[string]any`, so existing slices of parsed manifests interoperate with zero conversion), `Severity` (kubeapt's native scale, passed through verbatim — no remapping at the boundary), `ResourceRef`, `Finding`, `ScanError`, `Result`.

### `pkg/policies`

Loads a kubeapt policy bundle from any `fs.FS` (works with `os.DirFS` and `embed.FS`) and exposes it as a sealed `*Bundle`. Each `*Policy` retains its single-document `RawYAML` plus a concatenated `BindingYAML`, so you can ship the matching `kubectl apply -f` artifact alongside the findings.

```go
bundle, err := policies.Load(embeddedFS, "bundles/pod-security-admission/v1.36.0")
for policy := range bundle.Iterate() {
    fmt.Println(policy.ID, len(policy.RawYAML), len(policy.BindingYAML))
}
```

Duplicate policy IDs in a single bundle return an error wrapping `policies.ErrDuplicatePolicy`; check with `errors.Is`.

### `pkg/scanner`

Evaluates a loaded bundle against a slice of in-memory manifests.

```go
sc, _ := scanner.New(bundle)
result, _ := sc.Scan(ctx, manifests)
```

Highlights:

- **Concurrent-safe** — multiple goroutines can call `Scan` on the same `*Scanner` at once.
- **Context-aware** — `Scan` respects `ctx.Done()` between iterations and returns the context error on cancellation.
- **Non-mutating** — the input manifest slice is deep-copied before normalization; your data is never modified.
- **Detect-everything by default** — bundle bindings are ignored; an implicit "match anything the policy targets" binding is synthesized so policies fire against every matching resource. Opt back into the bundle's bindings with `scanner.WithRespectBindings()`.
- **Soft failures** — per-(policy, resource) evaluation errors (e.g. malformed CEL on one rule) land in `Result.ScanErrors`. `Scan` only returns an error for catastrophic failures like context cancellation.

## Bundling policies with your binary

Combine `embed.FS` with `policies.Load` to ship bundles inside your own binary — no on-host install needed.

```go
import "embed"

//go:embed bundles/pod-security-admission/v1.36.0/*.yaml
var policyFS embed.FS

bundle, err := policies.Load(policyFS, "bundles/pod-security-admission/v1.36.0")
```

This is the recommended pattern for tools that need to run on machines that never had `kubeapt` installed.
