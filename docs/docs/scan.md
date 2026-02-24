---
sidebar_position: 3
title: Scan
---

# Scan

`kubeapt scan` inspects a live cluster for admission safeguards and prints a multi-step report. It is designed as a quick posture check before deeper validation work.

## What scan checks

- Pod Security Admission (PSA) labels and PSA compliance using the `pod-security-admission` bundle when available.
- ValidatingAdmissionPolicies in the cluster.
- Third-party admission controllers (Kyverno and OPA Gatekeeper).
- Built-in admission plugins configured on the kube-apiserver.
- Validating and mutating webhook configurations.
- Updates for downloaded bundles and policies.

## Output overview

Scan runs in four stages and prints a mix of tables and short summaries:

1) PSA overview
- Table title: `PSA Namespace Levels`
- Columns: `Namespace`, `Enforce`, `Audit`, `Warn`, `Compliant`, `Non-compliant`
- If the PSA bundle is downloaded, compliance counts are calculated from pods evaluated against the bundle.

2) Built-in admission plugins
- Lists enabled plugins and, when available, disabled plugins.
- If kube-apiserver flags cannot be read, scan reports that it could not determine the plugins.

3) Webhook configurations
- Tables for ValidatingWebhookConfigurations and MutatingWebhookConfigurations.
- Columns: `Config`, `Webhook`, `Target` (service reference or URL).

4) Bundle and policy updates
- Reports whether local bundles or policies are behind the latest remote index.
- Suggests the download command when updates are available.

## Next steps

For PSA detail, follow the hint printed by scan:

```bash
kubeapt validate --bundle pod-security-admission --psa-level <baseline|restricted> --all-namespaces --report all
```
