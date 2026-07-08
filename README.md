<p align="center">
  Kubernetes Admission Policy Toolkit
</p>

<p align="center">
  <a href="https://img.shields.io/badge/license-Apache--2.0-blue.svg">License: Apache-2.0</a>
  <a href="https://img.shields.io/badge/go-1.25.0-00ADD8?logo=go">Go 1.25.0</a>
</p>

KubeAPT is a CLI for validating Kubernetes admission hardening. It evaluates ValidatingAdmissionPolicies (VAP) and bindings, checks Pod Security Admission (PSA) posture, and scans clusters for admission safeguards. It also manages policy bundles and standalone policies so you can download, inspect, and apply curated rulesets. Official bundles and policies are published at [https://cenroq.com/policies](https://cenroq.com/policies).

Documentation lives at [https://kubeapt.io](https://kubeapt.io).

## Installation

Install the latest version of kubeapt using `go install`...

```bash
go install github.com/cenroq/kubeapt/cmd/kubeapt@latest
```

...or download a pre-built binary from the [releases page](https://github.com/cenroq/kubeapt/releases).

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=cenroq/kubeapt&type=date&legend=top-left)](https://www.star-history.com/#cenroq/kubeapt&type=date&legend=top-left)
