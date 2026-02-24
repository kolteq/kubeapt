---
sidebar_position: 1
title: Introduction
---

# KubeAPT

KubeAPT is a CLI for validating Kubernetes admission hardening. It evaluates ValidatingAdmissionPolicies (VAP) and bindings, checks Pod Security Admission (PSA) posture, and scans clusters for admission safeguards. You can point it at local manifests or a live cluster and produce table or JSON reports for audits and CI.

## What it does

KubeAPT validates VAP policies and bindings against Kubernetes resources with CEL evaluation, evaluates PSA label posture and compliance using the `pod-security-admission` bundle, scans clusters for built-in admission plugins, webhook configurations, and common controllers such as Kyverno or OPA Gatekeeper, and manages policy bundles plus standalone policies for download, inspection, installation, and removal.

## Where it fits

- CI/CD: use `validate --pipeline` to fail builds on violations.
- Security reviews: generate human readable tables or machine readable JSON reports.
- Day-2 operations: scan clusters for admission hardening and stay current on policy updates.

## Output in brief

The `validate` command supports `--format table|json` and `--report summary|all`. The `scan` command prints step-by-step tables and summaries for the connected cluster. The `bundles` and `policies` commands can output tables and optionally JSON or YAML for the resources they manage.
