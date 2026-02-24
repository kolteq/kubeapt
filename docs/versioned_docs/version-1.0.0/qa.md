---
sidebar_position: 8
title: Q&A
---

# Q&A

## I'm missing a feature, what can I do?

You can either open a pull request or issue on [Github](https://github.com/kolteq/kolteq) or [write us an e-mail](mailto:hello@kolteq.com).

## How can I get enterprise support?

For support please contact [KolTEQ](mailto:hello@kolteq.com).

## How do I choose between table and JSON output?

Use `--format table` when you want a quick human-readable report. Use `--format json` for CI pipelines or when you want to archive results and parse them later. JSON output is wrapped in a metadata envelope so you can track the command, cluster, namespaces, and timestamps alongside the results.

## Where can I browse bundles and policies?

You can find the published bundles and policies at:

https://kolteq.com/policies

## Why is a resource missing from my report?

Validation only evaluates resources that match policy scope and bindings. If you provide `--resource`, kubeapt only considers those resources. When using cluster resources, namespace filters also reduce the evaluation set.
