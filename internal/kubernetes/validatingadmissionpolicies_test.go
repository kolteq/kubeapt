package kubernetes

import (
    "os"
    "path/filepath"
    "strings"
    "testing"
)

func TestDecodeValidatingAdmissionPolicies(t *testing.T) {
    yaml := `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: test
spec: {}
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: skip
`

    policies, err := decodeValidatingAdmissionPolicies(strings.NewReader(yaml))
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if len(policies) != 1 || policies[0].Name != "test" {
        t.Fatalf("unexpected policies: %v", policies)
    }
}

func TestDecodeValidatingAdmissionPolicyBindings(t *testing.T) {
    yaml := `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: binding
spec:
  policyName: test
`
    bindings, err := decodeValidatingAdmissionPolicyBindings(strings.NewReader(yaml))
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if len(bindings) != 1 || bindings[0].Name != "binding" {
        t.Fatalf("unexpected bindings: %v", bindings)
    }
}

func TestLoadValidatingAdmissionPoliciesFromPath(t *testing.T) {
    dir := t.TempDir()
    validPath := filepath.Join(dir, "valid.yaml")
    invalidPath := filepath.Join(dir, "invalid.yaml")

    valid := `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: test
spec: {}
`
    if err := os.WriteFile(validPath, []byte(valid), 0o644); err != nil {
        t.Fatalf("failed to write valid file: %v", err)
    }
    if err := os.WriteFile(invalidPath, []byte("not: [yaml"), 0o644); err != nil {
        t.Fatalf("failed to write invalid file: %v", err)
    }

    policies, err := loadValidatingAdmissionPoliciesFromPath(dir, nil)
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if len(policies) != 1 {
        t.Fatalf("expected 1 policy, got %d", len(policies))
    }
}

func TestCountManifestFiles(t *testing.T) {
    dir := t.TempDir()
    count, err := CountManifestFiles(dir)
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if count != 1 {
        t.Fatalf("expected count 1 for empty dir, got %d", count)
    }
}
