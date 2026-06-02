// Copyright by KolTEQ GmbH
// Contact: benjamin@kolteq.com

package policies_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/kolteq/kubeapt/internal/scanaccess"
	"github.com/kolteq/kubeapt/pkg/policies"
	"github.com/kolteq/kubeapt/pkg/types"
)

const (
	policyHighSeverityYAML = `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: test-policy
  annotations:
    security.kubeapt.io/severity: high
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE"]
        resources: ["pods"]
  validations:
    - expression: "object.metadata.name != 'forbidden'"
      message: "name must not be 'forbidden'"
`

	bindingForTestPolicyYAML = `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: test-binding
spec:
  policyName: test-policy
  validationActions: [Deny]
`

	secondBindingForTestPolicyYAML = `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: test-binding-2
spec:
  policyName: test-policy
  validationActions: [Warn]
`

	unrelatedConfigMapYAML = `apiVersion: v1
kind: ConfigMap
metadata:
  name: should-be-ignored
data:
  key: value
`
)

func TestLoad_SinglePolicy(t *testing.T) {
	fsys := fstest.MapFS{
		"policies.yaml": {Data: []byte(policyHighSeverityYAML)},
	}

	bundle, err := policies.Load(fsys, ".")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if bundle.Len() != 1 {
		t.Fatalf("Len = %d, want 1", bundle.Len())
	}

	policy, ok := bundle.Get("test-policy")
	if !ok {
		t.Fatal("Get(test-policy) = false")
	}
	if policy.ID != "test-policy" {
		t.Errorf("ID = %q, want test-policy", policy.ID)
	}
	if !bytes.Contains(policy.RawYAML, []byte("name: test-policy")) {
		t.Errorf("RawYAML missing policy name marker; got %q", policy.RawYAML)
	}
	if len(policy.BindingYAML) != 0 {
		t.Errorf("BindingYAML = %q, want empty for unbound policy", policy.BindingYAML)
	}

	parsed := policy.Parsed(scanaccess.Token{})
	if parsed == nil || parsed.VAP == nil {
		t.Fatal("Parsed handle missing VAP")
	}
	if parsed.Severity != types.SeverityHigh {
		t.Errorf("Severity = %q, want High", parsed.Severity)
	}
	if len(parsed.Bindings) != 0 {
		t.Errorf("Bindings = %d, want 0", len(parsed.Bindings))
	}
}

func TestLoad_PolicyWithBinding(t *testing.T) {
	fsys := fstest.MapFS{
		"policies.yaml": {Data: []byte(policyHighSeverityYAML)},
		"bindings.yaml": {Data: []byte(bindingForTestPolicyYAML)},
	}

	bundle, err := policies.Load(fsys, ".")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	policy, _ := bundle.Get("test-policy")
	if policy == nil {
		t.Fatal("test-policy not found")
	}
	if !bytes.Contains(policy.BindingYAML, []byte("name: test-binding")) {
		t.Errorf("BindingYAML missing binding name; got %q", policy.BindingYAML)
	}

	parsed := policy.Parsed(scanaccess.Token{})
	if len(parsed.Bindings) != 1 {
		t.Fatalf("Bindings = %d, want 1", len(parsed.Bindings))
	}
	if parsed.Bindings[0].Spec.PolicyName != "test-policy" {
		t.Errorf("binding.spec.policyName = %q, want test-policy", parsed.Bindings[0].Spec.PolicyName)
	}
}

func TestLoad_MultipleBindingsTargetingSamePolicy(t *testing.T) {
	fsys := fstest.MapFS{
		"all.yaml": {Data: []byte(policyHighSeverityYAML + "---\n" + bindingForTestPolicyYAML + "---\n" + secondBindingForTestPolicyYAML)},
	}
	bundle, err := policies.Load(fsys, ".")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	policy, _ := bundle.Get("test-policy")
	if policy == nil {
		t.Fatal("policy missing")
	}
	if !bytes.Contains(policy.BindingYAML, []byte("test-binding")) || !bytes.Contains(policy.BindingYAML, []byte("test-binding-2")) {
		t.Errorf("BindingYAML missing one of the two bindings; got %q", policy.BindingYAML)
	}
	// "---" separator must appear between the two binding documents.
	if !bytes.Contains(policy.BindingYAML, []byte("\n---\n")) {
		t.Errorf("BindingYAML missing document separator; got %q", policy.BindingYAML)
	}
	parsed := policy.Parsed(scanaccess.Token{})
	if len(parsed.Bindings) != 2 {
		t.Errorf("Bindings = %d, want 2", len(parsed.Bindings))
	}
}

func TestLoad_DuplicatePolicyIDReturnsSentinel(t *testing.T) {
	fsys := fstest.MapFS{
		"a.yaml": {Data: []byte(policyHighSeverityYAML)},
		"b.yaml": {Data: []byte(policyHighSeverityYAML)},
	}
	_, err := policies.Load(fsys, ".")
	if err == nil {
		t.Fatal("Load: want error, got nil")
	}
	if !errors.Is(err, policies.ErrDuplicatePolicy) {
		t.Errorf("err = %v, want errors.Is ErrDuplicatePolicy", err)
	}
}

func TestLoad_IgnoresOtherKinds(t *testing.T) {
	fsys := fstest.MapFS{
		"policies.yaml": {Data: []byte(policyHighSeverityYAML + "---\n" + unrelatedConfigMapYAML)},
	}
	bundle, err := policies.Load(fsys, ".")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if bundle.Len() != 1 {
		t.Errorf("Len = %d, want 1 (ConfigMap should be ignored)", bundle.Len())
	}
}

func TestLoad_SeverityNormalization(t *testing.T) {
	cases := map[string]types.Severity{
		"critical": types.SeverityCritical,
		"High":     types.SeverityHigh,
		"moderate": types.SeverityModerate,
		"LOW":      types.SeverityLow,
		"info":     types.SeverityInfo,
		"":         types.SeverityNotRated,
		"bogus":    types.SeverityNotRated,
	}
	for annotation, want := range cases {
		annotation, want := annotation, want
		t.Run(annotation, func(t *testing.T) {
			yaml := `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: p
  annotations:
    security.kubeapt.io/severity: "` + annotation + `"
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE"]
        resources: ["pods"]
  validations:
    - expression: "true"
`
			bundle, err := policies.Load(fstest.MapFS{"p.yaml": {Data: []byte(yaml)}}, ".")
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			p, _ := bundle.Get("p")
			got := p.Parsed(scanaccess.Token{}).Severity
			if got != want {
				t.Errorf("Severity(%q) = %q, want %q", annotation, got, want)
			}
		})
	}
}

func TestLoad_IterateOrder(t *testing.T) {
	// Filenames sort alphabetically, so iteration order should follow the sorted file list.
	fsys := fstest.MapFS{
		"01-first.yaml": {Data: []byte(renamePolicy(policyHighSeverityYAML, "alpha-policy"))},
		"02-second.yaml": {Data: []byte(renamePolicy(policyHighSeverityYAML, "beta-policy"))},
	}
	bundle, err := policies.Load(fsys, ".")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	var got []string
	for p := range bundle.Iterate() {
		got = append(got, p.ID)
	}
	want := []string{"alpha-policy", "beta-policy"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("Iterate order = %v, want %v", got, want)
	}
}

func TestLoadDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "policies.yaml"), []byte(policyHighSeverityYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	bundle, err := policies.LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if bundle.Len() != 1 {
		t.Errorf("Len = %d, want 1", bundle.Len())
	}
}

func renamePolicy(yaml, newName string) string {
	return string(bytes.Replace([]byte(yaml), []byte("name: test-policy"), []byte("name: "+newName), 1))
}
