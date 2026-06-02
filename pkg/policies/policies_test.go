// Copyright by KolTEQ GmbH
// Contact: benjamin@kolteq.com

package policies_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
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

const policyWithAllAnnotationsYAML = `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: annotated-policy
  annotations:
    security.kubeapt.io/displayName: Privileged Containers Not Allowed
    security.kubeapt.io/description: Containers must not run with privileged=true.
    security.kubeapt.io/category: Pod Security
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

const policyWithKyvernoAnnotationsYAML = `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: kyverno-annotated-policy
  annotations:
    policies.kyverno.io/title: Block hostPath Volumes
    policies.kyverno.io/description: hostPath volumes leak host filesystem state.
    policies.kyverno.io/category: Pod Security
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

const policyWithNoAnnotationsYAML = `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: bare-policy
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

func TestPolicyMetadata_KubeaptAnnotationsPreferred(t *testing.T) {
	bundle, err := policies.Load(fstest.MapFS{"p.yaml": {Data: []byte(policyWithAllAnnotationsYAML)}}, ".")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	p, _ := bundle.Get("annotated-policy")
	if got := p.Title(); got != "Privileged Containers Not Allowed" {
		t.Errorf("Title() = %q, want kubeapt displayName", got)
	}
	if got := p.Description(); got != "Containers must not run with privileged=true." {
		t.Errorf("Description() = %q, want kubeapt description", got)
	}
	if got := p.Category(); got != "Pod Security" {
		t.Errorf("Category() = %q, want kubeapt category", got)
	}
}

func TestPolicyMetadata_KyvernoFallback(t *testing.T) {
	bundle, err := policies.Load(fstest.MapFS{"p.yaml": {Data: []byte(policyWithKyvernoAnnotationsYAML)}}, ".")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	p, _ := bundle.Get("kyverno-annotated-policy")
	if got := p.Title(); got != "Block hostPath Volumes" {
		t.Errorf("Title() = %q, want kyverno title fallback", got)
	}
	if got := p.Description(); got != "hostPath volumes leak host filesystem state." {
		t.Errorf("Description() = %q, want kyverno description fallback", got)
	}
	if got := p.Category(); got != "Pod Security" {
		t.Errorf("Category() = %q, want kyverno category fallback", got)
	}
}

func TestPolicyMetadata_FallbacksWhenAbsent(t *testing.T) {
	bundle, err := policies.Load(fstest.MapFS{"p.yaml": {Data: []byte(policyWithNoAnnotationsYAML)}}, ".")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	p, _ := bundle.Get("bare-policy")
	if got := p.Title(); got != "bare-policy" {
		t.Errorf("Title() = %q, want fallback to ID", got)
	}
	if got := p.Description(); got != "" {
		t.Errorf("Description() = %q, want empty string when unset", got)
	}
	if got := p.Category(); got != "" {
		t.Errorf("Category() = %q, want empty string when unset", got)
	}
}

func TestBundleMetadata_FromBundleJSON(t *testing.T) {
	fsys := fstest.MapFS{
		"policies.yaml": {Data: []byte(policyHighSeverityYAML)},
		"bundle.json": {Data: []byte(`{
  "name": "pod-security-admission",
  "description": "Pod Security Admission policies.",
  "version": "v1.36.0"
}`)},
	}
	bundle, err := policies.Load(fsys, ".")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := bundle.Name(); got != "pod-security-admission" {
		t.Errorf("Name() = %q", got)
	}
	if got := bundle.Description(); got != "Pod Security Admission policies." {
		t.Errorf("Description() = %q", got)
	}
	if got := bundle.Version(); got != "v1.36.0" {
		t.Errorf("Version() = %q", got)
	}
}

func TestBundleMetadata_EmptyWhenBundleJSONAbsent(t *testing.T) {
	bundle, err := policies.Load(fstest.MapFS{"p.yaml": {Data: []byte(policyHighSeverityYAML)}}, ".")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := bundle.Name(); got != "" {
		t.Errorf("Name() = %q, want empty without bundle.json", got)
	}
	if got := bundle.Description(); got != "" {
		t.Errorf("Description() = %q, want empty without bundle.json", got)
	}
	if got := bundle.Version(); got != "" {
		t.Errorf("Version() = %q, want empty without bundle.json", got)
	}
}

func TestBundleMetadata_MalformedJSONIsError(t *testing.T) {
	fsys := fstest.MapFS{
		"policies.yaml": {Data: []byte(policyHighSeverityYAML)},
		"bundle.json":   {Data: []byte(`{"name": "broken`)},
	}
	if _, err := policies.Load(fsys, "."); err == nil {
		t.Fatal("Load on malformed bundle.json = nil, want error")
	}
}

func TestBundleLabelsAndSources_Populated(t *testing.T) {
	fsys := fstest.MapFS{
		"policies.yaml": {Data: []byte(policyHighSeverityYAML)},
		"bundle.json": {Data: []byte(`{
  "name": "pod-security-admission",
  "version": "v1.36.0",
  "labels": {
    "audit":   "pss.security.kolteq.com/audit",
    "enforce": "pss.security.kolteq.com/enforce",
    "warn":    "pss.security.kolteq.com/warn"
  },
  "sources": [
    "https://github.com/kolteq/kubernetes-security-policies/releases/download/vap_pod-security-admission@v1.36.0/pod-security-admission.tar.gz"
  ]
}`)},
	}
	bundle, err := policies.Load(fsys, ".")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	labels := bundle.Labels()
	if labels["audit"] != "pss.security.kolteq.com/audit" || labels["enforce"] != "pss.security.kolteq.com/enforce" || labels["warn"] != "pss.security.kolteq.com/warn" {
		t.Errorf("Labels() = %v, want audit/enforce/warn keys", labels)
	}
	sources := bundle.Sources()
	if len(sources) != 1 || !strings.HasSuffix(sources[0], "pod-security-admission.tar.gz") {
		t.Errorf("Sources() = %v, want one .tar.gz URL", sources)
	}
}

func TestBundleLabelsAndSources_NilWhenAbsent(t *testing.T) {
	bundle, err := policies.Load(fstest.MapFS{"p.yaml": {Data: []byte(policyHighSeverityYAML)}}, ".")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := bundle.Labels(); got != nil {
		t.Errorf("Labels() = %v, want nil without bundle.json", got)
	}
	if got := bundle.Sources(); got != nil {
		t.Errorf("Sources() = %v, want nil without bundle.json", got)
	}
}

func TestBundleLabelsAndSources_DefensiveCopy(t *testing.T) {
	fsys := fstest.MapFS{
		"policies.yaml": {Data: []byte(policyHighSeverityYAML)},
		"bundle.json": {Data: []byte(`{
  "name": "b",
  "labels": {"audit": "k1"},
  "sources": ["s1"]
}`)},
	}
	bundle, err := policies.Load(fsys, ".")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// Mutate the returned copies; subsequent reads must reflect the original.
	bundle.Labels()["audit"] = "tampered"
	bundle.Sources()[0] = "tampered"
	if got := bundle.Labels()["audit"]; got != "k1" {
		t.Errorf("Labels() mutation leaked back: got %q, want k1", got)
	}
	if got := bundle.Sources()[0]; got != "s1" {
		t.Errorf("Sources() mutation leaked back: got %q, want s1", got)
	}
}
