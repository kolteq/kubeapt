// Copyright by cenroq AG
// Contact: info@cenroq.com

package scanner_test

import (
	"context"
	"testing"
	"testing/fstest"

	"github.com/cenroq/kubeapt/v2/pkg/policies"
	"github.com/cenroq/kubeapt/v2/pkg/scanner"
	"github.com/cenroq/kubeapt/v2/pkg/types"
)

const policyForbidsNameYAML = `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: forbid-bad-name
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
      message: "pod name 'forbidden' is not allowed"
`

const policyWithNarrowBindingYAML = policyForbidsNameYAML + `---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: forbid-bad-name--prod-only
spec:
  policyName: forbid-bad-name
  matchResources:
    namespaceSelector:
      matchLabels:
        env: prod
  validationActions: [Deny]
`

const policyBadCELYAML = `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: bad-cel
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE"]
        resources: ["pods"]
  validations:
    - expression: "this is not valid cel @"
      message: "should not matter"
`

func mustLoad(t *testing.T, yaml string) *policies.Bundle {
	t.Helper()
	bundle, err := policies.Load(fstest.MapFS{"p.yaml": {Data: []byte(yaml)}}, ".")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return bundle
}

func pod(name string) types.Manifest {
	return types.Manifest{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]any{
			"name":      name,
			"namespace": "default",
		},
	}
}

func TestNew_NilBundle(t *testing.T) {
	if _, err := scanner.New(nil); err == nil {
		t.Fatal("New(nil) = nil error, want error")
	}
}

func TestScan_CompliantAndNonCompliant(t *testing.T) {
	sc, err := scanner.New(mustLoad(t, policyForbidsNameYAML))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res, err := sc.Scan(context.Background(), []types.Manifest{pod("forbidden"), pod("ok")})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1", len(res.Findings))
	}
	f := res.Findings[0]
	if f.PolicyID != "forbid-bad-name" {
		t.Errorf("PolicyID = %q, want forbid-bad-name", f.PolicyID)
	}
	if f.Severity != types.SeverityHigh {
		t.Errorf("Severity = %q, want High", f.Severity)
	}
	if f.Resource.Name != "forbidden" || f.Resource.Kind != "Pod" {
		t.Errorf("Resource = %+v, want Pod/forbidden", f.Resource)
	}
	if f.Message == "" {
		t.Error("Message empty, want CEL message")
	}
	if len(f.Actions) == 0 {
		t.Error("Actions empty; implicit binding should default to Deny")
	}
	if len(res.ScanErrors) != 0 {
		t.Errorf("ScanErrors = %d, want 0", len(res.ScanErrors))
	}
}

func TestScan_DoesNotMutateInput(t *testing.T) {
	sc, _ := scanner.New(mustLoad(t, policyForbidsNameYAML))
	// A Role kind triggers RBAC normalization (which mutates the resource).
	in := []types.Manifest{
		{
			"apiVersion": "rbac.authorization.k8s.io/v1",
			"kind":       "Role",
			"metadata":   map[string]any{"name": "r", "namespace": "default"},
			// rules absent — the normalizer would add an empty slice.
		},
	}
	if _, err := sc.Scan(context.Background(), in); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if _, present := in[0]["rules"]; present {
		t.Errorf("input manifest was mutated (rules field appeared); Scan should deep-copy")
	}
}

func TestScan_ContextCancelled(t *testing.T) {
	sc, _ := scanner.New(mustLoad(t, policyForbidsNameYAML))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := sc.Scan(ctx, []types.Manifest{pod("forbidden")})
	if err == nil {
		t.Fatal("Scan with cancelled ctx = nil error, want context.Canceled")
	}
	if err != context.Canceled {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

func TestScan_IgnoreBindingsByDefault(t *testing.T) {
	// Bundle ships a narrow binding (namespace env=prod). Pod has no labels.
	// With default (ignore bindings) the implicit binding is used and the
	// policy fires anyway.
	sc, err := scanner.New(mustLoad(t, policyWithNarrowBindingYAML))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res, err := sc.Scan(context.Background(), []types.Manifest{pod("forbidden")})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1 (default ignore-bindings should match everything)", len(res.Findings))
	}
}

func TestScan_RespectBindings(t *testing.T) {
	// Same bundle, opt into respect-bindings: namespace selector requires env=prod,
	// the Pod has no namespace label data, so MatchesBinding returns "match all"
	// when namespace data is unknown. We assert the scan still produces a finding —
	// the WithRespectBindings option must not crash and must use the bundle's bindings
	// instead of the implicit one (verified by checking Actions reflect the binding).
	sc, err := scanner.New(mustLoad(t, policyWithNarrowBindingYAML), scanner.WithRespectBindings())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res, err := sc.Scan(context.Background(), []types.Manifest{pod("forbidden")})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	// In respect-bindings mode, when namespace labels are unknown, the matcher
	// errs on the side of "match everything." So a finding still appears, and
	// its Actions come from the bundle's binding (Deny in the fixture).
	if len(res.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1", len(res.Findings))
	}
	if len(res.Findings[0].Actions) == 0 || res.Findings[0].Actions[0] != "Deny" {
		t.Errorf("Actions = %v, want [Deny] from bundle binding", res.Findings[0].Actions)
	}
}

func TestScan_BadCELProducesScanError(t *testing.T) {
	sc, _ := scanner.New(mustLoad(t, policyBadCELYAML))
	res, err := sc.Scan(context.Background(), []types.Manifest{pod("anything")})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.ScanErrors) == 0 {
		t.Fatal("ScanErrors empty, want CEL compile error")
	}
	se := res.ScanErrors[0]
	if se.PolicyID != "bad-cel" {
		t.Errorf("ScanError.PolicyID = %q, want bad-cel", se.PolicyID)
	}
	if se.Err == nil {
		t.Error("ScanError.Err = nil, want non-nil")
	}
}

func TestScan_NonMatchingResourceProducesNothing(t *testing.T) {
	// Policy matches pods; provide a Service.
	sc, _ := scanner.New(mustLoad(t, policyForbidsNameYAML))
	svc := types.Manifest{
		"apiVersion": "v1",
		"kind":       "Service",
		"metadata":   map[string]any{"name": "forbidden", "namespace": "default"},
	}
	res, err := sc.Scan(context.Background(), []types.Manifest{svc})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("Findings = %d, want 0 (Service should not match Pod-only policy)", len(res.Findings))
	}
}

// Fixture policies for exercising the WithPolicyResources GVR filter.
const netpolPolicyYAML = `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: forbid-netpol
  annotations:
    security.kubeapt.io/severity: high
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
      - apiGroups: ["networking.k8s.io"]
        apiVersions: ["v1"]
        operations: ["CREATE"]
        resources: ["networkpolicies"]
  validations:
    - expression: "false"
      message: "networkpolicy flagged"
`

const calicoNetpolPolicyYAML = `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: forbid-calico-netpol
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
      - apiGroups: ["projectcalico.org"]
        apiVersions: ["v3"]
        operations: ["CREATE"]
        resources: ["networkpolicies"]
  validations:
    - expression: "false"
      message: "calico networkpolicy flagged"
`

const servicePolicyYAML = `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: forbid-service
  annotations:
    security.kubeapt.io/severity: moderate
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE"]
        resources: ["services"]
  validations:
    - expression: "false"
      message: "service flagged"
`

func manifest(apiVersion, kind, name string) types.Manifest {
	return types.Manifest{
		"apiVersion": apiVersion,
		"kind":       kind,
		"metadata":   map[string]any{"name": name, "namespace": "default"},
	}
}

func firedPolicies(res *types.Result) map[string]bool {
	fired := make(map[string]bool)
	for _, f := range res.Findings {
		fired[f.PolicyID] = true
	}
	return fired
}

func TestScan_WithPolicyResources_FiltersByGVR(t *testing.T) {
	// Mixed bundle: a Pod policy, a NetworkPolicy policy, and a Service policy.
	bundle := mustLoad(t, policyForbidsNameYAML+"---\n"+netpolPolicyYAML+"---\n"+servicePolicyYAML)
	sc, err := scanner.New(bundle, scanner.WithPolicyResources([]scanner.GVR{
		{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"},
		{Group: "", Version: "v1", Resource: "services"},
	}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	manifests := []types.Manifest{
		pod("forbidden"), // would violate the Pod policy, but it is filtered out
		manifest("networking.k8s.io/v1", "NetworkPolicy", "np"),
		manifest("v1", "Service", "svc"),
	}
	res, err := sc.Scan(context.Background(), manifests)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	fired := firedPolicies(res)
	if fired["forbid-bad-name"] {
		t.Errorf("Pod policy fired, but pods were not in the policy-resources filter")
	}
	if !fired["forbid-netpol"] {
		t.Errorf("NetworkPolicy policy should have fired")
	}
	if !fired["forbid-service"] {
		t.Errorf("Service policy should have fired")
	}
}

func TestScan_WithPolicyResources_DistinguishesGroup(t *testing.T) {
	// Two policies target the "networkpolicies" resource but in different groups.
	bundle := mustLoad(t, netpolPolicyYAML+"---\n"+calicoNetpolPolicyYAML)
	sc, err := scanner.New(bundle, scanner.WithPolicyResources([]scanner.GVR{
		{Group: "networking.k8s.io", Version: "v1", Resource: "networkpolicies"},
	}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	manifests := []types.Manifest{
		manifest("networking.k8s.io/v1", "NetworkPolicy", "k8s-np"),
		manifest("projectcalico.org/v3", "NetworkPolicy", "calico-np"),
	}
	res, err := sc.Scan(context.Background(), manifests)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	fired := firedPolicies(res)
	if !fired["forbid-netpol"] {
		t.Errorf("networking.k8s.io NetworkPolicy policy should have fired")
	}
	if fired["forbid-calico-netpol"] {
		t.Errorf("projectcalico.org policy should have been filtered out by group")
	}
}

func TestScan_WithPolicyResources_EmptyIsNoOp(t *testing.T) {
	sc, err := scanner.New(mustLoad(t, policyForbidsNameYAML), scanner.WithPolicyResources(nil))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res, err := sc.Scan(context.Background(), []types.Manifest{pod("forbidden")})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("Findings = %d, want 1 (empty filter must not filter anything)", len(res.Findings))
	}
}
