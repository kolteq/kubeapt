// Copyright by cenroq AG
// Contact: info@cenroq.com

package kyverno_test

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"

	"github.com/cenroq/kubeapt/v2/pkg/kyverno"
)

const validatingPolicyYAML = `apiVersion: policies.kyverno.io/v1
kind: ValidatingPolicy
metadata:
  name: check-labels
spec:
  validationActions:
    - Deny
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["pods"]
  validations:
    - expression: "'environment' in object.metadata.labels"
      message: label 'environment' is required
`

const namespacedValidatingPolicyYAML = `apiVersion: policies.kyverno.io/v1
kind: NamespacedValidatingPolicy
metadata:
  name: check-replicas
  namespace: production
spec:
  matchConstraints:
    resourceRules:
      - apiGroups: ["apps"]
        apiVersions: ["v1"]
        operations: ["CREATE"]
        resources: ["deployments"]
  validations:
    - expression: "object.spec.replicas >= 2"
`

const unrelatedConfigMapYAML = `apiVersion: v1
kind: ConfigMap
metadata:
  name: unrelated
`

const legacyClusterPolicyYAML = `apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-labels
spec:
  rules:
    - name: check-team
      match:
        any:
          - resources:
              kinds: [Pod]
`

func TestDecodeValidatingPolicies(t *testing.T) {
	stream := strings.Join([]string{
		validatingPolicyYAML,
		unrelatedConfigMapYAML,
		"\n",
		namespacedValidatingPolicyYAML,
	}, "---\n")

	got, err := kyverno.DecodeValidatingPolicies(strings.NewReader(stream))
	if err != nil {
		t.Fatalf("DecodeValidatingPolicies: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d policies, want 2", len(got))
	}

	if got[0].Kind != kyverno.KindValidatingPolicy {
		t.Errorf("got kind %s, want %s", got[0].Kind, kyverno.KindValidatingPolicy)
	}
	if got[0].APIVersion != kyverno.APIVersionV1 {
		t.Errorf("got apiVersion %s, want %s", got[0].APIVersion, kyverno.APIVersionV1)
	}
	if got[0].Name != "check-labels" {
		t.Errorf("got name %s, want check-labels", got[0].Name)
	}
	if got[0].Namespaced() {
		t.Error("ValidatingPolicy reported as namespaced")
	}
	if len(got[0].Spec.ValidationActions) != 1 || got[0].Spec.ValidationActions[0] != admissionregistrationv1.Deny {
		t.Errorf("got validationActions %v, want [Deny]", got[0].Spec.ValidationActions)
	}

	if !got[1].Namespaced() {
		t.Error("NamespacedValidatingPolicy not reported as namespaced")
	}
	if got[1].Namespace != "production" {
		t.Errorf("got namespace %s, want production", got[1].Namespace)
	}
}

func TestDecodeConditionsAlias(t *testing.T) {
	const legacySpelling = `apiVersion: policies.kyverno.io/v1alpha1
kind: ValidatingPolicy
metadata:
  name: aliased
spec:
  conditions:
    - name: only-prod
      expression: "object.metadata.namespace == 'prod'"
`
	const bothSpellings = `apiVersion: policies.kyverno.io/v1alpha1
kind: ValidatingPolicy
metadata:
  name: both
spec:
  conditions:
    - name: legacy
      expression: "false"
  matchConditions:
    - name: current
      expression: "true"
`

	got, err := kyverno.DecodeValidatingPolicies(strings.NewReader(legacySpelling))
	if err != nil {
		t.Fatalf("DecodeValidatingPolicies: %v", err)
	}
	if len(got[0].Spec.MatchConditions) != 1 || got[0].Spec.MatchConditions[0].Name != "only-prod" {
		t.Fatalf("conditions did not populate MatchConditions: %+v", got[0].Spec.MatchConditions)
	}

	got, err = kyverno.DecodeValidatingPolicies(strings.NewReader(bothSpellings))
	if err != nil {
		t.Fatalf("DecodeValidatingPolicies: %v", err)
	}
	if len(got[0].Spec.MatchConditions) != 1 || got[0].Spec.MatchConditions[0].Name != "current" {
		t.Errorf("matchConditions did not win over conditions: %+v", got[0].Spec.MatchConditions)
	}

	got, err = kyverno.DecodeValidatingPolicies(strings.NewReader(validatingPolicyYAML))
	if err != nil {
		t.Fatalf("DecodeValidatingPolicies: %v", err)
	}
	if got[0].Spec.MatchConditions != nil {
		t.Errorf("got matchConditions %v, want nil", got[0].Spec.MatchConditions)
	}
}

func TestDecodeRejectsLegacyPolicies(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		want string
	}{
		{name: "ClusterPolicy", doc: legacyClusterPolicyYAML, want: "ClusterPolicy require-labels"},
		{
			name: "Policy",
			doc: `apiVersion: kyverno.io/v1
kind: Policy
metadata:
  name: namespaced-legacy
  namespace: prod
`,
			want: "Policy namespaced-legacy",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := kyverno.DecodeValidatingPolicies(strings.NewReader(tc.doc))
			if !errors.Is(err, kyverno.ErrLegacyPolicy) {
				t.Fatalf("got err %v, want ErrLegacyPolicy", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not name %q", err.Error(), tc.want)
			}
		})
	}
}

func TestDecodeSkipsForeignGroup(t *testing.T) {
	const foreign = `apiVersion: example.com/v1
kind: ValidatingPolicy
metadata:
  name: not-kyverno
spec: {}
`
	got, err := kyverno.DecodeValidatingPolicies(strings.NewReader(foreign))
	if err != nil {
		t.Fatalf("DecodeValidatingPolicies: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d policies, want 0", len(got))
	}
}

func TestDecodeUnknownVersionIsNotAnError(t *testing.T) {
	const future = `apiVersion: policies.kyverno.io/v1beta1
kind: ValidatingPolicy
metadata:
  name: from-the-future
spec:
  validations:
    - expression: "true"
`
	got, err := kyverno.DecodeValidatingPolicies(strings.NewReader(future))
	if err != nil {
		t.Fatalf("DecodeValidatingPolicies: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d policies, want 1", len(got))
	}
	if kyverno.IsKnownAPIVersion(got[0].APIVersion) {
		t.Errorf("IsKnownAPIVersion(%s) = true, want false", got[0].APIVersion)
	}
	if len(got[0].Spec.Validations) != 1 {
		t.Errorf("got %d validations, want 1", len(got[0].Spec.Validations))
	}
}

func TestDecodeV1Alpha1ParamFields(t *testing.T) {
	const withParams = `apiVersion: policies.kyverno.io/v1alpha1
kind: ValidatingPolicy
metadata:
  name: parameterized
spec:
  paramKind:
    apiVersion: rules.example.com/v1
    kind: ReplicaLimit
  paramRef:
    name: limits
    parameterNotFoundAction: Deny
`
	got, err := kyverno.DecodeValidatingPolicies(strings.NewReader(withParams))
	if err != nil {
		t.Fatalf("DecodeValidatingPolicies: %v", err)
	}
	if got[0].Spec.ParamKind == nil || got[0].Spec.ParamKind.Kind != "ReplicaLimit" {
		t.Errorf("got paramKind %+v, want kind ReplicaLimit", got[0].Spec.ParamKind)
	}
	if got[0].Spec.ParamRef == nil || got[0].Spec.ParamRef.Name != "limits" {
		t.Errorf("got paramRef %+v, want name limits", got[0].Spec.ParamRef)
	}
}

func TestMarshalRoundTrip(t *testing.T) {
	original, err := kyverno.DecodeValidatingPolicies(strings.NewReader(validatingPolicyYAML))
	if err != nil {
		t.Fatalf("DecodeValidatingPolicies: %v", err)
	}

	data, err := kyverno.Marshal(original[0])
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	again, err := kyverno.DecodeValidatingPolicies(strings.NewReader(string(data)))
	if err != nil {
		t.Fatalf("DecodeValidatingPolicies after Marshal: %v", err)
	}
	if !reflect.DeepEqual(original[0], again[0]) {
		t.Errorf("round trip changed the policy:\n got: %+v\nwant: %+v", again[0], original[0])
	}
}

func TestMarshalV1Alpha1RenamesMatchConditions(t *testing.T) {
	policy := kyverno.New("aliased", kyverno.APIVersionV1Alpha1)
	policy.Spec.MatchConditions = []admissionregistrationv1.MatchCondition{
		{Name: "only-prod", Expression: "object.metadata.namespace == 'prod'"},
	}

	data, err := kyverno.Marshal(policy)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(data), "conditions:") || strings.Contains(string(data), "matchConditions:") {
		t.Errorf("v1alpha1 output should spell the field conditions:\n%s", data)
	}

	// Decoding the renamed field must recover the same policy.
	again, err := kyverno.DecodeValidatingPolicies(strings.NewReader(string(data)))
	if err != nil {
		t.Fatalf("DecodeValidatingPolicies: %v", err)
	}
	if !reflect.DeepEqual(again[0].Spec.MatchConditions, policy.Spec.MatchConditions) {
		t.Errorf("got matchConditions %+v, want %+v", again[0].Spec.MatchConditions, policy.Spec.MatchConditions)
	}

	policy.APIVersion = kyverno.APIVersionV1
	data, err = kyverno.Marshal(policy)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(data), "matchConditions:") {
		t.Errorf("v1 output should spell the field matchConditions:\n%s", data)
	}
}

// TestMarshalOmitsEmptyFields guards against a mistyped omitempty silently
// writing an empty stanza such as "evaluation: {}" into every converted policy.
func TestMarshalOmitsEmptyFields(t *testing.T) {
	policy := kyverno.New("minimal", "")
	policy.Spec.Validations = []admissionregistrationv1.Validation{{Expression: "true"}}

	data, err := kyverno.Marshal(policy)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	for _, field := range []string{
		"evaluation:",
		"autogen:",
		"webhookConfiguration:",
		"status:",
		"paramKind:",
		"paramRef:",
		"validationActions:",
		"matchConstraints:",
		"matchConditions:",
		"failurePolicy:",
		"creationTimestamp:",
	} {
		if strings.Contains(string(data), field) {
			t.Errorf("marshalled minimal policy contains %q:\n%s", field, data)
		}
	}
}

func TestMarshalTrimsWhitespace(t *testing.T) {
	data, err := kyverno.Marshal(kyverno.New("trimmed", ""))
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.TrimSpace(string(data)) != string(data) {
		t.Errorf("output is not whitespace trimmed: %q", data)
	}
}
