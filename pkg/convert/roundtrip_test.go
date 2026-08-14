// Copyright by cenroq AG
// Contact: info@cenroq.com

package convert_test

import (
	"reflect"
	"strings"
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cenroq/kubeapt/v2/internal/kubernetes"
	"github.com/cenroq/kubeapt/v2/pkg/convert"
	"github.com/cenroq/kubeapt/v2/pkg/kyverno"
	"github.com/cenroq/kubeapt/v2/pkg/policies"
)

// roundTripVAP converts a policy and its binding to Kyverno and back.
func roundTripVAP(
	t *testing.T,
	vap admissionregistrationv1.ValidatingAdmissionPolicy,
	binding admissionregistrationv1.ValidatingAdmissionPolicyBinding,
) (admissionregistrationv1.ValidatingAdmissionPolicy, admissionregistrationv1.ValidatingAdmissionPolicyBinding) {
	t.Helper()

	converted, _, err := convert.VAPToKyverno(vap,
		[]admissionregistrationv1.ValidatingAdmissionPolicyBinding{binding}, noProvenance)
	if err != nil {
		t.Fatalf("VAPToKyverno: %v", err)
	}
	if len(converted) != 1 {
		t.Fatalf("got %d kyverno policies, want 1", len(converted))
	}

	back, backBinding, _, err := convert.KyvernoToVAP(converted[0], noProvenanceToVAP)
	if err != nil {
		t.Fatalf("KyvernoToVAP: %v", err)
	}
	return back, backBinding
}

// TestRoundTripVAPToKyvernoToVAP asserts the two honest invariants. A binding
// with no matchResources round-trips its spec exactly. A binding that does
// carry matchResources cannot: the merge folds it into matchConstraints and is
// irreversible by construction, so the right assertion is that the result
// equals the merge, not that it equals the original.
func TestRoundTripVAPToKyvernoToVAP(t *testing.T) {
	t.Run("binding without matchResources", func(t *testing.T) {
		vap := sampleVAP("require-labels")
		binding := sampleBinding("require-labels-binding", "require-labels", admissionregistrationv1.Deny)

		back, backBinding := roundTripVAP(t, vap, binding)

		if !reflect.DeepEqual(back.Spec, vap.Spec) {
			t.Errorf("spec changed across the round trip:\n got %+v\nwant %+v", back.Spec, vap.Spec)
		}
		if back.Name != vap.Name {
			t.Errorf("got name %s, want %s", back.Name, vap.Name)
		}
		if backBinding.Spec.PolicyName != vap.Name {
			t.Errorf("got policyName %s, want %s", backBinding.Spec.PolicyName, vap.Name)
		}
		if !reflect.DeepEqual(backBinding.Spec.ValidationActions, binding.Spec.ValidationActions) {
			t.Errorf("got actions %v, want %v", backBinding.Spec.ValidationActions, binding.Spec.ValidationActions)
		}
		if backBinding.Spec.MatchResources != nil {
			t.Errorf("got binding matchResources %+v, want nil", backBinding.Spec.MatchResources)
		}
	})

	t.Run("binding with matchResources", func(t *testing.T) {
		vap := sampleVAP("require-labels")
		binding := sampleBinding("prod-only", "require-labels", admissionregistrationv1.Deny)
		binding.Spec.MatchResources = &admissionregistrationv1.MatchResources{
			NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
			ResourceRules: []admissionregistrationv1.NamedRuleWithOperations{
				rule([]string{"*"}, []string{"*"}, []string{"*"}, []string{"*"}),
			},
		}

		back, backBinding := roundTripVAP(t, vap, binding)

		wantConstraints, _ := convert.MergeMatchConstraints(vap.Spec.MatchConstraints, binding.Spec.MatchResources)
		if !reflect.DeepEqual(back.Spec.MatchConstraints, wantConstraints) {
			t.Errorf("matchConstraints are not the merge:\n got %+v\nwant %+v",
				back.Spec.MatchConstraints, wantConstraints)
		}
		if backBinding.Spec.MatchResources != nil {
			t.Errorf("the merge belongs in matchConstraints, not back on the binding: %+v",
				backBinding.Spec.MatchResources)
		}
		// Everything outside matchConstraints is still exactly preserved.
		if !reflect.DeepEqual(back.Spec.Validations, vap.Spec.Validations) {
			t.Errorf("validations changed: %+v", back.Spec.Validations)
		}
		if !reflect.DeepEqual(back.Spec.Variables, vap.Spec.Variables) {
			t.Errorf("variables changed: %+v", back.Spec.Variables)
		}
	})
}

// matchCorpus is the set of request objects the match-decision property test
// evaluates every fixture against.
func matchCorpus() []map[string]any {
	var corpus []map[string]any
	for _, spec := range []struct {
		apiVersion string
		kind       string
		namespace  string
		name       string
		labels     map[string]string
	}{
		{apiVersion: "v1", kind: "Pod", namespace: "prod-web", name: "api"},
		{apiVersion: "v1", kind: "Pod", namespace: "prod-web", name: "api", labels: map[string]string{"tier": "web"}},
		{apiVersion: "v1", kind: "Pod", namespace: "prod-web", name: "api", labels: map[string]string{"tier": "db"}},
		{apiVersion: "v1", kind: "Pod", namespace: "dev-web", name: "api"},
		{apiVersion: "v1", kind: "Pod", namespace: "kube-system", name: "coredns"},
		{apiVersion: "v1", kind: "Pod", name: "clusterless"},
		{apiVersion: "v1", kind: "ConfigMap", namespace: "prod-web", name: "settings"},
		{apiVersion: "v1", kind: "Secret", namespace: "prod-web", name: "creds"},
		{apiVersion: "v1", kind: "Service", namespace: "prod-web", name: "api"},
		{apiVersion: "apps/v1", kind: "Deployment", namespace: "prod-web", name: "api"},
		{apiVersion: "apps/v1", kind: "Deployment", namespace: "dev-web", name: "api", labels: map[string]string{"tier": "web"}},
		{apiVersion: "apps/v1", kind: "StatefulSet", namespace: "prod-web", name: "db"},
		{apiVersion: "batch/v1", kind: "Job", namespace: "prod-web", name: "migrate"},
		{apiVersion: "batch/v1", kind: "CronJob", namespace: "dev-web", name: "cleanup"},
		{apiVersion: "networking.k8s.io/v1", kind: "NetworkPolicy", namespace: "prod-web", name: "deny"},
		{apiVersion: "rbac.authorization.k8s.io/v1", kind: "ClusterRole", name: "admin"},
		{apiVersion: "v1", kind: "Namespace", name: "prod-web", labels: map[string]string{"env": "prod"}},
		{apiVersion: "v1", kind: "Namespace", name: "dev-web", labels: map[string]string{"env": "dev"}},
		{apiVersion: "v1", kind: "Node", name: "worker-1"},
		{apiVersion: "v1", kind: "PersistentVolumeClaim", namespace: "prod-web", name: "data"},
	} {
		metadata := map[string]any{"name": spec.name}
		if spec.namespace != "" {
			metadata["namespace"] = spec.namespace
		}
		if spec.labels != nil {
			labels := map[string]any{}
			for key, value := range spec.labels {
				labels[key] = value
			}
			metadata["labels"] = labels
		}
		corpus = append(corpus, map[string]any{
			"apiVersion": spec.apiVersion,
			"kind":       spec.kind,
			"metadata":   metadata,
		})
	}
	return corpus
}

// namespaceLabelSets are the namespace label views the corpus is evaluated
// under, so namespaceSelector handling is genuinely exercised.
func namespaceLabelSets() []map[string]string {
	return []map[string]string{
		{"env": "prod", "kubernetes.io/metadata.name": "prod-web"},
		{"env": "dev", "kubernetes.io/metadata.name": "dev-web"},
		{"kubernetes.io/metadata.name": "kube-system"},
	}
}

// TestRoundTripPreservesMatchDecisions is the strongest check on the merge.
// For every fixture it asserts that a policy and binding pair selects exactly
// the same requests before and after a Kyverno round trip, using kubeapt's own
// matcher as the oracle so the test does not re-derive admission semantics.
//
// One documented gap: internal/kubernetes/match.go:125 hardcodes the request
// operation to CREATE, so the oracle cannot discriminate the operations
// dimension. That is covered instead by TestIntersectRulesDimensions.
func TestRoundTripPreservesMatchDecisions(t *testing.T) {
	fixtures := []struct {
		name        string
		constraints *admissionregistrationv1.MatchResources
		match       *admissionregistrationv1.MatchResources
	}{
		{
			name: "pods with no binding constraints",
			constraints: &admissionregistrationv1.MatchResources{
				ResourceRules: []admissionregistrationv1.NamedRuleWithOperations{podsRule()},
			},
		},
		{
			name: "binding narrows by namespaceSelector",
			constraints: &admissionregistrationv1.MatchResources{
				ResourceRules: []admissionregistrationv1.NamedRuleWithOperations{podsRule()},
			},
			match: &admissionregistrationv1.MatchResources{
				NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
			},
		},
		{
			name: "binding narrows by objectSelector",
			constraints: &admissionregistrationv1.MatchResources{
				ResourceRules: []admissionregistrationv1.NamedRuleWithOperations{
					rule([]string{"CREATE"}, []string{"*"}, []string{"*"}, []string{"*"}),
				},
			},
			match: &admissionregistrationv1.MatchResources{
				ObjectSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"tier": "web"}},
			},
		},
		{
			name: "both sides carry selectors",
			constraints: &admissionregistrationv1.MatchResources{
				ResourceRules:  []admissionregistrationv1.NamedRuleWithOperations{rule([]string{"CREATE"}, []string{"*"}, []string{"*"}, []string{"*"})},
				ObjectSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"tier": "web"}},
			},
			match: &admissionregistrationv1.MatchResources{
				NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
			},
		},
		{
			name: "conflicting selectors match nothing",
			constraints: &admissionregistrationv1.MatchResources{
				ResourceRules:     []admissionregistrationv1.NamedRuleWithOperations{podsRule()},
				NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
			},
			match: &admissionregistrationv1.MatchResources{
				NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "dev"}},
			},
		},
		{
			name: "selector expressions on both sides",
			constraints: &admissionregistrationv1.MatchResources{
				ResourceRules: []admissionregistrationv1.NamedRuleWithOperations{rule([]string{"CREATE"}, []string{"*"}, []string{"*"}, []string{"*"})},
				ObjectSelector: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "tier", Operator: metav1.LabelSelectorOpExists},
				}},
			},
			match: &admissionregistrationv1.MatchResources{
				ObjectSelector: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
					{Key: "tier", Operator: metav1.LabelSelectorOpIn, Values: []string{"web"}},
				}},
			},
		},
		{
			name: "binding narrows the resource set",
			constraints: &admissionregistrationv1.MatchResources{
				ResourceRules: []admissionregistrationv1.NamedRuleWithOperations{
					rule([]string{"CREATE"}, []string{"*"}, []string{"*"}, []string{"*"}),
				},
			},
			match: &admissionregistrationv1.MatchResources{
				ResourceRules: []admissionregistrationv1.NamedRuleWithOperations{
					rule([]string{"CREATE"}, []string{"apps"}, []string{"v1"}, []string{"deployments"}),
				},
			},
		},
		{
			name: "cross product over several rules",
			constraints: &admissionregistrationv1.MatchResources{
				ResourceRules: []admissionregistrationv1.NamedRuleWithOperations{
					podsRule(),
					rule([]string{"CREATE"}, []string{"apps"}, []string{"v1"}, []string{"deployments", "statefulsets"}),
					rule([]string{"CREATE"}, []string{"batch"}, []string{"v1"}, []string{"jobs"}),
				},
			},
			match: &admissionregistrationv1.MatchResources{
				ResourceRules: []admissionregistrationv1.NamedRuleWithOperations{
					rule([]string{"CREATE"}, []string{"*"}, []string{"*"}, []string{"*"}),
					rule([]string{"CREATE"}, []string{"apps"}, []string{"*"}, []string{"*"}),
				},
			},
		},
		{
			name: "excludes on both sides",
			constraints: &admissionregistrationv1.MatchResources{
				ResourceRules: []admissionregistrationv1.NamedRuleWithOperations{
					rule([]string{"CREATE"}, []string{""}, []string{"v1"}, []string{"pods", "configmaps", "secrets"}),
				},
				ExcludeResourceRules: []admissionregistrationv1.NamedRuleWithOperations{
					rule([]string{"CREATE"}, []string{""}, []string{"v1"}, []string{"secrets"}),
				},
			},
			match: &admissionregistrationv1.MatchResources{
				ExcludeResourceRules: []admissionregistrationv1.NamedRuleWithOperations{
					rule([]string{"CREATE"}, []string{""}, []string{"v1"}, []string{"configmaps"}),
				},
			},
		},
		{
			name: "scope narrowing",
			constraints: &admissionregistrationv1.MatchResources{
				ResourceRules: []admissionregistrationv1.NamedRuleWithOperations{
					rule([]string{"CREATE"}, []string{"*"}, []string{"*"}, []string{"*"}),
				},
			},
			match: &admissionregistrationv1.MatchResources{
				ResourceRules: []admissionregistrationv1.NamedRuleWithOperations{
					withScope(rule([]string{"CREATE"}, []string{"*"}, []string{"*"}, []string{"*"}), admissionregistrationv1.NamespacedScope),
				},
			},
		},
		{
			name: "resourceNames narrowing",
			constraints: &admissionregistrationv1.MatchResources{
				ResourceRules: []admissionregistrationv1.NamedRuleWithOperations{podsRule()},
			},
			match: &admissionregistrationv1.MatchResources{
				ResourceRules: []admissionregistrationv1.NamedRuleWithOperations{
					withResourceNames(rule([]string{"CREATE"}, []string{"*"}, []string{"*"}, []string{"*"}), "api"),
				},
			},
		},
		{
			name: "disjoint rules match nothing",
			constraints: &admissionregistrationv1.MatchResources{
				ResourceRules: []admissionregistrationv1.NamedRuleWithOperations{podsRule()},
			},
			match: &admissionregistrationv1.MatchResources{
				ResourceRules: []admissionregistrationv1.NamedRuleWithOperations{
					rule([]string{"CREATE"}, []string{"apps"}, []string{"v1"}, []string{"deployments"}),
				},
			},
		},
	}

	corpus := matchCorpus()

	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			vap := sampleVAP("prop")
			vap.Spec.MatchConstraints = fixture.constraints
			binding := sampleBinding("prop-binding", "prop", admissionregistrationv1.Deny)
			binding.Spec.MatchResources = fixture.match

			back, backBinding := roundTripVAP(t, vap, binding)

			var decided int
			for _, namespaceLabels := range namespaceLabelSets() {
				for i, object := range corpus {
					before := kubernetes.MatchesPolicy(&vap, object, namespaceLabels, true, false) &&
						kubernetes.MatchesBinding(&binding, object, namespaceLabels, true, false, false)
					after := kubernetes.MatchesPolicy(&back, object, namespaceLabels, true, false) &&
						kubernetes.MatchesBinding(&backBinding, object, namespaceLabels, true, false, false)

					if before != after {
						t.Errorf("object %d (%s/%s in %v) matched %v before and %v after",
							i, object["apiVersion"], object["kind"], namespaceLabels, before, after)
					}
					if before {
						decided++
					}
				}
			}

			// A fixture that matches nothing before and after would pass
			// vacuously, so say so rather than claiming coverage.
			if decided == 0 {
				t.Logf("fixture matches no request in the corpus; it only checks that the round trip stays empty")
			}
		})
	}
}

func withScope(r admissionregistrationv1.NamedRuleWithOperations, scope admissionregistrationv1.ScopeType) admissionregistrationv1.NamedRuleWithOperations {
	r.Scope = &scope
	return r
}

func withResourceNames(r admissionregistrationv1.NamedRuleWithOperations, names ...string) admissionregistrationv1.NamedRuleWithOperations {
	r.ResourceNames = names
	return r
}

func TestRoundTripKyvernoToVAPToKyverno(t *testing.T) {
	t.Run("cluster scoped", func(t *testing.T) {
		original := sampleKyverno("check-labels")

		vap, binding, _, err := convert.KyvernoToVAP(original, noProvenanceToVAP)
		if err != nil {
			t.Fatalf("KyvernoToVAP: %v", err)
		}
		back, _, err := convert.VAPToKyverno(vap,
			[]admissionregistrationv1.ValidatingAdmissionPolicyBinding{binding}, noProvenance)
		if err != nil {
			t.Fatalf("VAPToKyverno: %v", err)
		}
		if len(back) != 1 {
			t.Fatalf("got %d policies, want 1", len(back))
		}
		if !reflect.DeepEqual(back[0].Spec, original.Spec) {
			t.Errorf("spec changed across the round trip:\n got %+v\nwant %+v", back[0].Spec, original.Spec)
		}
	})

	t.Run("kyverno-only stanzas are dropped", func(t *testing.T) {
		enabled := true
		timeout := int32(15)
		original := sampleKyverno("p")
		original.Spec.Evaluation = &kyverno.EvaluationConfiguration{Background: &kyverno.BackgroundConfiguration{Enabled: &enabled}}
		original.Spec.Autogen = &kyverno.AutogenConfiguration{
			PodControllers: &kyverno.PodControllersGenerationConfiguration{Controllers: []string{"deployments"}},
		}
		original.Spec.WebhookConfiguration = &kyverno.WebhookConfiguration{TimeoutSeconds: &timeout}

		vap, binding, _, err := convert.KyvernoToVAP(original, noProvenanceToVAP)
		if err != nil {
			t.Fatalf("KyvernoToVAP: %v", err)
		}
		back, _, err := convert.VAPToKyverno(vap,
			[]admissionregistrationv1.ValidatingAdmissionPolicyBinding{binding}, noProvenance)
		if err != nil {
			t.Fatalf("VAPToKyverno: %v", err)
		}
		if back[0].Spec.Evaluation != nil || back[0].Spec.Autogen != nil || back[0].Spec.WebhookConfiguration != nil {
			t.Errorf("kyverno-only stanzas survived a ValidatingAdmissionPolicy: %+v", back[0].Spec)
		}
	})

	// A NamespacedValidatingPolicy has no cluster-scoped counterpart, so it
	// comes back as a cluster-scoped ValidatingPolicy with the namespace pin
	// folded into matchConstraints. The pin is what must survive.
	t.Run("namespaced policy keeps its pin", func(t *testing.T) {
		original := sampleKyverno("check-replicas")
		original.Kind = kyverno.KindNamespacedValidatingPolicy
		original.Namespace = "production"

		vap, binding, _, err := convert.KyvernoToVAP(original, noProvenanceToVAP)
		if err != nil {
			t.Fatalf("KyvernoToVAP: %v", err)
		}
		back, _, err := convert.VAPToKyverno(vap,
			[]admissionregistrationv1.ValidatingAdmissionPolicyBinding{binding}, noProvenance)
		if err != nil {
			t.Fatalf("VAPToKyverno: %v", err)
		}

		if back[0].Namespaced() {
			t.Errorf("got kind %s, want a cluster-scoped ValidatingPolicy", back[0].Kind)
		}
		selector := back[0].Spec.MatchConstraints.NamespaceSelector
		if selector == nil || selector.MatchLabels["kubernetes.io/metadata.name"] != "production" {
			t.Errorf("the namespace pin was lost: %+v", back[0].Spec.MatchConstraints)
		}
	})
}

func TestRoundTripPreservesAnnotations(t *testing.T) {
	vap := sampleVAP("annotated")
	vap.Annotations = map[string]string{
		policies.AnnotationDisplayName: "Require Labels",
		policies.AnnotationDescription: "every pod needs an environment label",
		policies.AnnotationCategory:    "Best Practices",
		policies.AnnotationSeverity:    "Critical",
		"team.example.com/owner":       "platform",
	}
	binding := sampleBinding("annotated-binding", "annotated", admissionregistrationv1.Deny)

	back, _ := roundTripVAP(t, vap, binding)

	for key, want := range map[string]string{
		policies.AnnotationDisplayName:        "Require Labels",
		policies.AnnotationDescription:        "every pod needs an environment label",
		policies.AnnotationCategory:           "Best Practices",
		policies.AnnotationSeverity:           "Critical",
		policies.KyvernoAnnotationTitle:       "Require Labels",
		policies.KyvernoAnnotationDescription: "every pod needs an environment label",
		policies.KyvernoAnnotationCategory:    "Best Practices",
		policies.KyvernoAnnotationSeverity:    "high",
		"team.example.com/owner":              "platform",
	} {
		if back.Annotations[key] != want {
			t.Errorf("annotation %s: got %q, want %q", key, back.Annotations[key], want)
		}
	}
}

// TestRoundTripIsIdempotent guards against annotations accumulating and against
// a merge re-merging an already-merged object into a growing cross product.
func TestRoundTripIsIdempotent(t *testing.T) {
	vap := sampleVAP("stable")
	vap.Annotations = map[string]string{policies.AnnotationSeverity: "Critical"}
	binding := sampleBinding("stable-binding", "stable", admissionregistrationv1.Deny)
	binding.Spec.MatchResources = &admissionregistrationv1.MatchResources{
		NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
		ResourceRules: []admissionregistrationv1.NamedRuleWithOperations{
			rule([]string{"*"}, []string{"*"}, []string{"*"}, []string{"*"}),
		},
	}

	once, onceBinding := roundTripVAP(t, vap, binding)
	twice, twiceBinding := roundTripVAP(t, once, onceBinding)

	if !reflect.DeepEqual(once.Spec, twice.Spec) {
		t.Errorf("a second round trip changed the spec:\n once %+v\ntwice %+v", once.Spec, twice.Spec)
	}
	if !reflect.DeepEqual(once.Annotations, twice.Annotations) {
		t.Errorf("annotations accumulated:\n once %v\ntwice %v", once.Annotations, twice.Annotations)
	}
	if !reflect.DeepEqual(onceBinding.Spec, twiceBinding.Spec) {
		t.Errorf("a second round trip changed the binding:\n once %+v\ntwice %+v", onceBinding.Spec, twiceBinding.Spec)
	}
	if once.Name != twice.Name || onceBinding.Name != twiceBinding.Name {
		t.Errorf("names drifted: %s/%s then %s/%s", once.Name, onceBinding.Name, twice.Name, twiceBinding.Name)
	}
}

// TestRoundTripThroughYAML checks the conversion survives serialization, since
// that is how the CLI actually moves policies between the two models.
func TestRoundTripThroughYAML(t *testing.T) {
	vap := sampleVAP("serialized")
	binding := sampleBinding("serialized-binding", "serialized", admissionregistrationv1.Deny)

	converted, _, err := convert.VAPToKyverno(vap,
		[]admissionregistrationv1.ValidatingAdmissionPolicyBinding{binding}, noProvenance)
	if err != nil {
		t.Fatalf("VAPToKyverno: %v", err)
	}

	data, err := kyverno.Marshal(converted[0])
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	decoded, err := kyverno.DecodeValidatingPolicies(strings.NewReader(string(data)))
	if err != nil {
		t.Fatalf("DecodeValidatingPolicies: %v", err)
	}
	if len(decoded) != 1 {
		t.Fatalf("got %d policies, want 1", len(decoded))
	}

	back, _, _, err := convert.KyvernoToVAP(decoded[0], noProvenanceToVAP)
	if err != nil {
		t.Fatalf("KyvernoToVAP: %v", err)
	}
	if !reflect.DeepEqual(back.Spec, vap.Spec) {
		t.Errorf("spec changed across a YAML round trip:\n got %+v\nwant %+v", back.Spec, vap.Spec)
	}
}
