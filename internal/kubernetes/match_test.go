package kubernetes

import (
    "testing"

    admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestMatchesResourceRule(t *testing.T) {
    if !matchesResourceRule("pods", []string{"*"}) {
        t.Fatalf("expected wildcard to match")
    }
    if !matchesResourceRule("pods", []string{"pods/*"}) {
        t.Fatalf("expected subresource wildcard to match")
    }
    if matchesResourceRule("pods", []string{"pods/status"}) {
        t.Fatalf("expected explicit subresource to not match base resource")
    }
}

func TestMatchesRuleAndSelectors(t *testing.T) {
    obj := map[string]interface{}{
        "apiVersion": "v1",
        "kind":       "Pod",
        "metadata": map[string]interface{}{
            "name":      "mypod",
            "namespace": "ns1",
            "labels": map[string]interface{}{
                "app": "demo",
            },
        },
    }

    rule := admissionregistrationv1.NamedRuleWithOperations{
        ResourceNames: []string{"mypod"},
        RuleWithOperations: admissionregistrationv1.RuleWithOperations{
            Rule: admissionregistrationv1.Rule{
                APIGroups:   []string{""},
                APIVersions: []string{"v1"},
                Resources:   []string{"pods"},
            },
        },
    }
    if !matchesRule(obj, rule) {
        t.Fatalf("expected rule to match")
    }

    scope := admissionregistrationv1.ClusterScope
    rule.Scope = &scope
    if matchesRule(obj, rule) {
        t.Fatalf("expected cluster scope to not match namespaced object")
    }

    selector := &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}}
    if !matchesNamespaceSelector(selector, obj, map[string]string{"env": "prod"}, false, false) {
        t.Fatalf("expected selector to match when namespace unknown")
    }

    objSelector := &metav1.LabelSelector{MatchLabels: map[string]string{"app": "demo"}}
    if !matchesObjectSelector(objSelector, obj, false) {
        t.Fatalf("expected object selector to match")
    }
}

func TestMatchesPolicyAndBinding(t *testing.T) {
    obj := map[string]interface{}{
        "apiVersion": "v1",
        "kind":       "Pod",
        "metadata": map[string]interface{}{
            "name":      "mypod",
            "namespace": "ns1",
        },
    }

    policy := &admissionregistrationv1.ValidatingAdmissionPolicy{
        Spec: admissionregistrationv1.ValidatingAdmissionPolicySpec{
            MatchConstraints: &admissionregistrationv1.MatchResources{
                ResourceRules: []admissionregistrationv1.NamedRuleWithOperations{{
                    RuleWithOperations: admissionregistrationv1.RuleWithOperations{
                        Rule: admissionregistrationv1.Rule{
                            APIGroups:   []string{""},
                            APIVersions: []string{"v1"},
                            Resources:   []string{"pods"},
                        },
                    },
                }},
            },
        },
    }

    binding := &admissionregistrationv1.ValidatingAdmissionPolicyBinding{
        Spec: admissionregistrationv1.ValidatingAdmissionPolicyBindingSpec{},
    }

    if !MatchesPolicy(policy, obj, nil, true, false) {
        t.Fatalf("expected policy to match")
    }
    if !MatchesBinding(binding, obj, nil, true, false, false) {
        t.Fatalf("expected binding to match when match resources nil")
    }
}

func TestMetadataHelpers(t *testing.T) {
    obj := map[string]interface{}{
        "metadata": map[string]interface{}{
            "name": "demo",
            "labels": map[string]interface{}{
                "k": "v",
                "x": 10,
            },
        },
    }

    if got := MetadataString(obj, "name"); got != "demo" {
        t.Fatalf("expected name demo, got %q", got)
    }
    labels := MetadataLabels(obj)
    if len(labels) != 1 || labels["k"] != "v" {
        t.Fatalf("unexpected labels: %v", labels)
    }
}
