package kubernetes

import (
    "testing"

    admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestApplyPSALevelLabels(t *testing.T) {
    labels := map[string]string{"env": "prod"}
    out := ApplyPSALevelLabels(labels, "baseline")
    if out["env"] != "prod" {
        t.Fatalf("expected existing labels to be preserved")
    }
    if out["pod-security.kubernetes.io/enforce"] != "baseline" {
        t.Fatalf("expected enforce label to be set")
    }
    if out["pss.security.kolteq.com/warn"] != "baseline" {
        t.Fatalf("expected kolteq warn label to be set")
    }
}

func TestExpandPSANamespaceLabels(t *testing.T) {
    labels := map[string]string{
        "pod-security.kubernetes.io/enforce": "restricted",
    }
    expanded := expandPSANamespaceLabels(labels)
    if expanded["pss.security.kolteq.com/enforce"] != "restricted" {
        t.Fatalf("expected kolteq label to mirror native")
    }
}

func TestDescribeResource(t *testing.T) {
    obj := map[string]interface{}{
        "kind": "Pod",
        "metadata": map[string]interface{}{
            "name":      "demo",
            "namespace": "ns1",
        },
    }
    if got := describeResource(obj); got != "Pod ns1/demo" {
        t.Fatalf("unexpected description: %s", got)
    }
}

func TestEvaluatePSACompliance(t *testing.T) {
    policy := admissionregistrationv1.ValidatingAdmissionPolicy{
        ObjectMeta: metav1.ObjectMeta{Name: "policy1"},
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
            Validations: []admissionregistrationv1.Validation{{
                Expression: "object.metadata.name == 'ok'",
            }},
        },
    }

    binding := admissionregistrationv1.ValidatingAdmissionPolicyBinding{
        ObjectMeta: metav1.ObjectMeta{Name: "binding1"},
        Spec: admissionregistrationv1.ValidatingAdmissionPolicyBindingSpec{PolicyName: "policy1"},
    }

    resources := []map[string]interface{}{
        {
            "apiVersion": "v1",
            "kind":       "Pod",
            "metadata": map[string]interface{}{
                "name":      "ok",
                "namespace": "ns1",
                "uid":       "1",
            },
        },
        {
            "apiVersion": "v1",
            "kind":       "Pod",
            "metadata": map[string]interface{}{
                "name":      "bad",
                "namespace": "ns1",
                "uid":       "2",
            },
        },
    }

    results, err := EvaluatePSACompliance([]admissionregistrationv1.ValidatingAdmissionPolicy{policy}, []admissionregistrationv1.ValidatingAdmissionPolicyBinding{binding}, resources, map[string]map[string]string{"ns1": {}}, true, "", nil)
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    counts := results["ns1"]
    if counts.Compliant != 1 || counts.NonCompliant != 1 {
        t.Fatalf("unexpected counts: %+v", counts)
    }
    if len(counts.Violations) != 1 {
        t.Fatalf("expected one violation, got %d", len(counts.Violations))
    }
}

func TestEvaluatePSAComplianceMissingPolicy(t *testing.T) {
    binding := admissionregistrationv1.ValidatingAdmissionPolicyBinding{
        ObjectMeta: metav1.ObjectMeta{Name: "binding1"},
        Spec: admissionregistrationv1.ValidatingAdmissionPolicyBindingSpec{PolicyName: "missing"},
    }
    policy := admissionregistrationv1.ValidatingAdmissionPolicy{
        ObjectMeta: metav1.ObjectMeta{Name: "other"},
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
            Validations: []admissionregistrationv1.Validation{{Expression: "true"}},
        },
    }
    resources := []map[string]interface{}{{
        "apiVersion": "v1",
        "kind":       "Pod",
        "metadata": map[string]interface{}{
            "name":      "demo",
            "namespace": "ns1",
            "uid":       "1",
        },
    }}
    if _, err := EvaluatePSACompliance([]admissionregistrationv1.ValidatingAdmissionPolicy{policy}, []admissionregistrationv1.ValidatingAdmissionPolicyBinding{binding}, resources, nil, false, "", nil); err == nil {
        t.Fatalf("expected error for missing policy")
    }
}
