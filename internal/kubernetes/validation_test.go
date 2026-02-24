package kubernetes

import (
    "testing"

    admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestEvaluateValidations(t *testing.T) {
    policy := &admissionregistrationv1.ValidatingAdmissionPolicy{
        ObjectMeta: metav1.ObjectMeta{Name: "policy1"},
        Spec: admissionregistrationv1.ValidatingAdmissionPolicySpec{
            Variables: []admissionregistrationv1.Variable{{
                Name:       "foo",
                Expression: "'bar'",
            }},
            Validations: []admissionregistrationv1.Validation{{
                Expression: "variables.foo == 'bar'",
            }, {
                Expression: "object.metadata.name == 'ok'",
            }},
        },
    }

    binding := &admissionregistrationv1.ValidatingAdmissionPolicyBinding{
        ObjectMeta: metav1.ObjectMeta{Name: "binding1"},
        Spec:       admissionregistrationv1.ValidatingAdmissionPolicyBindingSpec{PolicyName: "policy1"},
    }

    resourceOK := map[string]interface{}{
        "apiVersion": "v1",
        "kind":       "Pod",
        "metadata": map[string]interface{}{
            "name":      "ok",
            "namespace": "ns1",
        },
    }

    result, err := EvaluateValidations(policy, binding, resourceOK, "ns1", nil)
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if !result.Compliant || len(result.Violations) != 0 {
        t.Fatalf("expected compliant result, got %+v", result)
    }

    resourceBad := map[string]interface{}{
        "apiVersion": "v1",
        "kind":       "Pod",
        "metadata": map[string]interface{}{
            "name":      "bad",
            "namespace": "ns1",
        },
    }
    result, err = EvaluateValidations(policy, binding, resourceBad, "ns1", nil)
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if result.Compliant || len(result.Violations) != 1 {
        t.Fatalf("expected non-compliant with one violation, got %+v", result)
    }
    if result.Violations[0].Message == "" {
        t.Fatalf("expected violation message to be set")
    }
    if len(result.Violations[0].Actions) != 1 || result.Violations[0].Actions[0] != string(admissionregistrationv1.Deny) {
        t.Fatalf("expected default deny action, got %v", result.Violations[0].Actions)
    }
}

func TestBuildNamespaceObject(t *testing.T) {
    if buildNamespaceObject("", nil) != nil {
        t.Fatalf("expected nil namespace object for empty name")
    }
    obj := buildNamespaceObject("ns1", map[string]string{"env": "prod"})
    meta := obj["metadata"].(map[string]interface{})
    if meta["name"].(string) != "ns1" {
        t.Fatalf("unexpected namespace name: %v", meta)
    }
    labels := meta["labels"].(map[string]interface{})
    if labels["env"].(string) != "prod" {
        t.Fatalf("unexpected labels: %v", labels)
    }
}

func TestConvertStringMap(t *testing.T) {
    if convertStringMap(nil) != nil {
        t.Fatalf("expected nil for empty map")
    }
    out := convertStringMap(map[string]string{"a": "b"})
    if out["a"] != "b" {
        t.Fatalf("unexpected conversion result: %v", out)
    }
}
