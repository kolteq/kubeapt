package kubernetes

import (
    "reflect"
    "testing"

    admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
)

func TestBuildNamespaceFilterAndAllowed(t *testing.T) {
    filter := buildNamespaceFilter([]string{"", "ns1", "ns2"})
    if len(filter) != 2 {
        t.Fatalf("expected 2 namespaces, got %v", filter)
    }
    if !isNamespaceAllowed("", ResourceScopeSelected, filter, "default") {
        t.Fatalf("expected empty namespace to be allowed")
    }
    if !isNamespaceAllowed("ns1", ResourceScopeSelected, filter, "default") {
        t.Fatalf("expected ns1 to be allowed")
    }
    if isNamespaceAllowed("ns3", ResourceScopeSelected, filter, "default") {
        t.Fatalf("expected ns3 to be rejected")
    }
}

func TestResourceKey(t *testing.T) {
    obj := map[string]interface{}{
        "kind": "Pod",
        "metadata": map[string]interface{}{
            "name":      "demo",
            "namespace": "ns1",
            "uid":       "u1",
        },
    }
    got := resourceKey(obj)
    if got != "Pod/ns1/demo/u1" {
        t.Fatalf("unexpected resource key: %s", got)
    }
}

func TestListResourcesForPoliciesEmpty(t *testing.T) {
    resources, labels, err := ListResourcesForPoliciesWithProgress([]admissionregistrationv1.ValidatingAdmissionPolicy{}, ResourceScopeSelected, nil, nil)
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if len(resources) != 0 {
        t.Fatalf("expected no resources, got %v", resources)
    }
    if !reflect.DeepEqual(labels, map[string]map[string]string{}) {
        t.Fatalf("expected empty labels, got %v", labels)
    }
}
