package kubernetes

import "testing"

func TestNormalizeRBACRules(t *testing.T) {
    obj := map[string]interface{}{
        "kind": "Role",
        "rules": []interface{}{
            map[string]interface{}{
                "apiGroups": nil,
                "resources": []string{"pods"},
                "verbs": []interface{}{"get"},
            },
        },
    }

    NormalizeResourcesForCEL([]map[string]interface{}{obj})

    rules := obj["rules"].([]interface{})
    rule := rules[0].(map[string]interface{})

    if apiGroups, ok := rule["apiGroups"].([]interface{}); !ok || len(apiGroups) != 0 {
        t.Fatalf("expected apiGroups to be empty slice, got %T %v", rule["apiGroups"], rule["apiGroups"])
    }
    resources, ok := rule["resources"].([]interface{})
    if !ok || len(resources) != 1 || resources[0] != "pods" {
        t.Fatalf("expected resources to be []interface{}{\"pods\"}, got %T %v", rule["resources"], rule["resources"])
    }
}

func TestNormalizeListFieldNilRules(t *testing.T) {
    obj := map[string]interface{}{
        "kind": "ClusterRole",
        "rules": nil,
    }
    NormalizeResourcesForCEL([]map[string]interface{}{obj})
    if rules, ok := obj["rules"].([]interface{}); !ok || len(rules) != 0 {
        t.Fatalf("expected rules to be empty slice, got %T %v", obj["rules"], obj["rules"])
    }
}
