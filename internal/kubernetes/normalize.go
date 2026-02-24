// Copyright by KolTEQ GmbH
// Contact: benjamin@kolteq.com

package kubernetes

import "strings"

func NormalizeResourcesForCEL(resources []map[string]interface{}) {
	for _, obj := range resources {
		normalizeResourceForCEL(obj)
	}
}

func normalizeResourceForCEL(obj map[string]interface{}) {
	if obj == nil {
		return
	}
	kind, _ := obj["kind"].(string)
	switch strings.ToLower(kind) {
	case "role", "clusterrole":
		normalizeRBACRules(obj)
	}
}

func normalizeRBACRules(obj map[string]interface{}) {
	rulesRaw, ok := obj["rules"]
	if !ok {
		return
	}
	if rulesRaw == nil {
		obj["rules"] = []interface{}{}
		return
	}
	rules, ok := rulesRaw.([]interface{})
	if !ok {
		return
	}
	for _, ruleRaw := range rules {
		rule, ok := ruleRaw.(map[string]interface{})
		if !ok {
			continue
		}
		normalizeListField(rule, "apiGroups")
		normalizeListField(rule, "resources")
		normalizeListField(rule, "verbs")
		normalizeListField(rule, "resourceNames")
		normalizeListField(rule, "nonResourceURLs")
	}
}

func normalizeListField(rule map[string]interface{}, key string) {
	val, ok := rule[key]
	if !ok || val == nil {
		rule[key] = []interface{}{}
		return
	}
	switch v := val.(type) {
	case []interface{}:
		return
	case []string:
		out := make([]interface{}, 0, len(v))
		for _, item := range v {
			out = append(out, item)
		}
		rule[key] = out
	}
}
