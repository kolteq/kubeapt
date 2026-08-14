// Copyright by cenroq AG
// Contact: info@cenroq.com

package convert_test

import (
	"reflect"
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cenroq/kubeapt/v2/pkg/convert"
)

// rule builds a NamedRuleWithOperations from the dimensions a test cares about.
func rule(operations []string, groups, versions, resources []string) admissionregistrationv1.NamedRuleWithOperations {
	ops := make([]admissionregistrationv1.OperationType, 0, len(operations))
	for _, op := range operations {
		ops = append(ops, admissionregistrationv1.OperationType(op))
	}
	return admissionregistrationv1.NamedRuleWithOperations{
		RuleWithOperations: admissionregistrationv1.RuleWithOperations{
			Operations: ops,
			Rule: admissionregistrationv1.Rule{
				APIGroups:   groups,
				APIVersions: versions,
				Resources:   resources,
			},
		},
	}
}

func podsRule() admissionregistrationv1.NamedRuleWithOperations {
	return rule([]string{"CREATE"}, []string{""}, []string{"v1"}, []string{"pods"})
}

func scopePtr(s admissionregistrationv1.ScopeType) *admissionregistrationv1.ScopeType { return &s }

func matchPolicyPtr(m admissionregistrationv1.MatchPolicyType) *admissionregistrationv1.MatchPolicyType {
	return &m
}

func TestMergeMatchConstraintsNilHandling(t *testing.T) {
	if got, rep := convert.MergeMatchConstraints(nil, nil); got != nil || rep.Len() != 0 {
		t.Errorf("nil/nil: got %+v with %d notes, want nil with 0", got, rep.Len())
	}

	policy := &admissionregistrationv1.MatchResources{ResourceRules: []admissionregistrationv1.NamedRuleWithOperations{podsRule()}}
	got, rep := convert.MergeMatchConstraints(policy, nil)
	if rep.Len() != 0 {
		t.Errorf("nil binding should be silent, got %d notes", rep.Len())
	}
	if len(got.ResourceRules) != 1 || got.ResourceRules[0].Resources[0] != "pods" {
		t.Fatalf("nil binding should pass the policy through: %+v", got)
	}
	// The result must not alias the input.
	got.ResourceRules[0].Resources[0] = "deployments"
	if policy.ResourceRules[0].Resources[0] != "pods" {
		t.Error("result aliases the input policy")
	}

	binding := &admissionregistrationv1.MatchResources{
		NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
	}
	got, rep = convert.MergeMatchConstraints(nil, binding)
	if got == nil || got.NamespaceSelector == nil {
		t.Fatalf("nil policy should fall back to the binding: %+v", got)
	}
	if rep.Count(convert.LevelWarn) != 1 {
		t.Errorf("nil policy should warn once, got %d warns", rep.Count(convert.LevelWarn))
	}
}

func TestIntersectLabelSelectors(t *testing.T) {
	cases := []struct {
		name        string
		a, b        *metav1.LabelSelector
		want        *metav1.LabelSelector
		wantConflic bool
	}{
		{name: "both nil"},
		{
			name: "a nil",
			b:    &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
			want: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
		},
		{
			name: "b nil",
			a:    &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
			want: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
		},
		{
			name: "disjoint keys merge",
			a:    &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
			b:    &metav1.LabelSelector{MatchLabels: map[string]string{"tier": "web"}},
			want: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod", "tier": "web"}},
		},
		{
			name: "same key same value",
			a:    &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
			b:    &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
			want: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
		},
		{
			name: "matchExpressions concatenate",
			a: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
				{Key: "env", Operator: metav1.LabelSelectorOpExists},
			}},
			b: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
				{Key: "tier", Operator: metav1.LabelSelectorOpDoesNotExist},
			}},
			want: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
				{Key: "env", Operator: metav1.LabelSelectorOpExists},
				{Key: "tier", Operator: metav1.LabelSelectorOpDoesNotExist},
			}},
		},
		{
			name: "conflicting key lowers both sides to expressions",
			a:    &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod", "team": "core"}},
			b:    &metav1.LabelSelector{MatchLabels: map[string]string{"env": "dev"}},
			want: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
				{Key: "env", Operator: metav1.LabelSelectorOpIn, Values: []string{"prod"}},
				{Key: "team", Operator: metav1.LabelSelectorOpIn, Values: []string{"core"}},
				{Key: "env", Operator: metav1.LabelSelectorOpIn, Values: []string{"dev"}},
			}},
			wantConflic: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, conflict := convert.IntersectLabelSelectors(tc.a, tc.b)
			if conflict != tc.wantConflic {
				t.Errorf("got conflict %v, want %v", conflict, tc.wantConflic)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %+v\nwant %+v", got, tc.want)
			}
		})
	}
}

// TestIntersectLabelSelectorsIsDeterministic guards the sorted iteration that
// keeps conflict lowering stable across runs.
func TestIntersectLabelSelectorsIsDeterministic(t *testing.T) {
	a := &metav1.LabelSelector{MatchLabels: map[string]string{"a": "1", "b": "2", "c": "3", "d": "4"}}
	b := &metav1.LabelSelector{MatchLabels: map[string]string{"a": "9"}}

	first, _ := convert.IntersectLabelSelectors(a, b)
	for i := 0; i < 20; i++ {
		again, _ := convert.IntersectLabelSelectors(a, b)
		if !reflect.DeepEqual(first, again) {
			t.Fatalf("run %d differs:\n got %+v\nwant %+v", i, again, first)
		}
	}
}

func TestIntersectRulesDimensions(t *testing.T) {
	cases := []struct {
		name          string
		a, b          admissionregistrationv1.NamedRuleWithOperations
		wantOK        bool
		wantOps       []string
		wantGroups    []string
		wantVersions  []string
		wantResources []string
	}{
		{
			name:   "operations wildcard on a",
			a:      rule([]string{"*"}, []string{"*"}, []string{"*"}, []string{"*"}),
			b:      rule([]string{"CREATE", "UPDATE"}, []string{""}, []string{"v1"}, []string{"pods"}),
			wantOK: true, wantOps: []string{"CREATE", "UPDATE"},
			wantGroups: []string{""}, wantVersions: []string{"v1"}, wantResources: []string{"pods"},
		},
		{
			name:   "operations intersect",
			a:      rule([]string{"CREATE", "UPDATE"}, nil, nil, []string{"pods"}),
			b:      rule([]string{"UPDATE", "DELETE"}, nil, nil, []string{"pods"}),
			wantOK: true, wantOps: []string{"UPDATE"}, wantResources: []string{"pods"},
		},
		{
			name:   "operations disjoint",
			a:      rule([]string{"CREATE"}, nil, nil, []string{"pods"}),
			b:      rule([]string{"DELETE"}, nil, nil, []string{"pods"}),
			wantOK: false,
		},
		{
			name:   "empty operations means all",
			a:      rule(nil, nil, nil, []string{"pods"}),
			b:      rule([]string{"CREATE"}, nil, nil, []string{"pods"}),
			wantOK: true, wantOps: []string{"CREATE"}, wantResources: []string{"pods"},
		},
		{
			name:   "apiGroups intersect",
			a:      rule([]string{"*"}, []string{"apps", "batch"}, nil, []string{"*"}),
			b:      rule([]string{"*"}, []string{"batch"}, nil, []string{"*"}),
			wantOK: true, wantOps: []string{"*"}, wantGroups: []string{"batch"}, wantResources: []string{"*"},
		},
		{
			name:   "apiGroups disjoint",
			a:      rule([]string{"*"}, []string{"apps"}, nil, []string{"*"}),
			b:      rule([]string{"*"}, []string{"batch"}, nil, []string{"*"}),
			wantOK: false,
		},
		{
			name:   "apiVersions wildcard on b",
			a:      rule([]string{"*"}, nil, []string{"v1", "v1beta1"}, []string{"*"}),
			b:      rule([]string{"*"}, nil, []string{"*"}, []string{"*"}),
			wantOK: true, wantOps: []string{"*"}, wantVersions: []string{"v1", "v1beta1"}, wantResources: []string{"*"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := convert.IntersectRules(tc.a, tc.b)
			if ok != tc.wantOK {
				t.Fatalf("got ok %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if want := tc.wantOps; want != nil {
				var gotOps []string
				for _, op := range got.Operations {
					gotOps = append(gotOps, string(op))
				}
				if !reflect.DeepEqual(gotOps, want) {
					t.Errorf("got operations %v, want %v", gotOps, want)
				}
			}
			if !reflect.DeepEqual(got.APIGroups, tc.wantGroups) {
				t.Errorf("got apiGroups %v, want %v", got.APIGroups, tc.wantGroups)
			}
			if !reflect.DeepEqual(got.APIVersions, tc.wantVersions) {
				t.Errorf("got apiVersions %v, want %v", got.APIVersions, tc.wantVersions)
			}
			if !reflect.DeepEqual(got.Resources, tc.wantResources) {
				t.Errorf("got resources %v, want %v", got.Resources, tc.wantResources)
			}
		})
	}
}

// TestIntersectRulesResourcePatterns walks the subresource pattern algebra.
// A pattern constrains resource and subresource independently, so the language
// is closed under intersection and every row has an exact answer.
func TestIntersectRulesResourcePatterns(t *testing.T) {
	cases := []struct {
		a, b []string
		want []string
	}{
		{a: []string{"*/*"}, b: []string{"pods"}, want: []string{"pods"}},
		{a: []string{"*/*"}, b: []string{"pods/log"}, want: []string{"pods/log"}},
		{a: []string{"*/*"}, b: []string{"*/*"}, want: []string{"*/*"}},
		{a: []string{"pods"}, b: []string{"pods"}, want: []string{"pods"}},
		{a: []string{"pods"}, b: []string{"deployments"}},
		{a: []string{"*"}, b: []string{"pods"}, want: []string{"pods"}},
		{a: []string{"*"}, b: []string{"*"}, want: []string{"*"}},
		{a: []string{"*"}, b: []string{"pods/log"}},
		{a: []string{"*"}, b: []string{"*/scale"}},
		// "pods/*" covers pods with any subresource, including none, so its
		// overlap with "*" - which requires no subresource - is exactly "pods".
		{a: []string{"*"}, b: []string{"pods/*"}, want: []string{"pods"}},
		{a: []string{"pods"}, b: []string{"pods/*"}, want: []string{"pods"}},
		{a: []string{"pods"}, b: []string{"pods/log"}},
		{a: []string{"pods/*"}, b: []string{"pods/log"}, want: []string{"pods/log"}},
		{a: []string{"pods/*"}, b: []string{"*/log"}, want: []string{"pods/log"}},
		{a: []string{"*/scale"}, b: []string{"deployments/scale"}, want: []string{"deployments/scale"}},
		{a: []string{"*/scale"}, b: []string{"deployments/*"}, want: []string{"deployments/scale"}},
		{a: []string{"*/scale"}, b: []string{"*/status"}},
		{a: []string{"pods/*"}, b: []string{"deployments/*"}},
		{a: []string{"pods/*"}, b: []string{"pods/*"}, want: []string{"pods/*"}},
		// A cross product over several patterns unions and sorts its results.
		{
			a:    []string{"pods", "deployments", "services"},
			b:    []string{"deployments", "pods"},
			want: []string{"deployments", "pods"},
		},
	}

	for _, tc := range cases {
		name := joinForName(tc.a) + " x " + joinForName(tc.b)
		t.Run(name, func(t *testing.T) {
			got, ok := convert.IntersectRules(
				rule([]string{"*"}, nil, nil, tc.a),
				rule([]string{"*"}, nil, nil, tc.b),
			)
			if tc.want == nil {
				if ok {
					t.Fatalf("got resources %v, want no overlap", got.Resources)
				}
				return
			}
			if !ok {
				t.Fatalf("got no overlap, want %v", tc.want)
			}
			if !reflect.DeepEqual(got.Resources, tc.want) {
				t.Errorf("got %v, want %v", got.Resources, tc.want)
			}
		})
	}
}

func joinForName(in []string) string {
	out := ""
	for i, v := range in {
		if i > 0 {
			out += ","
		}
		out += v
	}
	if out == "" {
		return "(empty)"
	}
	return out
}

func TestIntersectRulesScope(t *testing.T) {
	all := admissionregistrationv1.AllScopes
	cluster := admissionregistrationv1.ClusterScope
	namespaced := admissionregistrationv1.NamespacedScope

	cases := []struct {
		name   string
		a, b   *admissionregistrationv1.ScopeType
		want   *admissionregistrationv1.ScopeType
		wantOK bool
	}{
		{name: "both nil", wantOK: true},
		{name: "all and cluster", a: &all, b: &cluster, want: &cluster, wantOK: true},
		{name: "nil and namespaced", b: &namespaced, want: &namespaced, wantOK: true},
		{name: "same", a: &cluster, b: &cluster, want: &cluster, wantOK: true},
		{name: "cluster and namespaced", a: &cluster, b: &namespaced},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, b := podsRule(), podsRule()
			a.Scope, b.Scope = tc.a, tc.b
			got, ok := convert.IntersectRules(a, b)
			if ok != tc.wantOK {
				t.Fatalf("got ok %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if !reflect.DeepEqual(got.Scope, tc.want) {
				t.Errorf("got scope %v, want %v", got.Scope, tc.want)
			}
		})
	}
}

func TestIntersectRulesResourceNames(t *testing.T) {
	cases := []struct {
		name   string
		a, b   []string
		want   []string
		wantOK bool
	}{
		{name: "both empty is all names", wantOK: true},
		{name: "a empty is the identity", b: []string{"one"}, want: []string{"one"}, wantOK: true},
		{name: "b empty is the identity", a: []string{"one"}, want: []string{"one"}, wantOK: true},
		{name: "intersect", a: []string{"one", "two"}, b: []string{"two", "three"}, want: []string{"two"}, wantOK: true},
		{name: "disjoint", a: []string{"one"}, b: []string{"two"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, b := podsRule(), podsRule()
			a.ResourceNames, b.ResourceNames = tc.a, tc.b
			got, ok := convert.IntersectRules(a, b)
			if ok != tc.wantOK {
				t.Fatalf("got ok %v, want %v", ok, tc.wantOK)
			}
			if ok && !reflect.DeepEqual(got.ResourceNames, tc.want) {
				t.Errorf("got resourceNames %v, want %v", got.ResourceNames, tc.want)
			}
		})
	}
}

func TestMergeMatchConstraintsCrossProduct(t *testing.T) {
	policy := &admissionregistrationv1.MatchResources{
		ResourceRules: []admissionregistrationv1.NamedRuleWithOperations{
			rule([]string{"CREATE"}, []string{""}, []string{"v1"}, []string{"pods"}),
			rule([]string{"CREATE"}, []string{"apps"}, []string{"v1"}, []string{"deployments"}),
		},
	}
	binding := &admissionregistrationv1.MatchResources{
		ResourceRules: []admissionregistrationv1.NamedRuleWithOperations{
			rule([]string{"*"}, []string{"*"}, []string{"*"}, []string{"*"}),
			rule([]string{"CREATE"}, []string{"apps"}, []string{"v1"}, []string{"*"}),
		},
	}

	got, rep := convert.MergeMatchConstraints(policy, binding)
	if rep.Has(convert.LevelError) {
		t.Errorf("cross product should not report errors: %+v", rep.Notes)
	}
	// pods x "*" keeps pods; pods x apps is disjoint; deployments x both
	// collapse to the same rule and dedupe.
	want := []string{"pods", "deployments"}
	var gotResources []string
	for _, r := range got.ResourceRules {
		gotResources = append(gotResources, r.Resources...)
	}
	if !reflect.DeepEqual(gotResources, want) {
		t.Errorf("got resources %v, want %v (policy-outer, binding-inner, deduped)", gotResources, want)
	}
}

func TestMergeMatchConstraintsNoOverlapWarns(t *testing.T) {
	policy := &admissionregistrationv1.MatchResources{
		ResourceRules: []admissionregistrationv1.NamedRuleWithOperations{podsRule()},
	}
	binding := &admissionregistrationv1.MatchResources{
		ResourceRules: []admissionregistrationv1.NamedRuleWithOperations{
			rule([]string{"CREATE"}, []string{"apps"}, []string{"v1"}, []string{"deployments"}),
		},
	}

	got, rep := convert.MergeMatchConstraints(policy, binding)
	if len(got.ResourceRules) != 0 {
		t.Errorf("got %d rules, want 0", len(got.ResourceRules))
	}
	if rep.Count(convert.LevelWarn) != 1 {
		t.Errorf("want exactly one warn about the empty overlap, got %+v", rep.Notes)
	}
}

func TestMergeMatchConstraintsEmptyPolicyRules(t *testing.T) {
	policy := &admissionregistrationv1.MatchResources{}
	binding := &admissionregistrationv1.MatchResources{
		ResourceRules: []admissionregistrationv1.NamedRuleWithOperations{podsRule()},
	}

	got, rep := convert.MergeMatchConstraints(policy, binding)
	if len(got.ResourceRules) != 0 {
		t.Errorf("a policy matching nothing must keep matching nothing, got %+v", got.ResourceRules)
	}
	if rep.Count(convert.LevelWarn) != 1 {
		t.Errorf("want one warn, got %+v", rep.Notes)
	}
}

func TestMergeMatchConstraintsExcludesConcatenate(t *testing.T) {
	shared := rule([]string{"CREATE"}, []string{""}, []string{"v1"}, []string{"secrets"})
	policy := &admissionregistrationv1.MatchResources{
		ResourceRules:        []admissionregistrationv1.NamedRuleWithOperations{podsRule()},
		ExcludeResourceRules: []admissionregistrationv1.NamedRuleWithOperations{shared, rule([]string{"CREATE"}, []string{""}, []string{"v1"}, []string{"configmaps"})},
	}
	binding := &admissionregistrationv1.MatchResources{
		ExcludeResourceRules: []admissionregistrationv1.NamedRuleWithOperations{shared},
	}

	got, _ := convert.MergeMatchConstraints(policy, binding)
	if len(got.ExcludeResourceRules) != 2 {
		t.Errorf("got %d exclude rules, want 2 (concatenated and deduped): %+v",
			len(got.ExcludeResourceRules), got.ExcludeResourceRules)
	}
}

func TestMergeMatchConstraintsMatchPolicy(t *testing.T) {
	rules := []admissionregistrationv1.NamedRuleWithOperations{podsRule()}

	cases := []struct {
		name      string
		a, b      *admissionregistrationv1.MatchPolicyType
		want      *admissionregistrationv1.MatchPolicyType
		wantInfos int
	}{
		{name: "both unset"},
		{
			name: "both equivalent",
			a:    matchPolicyPtr(admissionregistrationv1.Equivalent),
			b:    matchPolicyPtr(admissionregistrationv1.Equivalent),
			want: matchPolicyPtr(admissionregistrationv1.Equivalent),
		},
		{
			name: "both exact",
			a:    matchPolicyPtr(admissionregistrationv1.Exact),
			b:    matchPolicyPtr(admissionregistrationv1.Exact),
			want: matchPolicyPtr(admissionregistrationv1.Exact),
		},
		{
			name:      "exact wins over equivalent",
			a:         matchPolicyPtr(admissionregistrationv1.Equivalent),
			b:         matchPolicyPtr(admissionregistrationv1.Exact),
			want:      matchPolicyPtr(admissionregistrationv1.Exact),
			wantInfos: 1,
		},
		{
			name:      "exact wins over unset, which defaults to equivalent",
			a:         matchPolicyPtr(admissionregistrationv1.Exact),
			want:      matchPolicyPtr(admissionregistrationv1.Exact),
			wantInfos: 1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policy := &admissionregistrationv1.MatchResources{ResourceRules: rules, MatchPolicy: tc.a}
			binding := &admissionregistrationv1.MatchResources{MatchPolicy: tc.b}
			got, rep := convert.MergeMatchConstraints(policy, binding)
			if !reflect.DeepEqual(got.MatchPolicy, tc.want) {
				t.Errorf("got matchPolicy %v, want %v", got.MatchPolicy, tc.want)
			}
			if rep.Count(convert.LevelInfo) != tc.wantInfos {
				t.Errorf("got %d info notes, want %d: %+v", rep.Count(convert.LevelInfo), tc.wantInfos, rep.Notes)
			}
		})
	}
}

func TestMergeMatchConstraintsWarnsOnLargeCrossProduct(t *testing.T) {
	var policyRules, bindingRules []admissionregistrationv1.NamedRuleWithOperations
	for i := 0; i < 9; i++ {
		policyRules = append(policyRules, rule([]string{"CREATE"}, []string{"g" + string(rune('a'+i))}, []string{"*"}, []string{"*"}))
	}
	for i := 0; i < 9; i++ {
		bindingRules = append(bindingRules, rule([]string{"CREATE"}, []string{"*"}, []string{"v" + string(rune('a'+i))}, []string{"*"}))
	}

	_, rep := convert.MergeMatchConstraints(
		&admissionregistrationv1.MatchResources{ResourceRules: policyRules},
		&admissionregistrationv1.MatchResources{ResourceRules: bindingRules},
	)
	if rep.Count(convert.LevelWarn) != 1 {
		t.Errorf("81 merged rules should warn once, got %+v", rep.Notes)
	}
}

func TestMergeMatchConstraintsSelectorConflictWarns(t *testing.T) {
	policy := &admissionregistrationv1.MatchResources{
		ResourceRules:     []admissionregistrationv1.NamedRuleWithOperations{podsRule()},
		NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
		ObjectSelector:    &metav1.LabelSelector{MatchLabels: map[string]string{"tier": "web"}},
	}
	binding := &admissionregistrationv1.MatchResources{
		NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "dev"}},
		ObjectSelector:    &metav1.LabelSelector{MatchLabels: map[string]string{"tier": "api"}},
	}

	_, rep := convert.MergeMatchConstraints(policy, binding)
	if rep.Count(convert.LevelWarn) != 2 {
		t.Errorf("both selector conflicts should warn, got %+v", rep.Notes)
	}
}

func TestMergeMatchConstraintsScopeIsCarried(t *testing.T) {
	policyRule := podsRule()
	policyRule.Scope = scopePtr(admissionregistrationv1.AllScopes)
	bindingRule := podsRule()
	bindingRule.Scope = scopePtr(admissionregistrationv1.NamespacedScope)

	got, _ := convert.MergeMatchConstraints(
		&admissionregistrationv1.MatchResources{ResourceRules: []admissionregistrationv1.NamedRuleWithOperations{policyRule}},
		&admissionregistrationv1.MatchResources{ResourceRules: []admissionregistrationv1.NamedRuleWithOperations{bindingRule}},
	)
	if len(got.ResourceRules) != 1 || got.ResourceRules[0].Scope == nil ||
		*got.ResourceRules[0].Scope != admissionregistrationv1.NamespacedScope {
		t.Errorf("got scope %+v, want Namespaced", got.ResourceRules)
	}
}
