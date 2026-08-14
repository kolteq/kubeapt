// Copyright by cenroq AG
// Contact: info@cenroq.com

package convert

import (
	"sort"
	"strings"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// maxMergedRules bounds the cross product before kubeapt warns. Real policies
// carry one to three rules per side, so exceeding this suggests the binding is
// broader than intended.
const maxMergedRules = 64

// MergeMatchConstraints intersects a ValidatingAdmissionPolicy's
// spec.matchConstraints with a ValidatingAdmissionPolicyBinding's
// spec.matchResources, producing the single MatchResources that Kyverno needs
// because it has no binding object.
//
// Kubernetes requires both to match, and that conjunction is exactly
// expressible in a single object on every dimension: label selectors AND by
// concatenating their matchExpressions, exclude rules AND by concatenation
// because not-A and not-B is not-(A or B), and resource rules become the cross
// product of the two sides with each pair intersected dimension-wise. The one
// conservative choice is matchPolicy, where Exact wins because it is the
// narrower of the two and so never widens what the policy matches.
//
// Semantics follow internal/kubernetes/match.go: a nil binding matchResources
// matches every request, while empty policy resourceRules match none.
//
// Notes carry no Source or Target; use Report.Absorb to attach them.
func MergeMatchConstraints(
	policy *admissionregistrationv1.MatchResources,
	binding *admissionregistrationv1.MatchResources,
) (*admissionregistrationv1.MatchResources, Report) {
	var rep Report

	switch {
	case policy == nil && binding == nil:
		return nil, rep
	case binding == nil:
		return policy.DeepCopy(), rep
	case policy == nil:
		rep.Warnf("", "", "spec.matchConstraints",
			"source policy has no matchConstraints, so the binding's matchResources is used alone")
		return binding.DeepCopy(), rep
	}

	out := &admissionregistrationv1.MatchResources{}

	// Selectors: an exact conjunction.
	var unsatisfiable bool
	out.NamespaceSelector, unsatisfiable = IntersectLabelSelectors(policy.NamespaceSelector, binding.NamespaceSelector)
	if unsatisfiable {
		rep.Warnf("", "", "spec.matchConstraints.namespaceSelector",
			"policy and binding namespaceSelectors require different values for the same label key, so the merged policy matches no namespace; this mirrors the source pair")
	}
	out.ObjectSelector, unsatisfiable = IntersectLabelSelectors(policy.ObjectSelector, binding.ObjectSelector)
	if unsatisfiable {
		rep.Warnf("", "", "spec.matchConstraints.objectSelector",
			"policy and binding objectSelectors require different values for the same label key, so the merged policy matches no object; this mirrors the source pair")
	}

	// Excludes: a union, because not-any(A) and not-any(B) is not-any(A or B).
	out.ExcludeResourceRules = dedupeRules(concatRules(policy.ExcludeResourceRules, binding.ExcludeResourceRules))

	// matchPolicy: Exact is the narrower of the two.
	policyMatch := derefMatchPolicy(policy.MatchPolicy)
	bindingMatch := derefMatchPolicy(binding.MatchPolicy)
	if policyMatch != bindingMatch {
		exact := admissionregistrationv1.Exact
		out.MatchPolicy = &exact
		rep.Infof("", "", "spec.matchConstraints.matchPolicy",
			"policy uses matchPolicy %s and the binding uses %s; the merged policy uses Exact, the narrower of the two",
			policyMatch, bindingMatch)
	} else if policy.MatchPolicy != nil {
		value := *policy.MatchPolicy
		out.MatchPolicy = &value
	}

	out.ResourceRules = mergeResourceRules(policy.ResourceRules, binding.ResourceRules, &rep)

	return out, rep
}

// mergeResourceRules intersects two rule sets as an or-of-ands cross product.
func mergeResourceRules(
	policyRules, bindingRules []admissionregistrationv1.NamedRuleWithOperations,
	rep *Report,
) []admissionregistrationv1.NamedRuleWithOperations {
	// An empty binding matchResources selects everything; see
	// internal/kubernetes/match.go, where requireResourceRules is false for a
	// binding.
	if len(bindingRules) == 0 {
		return deepCopyRules(policyRules)
	}
	if len(policyRules) == 0 {
		rep.Warnf("", "", "spec.matchConstraints.resourceRules",
			"source policy has no resourceRules, so it matches no request; the merged policy keeps that behaviour")
		return nil
	}

	var merged []admissionregistrationv1.NamedRuleWithOperations
	for _, policyRule := range policyRules {
		for _, bindingRule := range bindingRules {
			rule, ok := IntersectRules(policyRule, bindingRule)
			if !ok {
				continue
			}
			merged = append(merged, rule)
		}
	}
	merged = dedupeRules(merged)

	if len(merged) == 0 {
		rep.Warnf("", "", "spec.matchConstraints.resourceRules",
			"no policy rule overlaps any binding rule, so the merged policy matches no request; verify the binding targets this policy's resources")
	}
	if len(merged) > maxMergedRules {
		rep.Warnf("", "", "spec.matchConstraints.resourceRules",
			"merging %d policy rules with %d binding rules produced %d rules; consider narrowing the binding",
			len(policyRules), len(bindingRules), len(merged))
	}
	return merged
}

// IntersectLabelSelectors returns a selector matching exactly the objects both
// a and b match. A nil selector matches everything. The second result reports
// that the two require different values for the same label key, which makes the
// merged selector match nothing - the same as the source pair.
func IntersectLabelSelectors(a, b *metav1.LabelSelector) (*metav1.LabelSelector, bool) {
	switch {
	case a == nil && b == nil:
		return nil, false
	case a == nil:
		return b.DeepCopy(), false
	case b == nil:
		return a.DeepCopy(), false
	}

	out := &metav1.LabelSelector{}
	// matchExpressions are ANDed within one selector, so concatenating is exact.
	out.MatchExpressions = append(out.MatchExpressions, deepCopyRequirements(a.MatchExpressions)...)
	out.MatchExpressions = append(out.MatchExpressions, deepCopyRequirements(b.MatchExpressions)...)

	conflict := false
	for key, value := range a.MatchLabels {
		if other, ok := b.MatchLabels[key]; ok && other != value {
			conflict = true
			break
		}
	}

	if !conflict {
		if len(a.MatchLabels)+len(b.MatchLabels) > 0 {
			out.MatchLabels = map[string]string{}
			for key, value := range a.MatchLabels {
				out.MatchLabels[key] = value
			}
			for key, value := range b.MatchLabels {
				out.MatchLabels[key] = value
			}
		}
		return out, false
	}

	// Lower every matchLabel on both sides to a matchExpression. Concatenated
	// matchExpressions are ANDed, so "key In [x]" and "key In [y]" correctly
	// matches nothing, exactly as the source pair did.
	for _, labels := range []map[string]string{a.MatchLabels, b.MatchLabels} {
		for _, key := range sortedStringKeys(labels) {
			out.MatchExpressions = append(out.MatchExpressions, metav1.LabelSelectorRequirement{
				Key:      key,
				Operator: metav1.LabelSelectorOpIn,
				Values:   []string{labels[key]},
			})
		}
	}
	return out, true
}

// IntersectRules returns the rule matching exactly the requests both a and b
// match. ok is false when no request matches both, in which case the pair
// contributes nothing to a merge.
//
// Every dimension intersects exactly, so the result is never an approximation.
func IntersectRules(a, b admissionregistrationv1.NamedRuleWithOperations) (
	admissionregistrationv1.NamedRuleWithOperations, bool) {
	var zero admissionregistrationv1.NamedRuleWithOperations
	var out admissionregistrationv1.NamedRuleWithOperations

	operations, ok := intersectOperations(a.Operations, b.Operations)
	if !ok {
		return zero, false
	}
	out.Operations = operations

	if out.APIGroups, ok = intersectWildcard(a.APIGroups, b.APIGroups); !ok {
		return zero, false
	}
	if out.APIVersions, ok = intersectWildcard(a.APIVersions, b.APIVersions); !ok {
		return zero, false
	}
	if out.Resources, ok = intersectResourcePatterns(a.Resources, b.Resources); !ok {
		return zero, false
	}
	if out.Scope, ok = intersectScope(a.Scope, b.Scope); !ok {
		return zero, false
	}

	// Empty resourceNames means "all names", so it is the identity element.
	switch {
	case len(a.ResourceNames) == 0:
		out.ResourceNames = append([]string(nil), b.ResourceNames...)
	case len(b.ResourceNames) == 0:
		out.ResourceNames = append([]string(nil), a.ResourceNames...)
	default:
		out.ResourceNames = intersectStrings(a.ResourceNames, b.ResourceNames)
		if len(out.ResourceNames) == 0 {
			return zero, false
		}
	}

	return out, true
}

// intersectOperations intersects two operation sets, treating both "*" and an
// empty list as every operation.
func intersectOperations(a, b []admissionregistrationv1.OperationType) ([]admissionregistrationv1.OperationType, bool) {
	as := operationStrings(a)
	bs := operationStrings(b)
	merged, ok := intersectWildcard(as, bs)
	if !ok {
		return nil, false
	}
	if merged == nil {
		return nil, true
	}
	out := make([]admissionregistrationv1.OperationType, 0, len(merged))
	for _, op := range merged {
		out = append(out, admissionregistrationv1.OperationType(op))
	}
	return out, true
}

func operationStrings(in []admissionregistrationv1.OperationType) []string {
	if in == nil {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, op := range in {
		out = append(out, string(op))
	}
	return out
}

// intersectWildcard intersects two value sets where "*" and an empty list both
// mean "all". ok is false when the intersection is empty.
func intersectWildcard(a, b []string) ([]string, bool) {
	aAll := len(a) == 0 || containsString(a, "*")
	bAll := len(b) == 0 || containsString(b, "*")

	switch {
	case aAll && bAll:
		// Prefer whichever side spelled it out, so a merged rule keeps its
		// readable "*" instead of collapsing to an empty list.
		if len(a) > 0 {
			return append([]string(nil), a...), true
		}
		return append([]string(nil), b...), true
	case aAll:
		return append([]string(nil), b...), true
	case bAll:
		return append([]string(nil), a...), true
	}

	out := intersectStrings(a, b)
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}

// intersectScope intersects two rule scopes. A nil scope and AllScopes both
// mean every scope; Cluster and Namespaced are disjoint.
func intersectScope(a, b *admissionregistrationv1.ScopeType) (*admissionregistrationv1.ScopeType, bool) {
	aValue := derefScope(a)
	bValue := derefScope(b)

	switch {
	case aValue == admissionregistrationv1.AllScopes:
		return copyScope(b), true
	case bValue == admissionregistrationv1.AllScopes:
		return copyScope(a), true
	case aValue == bValue:
		return copyScope(a), true
	default:
		return nil, false
	}
}

// intersectResourcePatterns intersects two resource pattern lists. ok is false
// when nothing matches both.
//
// Per the Rule.Resources contract as the API server implements it, a pattern
// constrains the resource and the subresource independently: "pods" is pods
// with no subresource, "pods/log" that one subresource, "pods/*" pods with any
// subresource including none, "*" any resource with no subresource, "*/scale"
// that subresource of any resource, and "*/*" everything. Because both
// constraints are drawn from {any, equals-X} the language is closed under
// intersection, so every pair is exactly expressible and no result is ever
// approximated.
func intersectResourcePatterns(a, b []string) ([]string, bool) {
	if len(a) == 0 && len(b) == 0 {
		return nil, true
	}
	if len(a) == 0 {
		return append([]string(nil), b...), true
	}
	if len(b) == 0 {
		return append([]string(nil), a...), true
	}

	seen := map[string]struct{}{}
	var out []string
	for _, left := range a {
		for _, right := range b {
			value, ok := intersectResourcePattern(left, right)
			if !ok {
				continue
			}
			if _, dup := seen[value]; dup {
				continue
			}
			seen[value] = struct{}{}
			out = append(out, value)
		}
	}
	if len(out) == 0 {
		return nil, false
	}
	sort.Strings(out)
	return out, true
}

func intersectResourcePattern(a, b string) (string, bool) {
	aResource, aSub, aHasSub := splitResourcePattern(a)
	bResource, bSub, bHasSub := splitResourcePattern(b)

	resource, ok := intersectPatternPart(aResource, bResource)
	if !ok {
		return "", false
	}

	switch {
	case !aHasSub && !bHasSub:
		// Both require no subresource.
		return resource, true

	case aHasSub && bHasSub:
		sub, ok := intersectPatternPart(aSub, bSub)
		if !ok {
			return "", false
		}
		return joinResourcePattern(resource, sub), true

	default:
		// Exactly one side names a subresource. The other requires no
		// subresource, so only a "/*" wildcard - which also covers the
		// subresource-free request - can overlap it.
		sub := aSub
		if bHasSub {
			sub = bSub
		}
		if sub != "*" {
			return "", false
		}
		return resource, true
	}
}

func intersectPatternPart(a, b string) (string, bool) {
	switch {
	case a == "*":
		return b, true
	case b == "*":
		return a, true
	case a == b:
		return a, true
	default:
		return "", false
	}
}

func joinResourcePattern(resource, subresource string) string {
	return resource + "/" + subresource
}

func splitResourcePattern(pattern string) (resource, subresource string, hasSubresource bool) {
	if index := strings.IndexByte(pattern, '/'); index != -1 {
		return pattern[:index], pattern[index+1:], true
	}
	return pattern, "", false
}

func concatRules(a, b []admissionregistrationv1.NamedRuleWithOperations) []admissionregistrationv1.NamedRuleWithOperations {
	if len(a) == 0 && len(b) == 0 {
		return nil
	}
	out := make([]admissionregistrationv1.NamedRuleWithOperations, 0, len(a)+len(b))
	out = append(out, deepCopyRules(a)...)
	out = append(out, deepCopyRules(b)...)
	return out
}

func deepCopyRules(in []admissionregistrationv1.NamedRuleWithOperations) []admissionregistrationv1.NamedRuleWithOperations {
	if in == nil {
		return nil
	}
	out := make([]admissionregistrationv1.NamedRuleWithOperations, len(in))
	for i := range in {
		in[i].DeepCopyInto(&out[i])
	}
	return out
}

func deepCopyRequirements(in []metav1.LabelSelectorRequirement) []metav1.LabelSelectorRequirement {
	if in == nil {
		return nil
	}
	out := make([]metav1.LabelSelectorRequirement, len(in))
	for i := range in {
		in[i].DeepCopyInto(&out[i])
	}
	return out
}

// dedupeRules drops rules that select exactly the same requests as an earlier
// one, preserving first-seen order.
func dedupeRules(in []admissionregistrationv1.NamedRuleWithOperations) []admissionregistrationv1.NamedRuleWithOperations {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]admissionregistrationv1.NamedRuleWithOperations, 0, len(in))
	for _, rule := range in {
		key := ruleKey(rule)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, rule)
	}
	return out
}

func ruleKey(rule admissionregistrationv1.NamedRuleWithOperations) string {
	parts := []string{
		strings.Join(sortedCopy(operationStrings(rule.Operations)), ","),
		strings.Join(sortedCopy(rule.APIGroups), ","),
		strings.Join(sortedCopy(rule.APIVersions), ","),
		strings.Join(sortedCopy(rule.Resources), ","),
		strings.Join(sortedCopy(rule.ResourceNames), ","),
		string(derefScope(rule.Scope)),
	}
	return strings.Join(parts, "|")
}

func intersectStrings(a, b []string) []string {
	set := make(map[string]struct{}, len(b))
	for _, value := range b {
		set[value] = struct{}{}
	}
	seen := map[string]struct{}{}
	var out []string
	for _, value := range a {
		if _, ok := set[value]; !ok {
			continue
		}
		if _, dup := seen[value]; dup {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func sortedStringKeys(in map[string]string) []string {
	out := make([]string, 0, len(in))
	for key := range in {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func derefMatchPolicy(in *admissionregistrationv1.MatchPolicyType) admissionregistrationv1.MatchPolicyType {
	if in == nil {
		return admissionregistrationv1.Equivalent
	}
	return *in
}

func derefScope(in *admissionregistrationv1.ScopeType) admissionregistrationv1.ScopeType {
	if in == nil {
		return admissionregistrationv1.AllScopes
	}
	return *in
}

func copyScope(in *admissionregistrationv1.ScopeType) *admissionregistrationv1.ScopeType {
	if in == nil {
		return nil
	}
	value := *in
	return &value
}
