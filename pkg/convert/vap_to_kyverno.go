// Copyright by cenroq AG
// Contact: info@cenroq.com

package convert

import (
	"sort"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"

	"github.com/cenroq/kubeapt/v2/pkg/kyverno"
)

// VAPToKyvernoOptions tunes ValidatingAdmissionPolicy to Kyverno conversion.
// The zero value is valid and behaves as the documented defaults.
type VAPToKyvernoOptions struct {
	// DefaultValidationActions applies when no binding supplies actions. A nil
	// value means Deny.
	DefaultValidationActions []admissionregistrationv1.ValidationAction
	// Namespace, when set, emits NamespacedValidatingPolicy in that namespace
	// instead of a cluster-scoped ValidatingPolicy.
	Namespace string
	// TargetAPIVersion is the emitted apiVersion. An empty value means
	// kyverno.APIVersionV1.
	TargetAPIVersion string
	// ProvenanceTool identifies the converter in the convert.kubeapt.io/tool
	// annotation, for example "kubeapt/2.0.1". An empty value means "kubeapt".
	ProvenanceTool string
	// OmitProvenance suppresses the convert.kubeapt.io/* annotations.
	OmitProvenance bool
	// DropUnmappedAnnotations discards source annotations that have no mapping
	// instead of copying them through.
	DropUnmappedAnnotations bool
}

func (o VAPToKyvernoOptions) actions() []admissionregistrationv1.ValidationAction {
	if len(o.DefaultValidationActions) == 0 {
		return []admissionregistrationv1.ValidationAction{admissionregistrationv1.Deny}
	}
	return append([]admissionregistrationv1.ValidationAction(nil), o.DefaultValidationActions...)
}

func (o VAPToKyvernoOptions) tool() string {
	if o.ProvenanceTool == "" {
		return defaultProvenanceTool
	}
	return o.ProvenanceTool
}

// VAPToKyverno converts one ValidatingAdmissionPolicy together with the
// bindings that reference it.
//
// It returns one ValidatingPolicy per binding. Kubernetes evaluates a policy
// when *any* of its bindings matches, and a single ValidatingPolicy cannot
// express that union, so splitting is the only faithful encoding; the split is
// recorded as a LevelError note. With no bindings it returns one policy whose
// validationActions come from opts, because a bindingless
// ValidatingAdmissionPolicy is inert in Kubernetes while a ValidatingPolicy is
// always active.
//
// Every binding must reference vap.Name; callers with a mixed set should use
// VAPSetToKyverno, which groups them. The error is always nil today and exists
// so callers do not have to change when a future input becomes unconvertible.
func VAPToKyverno(
	vap admissionregistrationv1.ValidatingAdmissionPolicy,
	bindings []admissionregistrationv1.ValidatingAdmissionPolicyBinding,
	opts VAPToKyvernoOptions,
) ([]kyverno.ValidatingPolicy, Report, error) {
	var rep Report
	source := objectRef("ValidatingAdmissionPolicy", "", vap.Name)
	actions := opts.actions()

	if vap.Spec.ParamKind != nil {
		rep.Errorf(source, "", "spec.paramKind",
			"paramKind %s %s has no ValidatingPolicy equivalent and is dropped; the params identifier will be unbound, so the converted policy will not compile until the expressions are rewritten",
			vap.Spec.ParamKind.APIVersion, vap.Spec.ParamKind.Kind)
	}
	if len(vap.Spec.Validations) == 0 {
		rep.Warnf(source, "", "spec.validations", "policy declares no validations, so it accepts every request it matches")
	}
	if vapHasStatus(vap) {
		rep.Infof(source, "", "status", "status is not carried into the converted policy")
	}

	base := newBasePolicy(vap, opts, &rep, source)

	switch len(bindings) {
	case 0:
		policy := base.DeepCopy()
		policy.Spec.ValidationActions = actions
		rep.Warnf(source, targetRef(policy), "spec.validationActions",
			"no ValidatingAdmissionPolicyBinding references this policy, so it is inert in kubernetes; the converted policy is active with validationActions %v",
			actionStrings(actions))
		applyPolicyProvenance(policy, opts, source, "")
		return []kyverno.ValidatingPolicy{*policy}, rep, nil

	case 1:
		policy := convertBinding(base, bindings[0], vap.Name, actions, opts, &rep, source)
		return []kyverno.ValidatingPolicy{*policy}, rep, nil

	default:
		sorted := append([]admissionregistrationv1.ValidatingAdmissionPolicyBinding(nil), bindings...)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })

		out := make([]kyverno.ValidatingPolicy, 0, len(sorted))
		for _, binding := range sorted {
			name := derivedName(vap.Name, binding.Name)
			out = append(out, *convertBinding(base, binding, name, actions, opts, &rep, source))
		}
		rep.Errorf(source, "", "",
			"%d bindings reference this policy and kubernetes validates a request matching any of them; kubeapt emitted %d ValidatingPolicy documents, one per binding, because a single ValidatingPolicy cannot express that union",
			len(sorted), len(out))
		return out, rep, nil
	}
}

// VAPSetToKyverno converts a whole policy and binding set, grouping bindings by
// spec.policyName. Output follows input policy order, then binding name. A
// binding naming a policy that is not present is recorded as a LevelError note
// and skipped. The error is non-nil only when no policy converted.
func VAPSetToKyverno(
	vaps []admissionregistrationv1.ValidatingAdmissionPolicy,
	bindings []admissionregistrationv1.ValidatingAdmissionPolicyBinding,
	opts VAPToKyvernoOptions,
) ([]kyverno.ValidatingPolicy, Report, error) {
	var rep Report

	byPolicy := map[string][]admissionregistrationv1.ValidatingAdmissionPolicyBinding{}
	known := make(map[string]struct{}, len(vaps))
	for _, vap := range vaps {
		known[vap.Name] = struct{}{}
	}
	for _, binding := range bindings {
		if _, ok := known[binding.Spec.PolicyName]; !ok {
			rep.Errorf(objectRef("ValidatingAdmissionPolicyBinding", "", binding.Name), "", "spec.policyName",
				"binding references policy %s, which is not in the input, so it was skipped; supply the policy or the converted output will not enforce it",
				binding.Spec.PolicyName)
			continue
		}
		byPolicy[binding.Spec.PolicyName] = append(byPolicy[binding.Spec.PolicyName], binding)
	}

	var out []kyverno.ValidatingPolicy
	for _, vap := range vaps {
		converted, sub, err := VAPToKyverno(vap, byPolicy[vap.Name], opts)
		rep.Notes = append(rep.Notes, sub.Notes...)
		if err != nil {
			rep.Errorf(objectRef("ValidatingAdmissionPolicy", "", vap.Name), "", "", "%v", err)
			continue
		}
		out = append(out, converted...)
	}

	if len(out) == 0 {
		return nil, rep, ErrNothingConverted
	}
	return out, rep, nil
}

// newBasePolicy builds the parts of a ValidatingPolicy that every binding of
// one source policy shares.
func newBasePolicy(
	vap admissionregistrationv1.ValidatingAdmissionPolicy,
	opts VAPToKyvernoOptions,
	rep *Report,
	source string,
) *kyverno.ValidatingPolicy {
	base := kyverno.New(vap.Name, opts.TargetAPIVersion)
	if opts.Namespace != "" {
		base = kyverno.NewNamespaced(vap.Name, opts.Namespace, opts.TargetAPIVersion)
	}

	base.Labels = copyStringMap(vap.Labels)

	annotations, annotationNotes := BridgeAnnotations(vap.Annotations, !opts.DropUnmappedAnnotations)
	base.Annotations = annotations
	rep.Absorb(annotationNotes, source, targetRef(&base))

	base.Spec = kyverno.ValidatingPolicySpec{
		MatchConstraints:  vap.Spec.MatchConstraints.DeepCopy(),
		MatchConditions:   copyMatchConditions(vap.Spec.MatchConditions),
		Variables:         copyVariables(vap.Spec.Variables),
		Validations:       copyValidations(vap.Spec.Validations),
		AuditAnnotations:  copyAuditAnnotations(vap.Spec.AuditAnnotations),
		FailurePolicy:     copyFailurePolicy(vap.Spec.FailurePolicy),
		ValidationActions: nil,
	}

	// spec.autogen is deliberately left unset. Kyverno auto-generates nothing
	// unless a policy opts in, so omitting it keeps the converted policy
	// matching exactly what the source ValidatingAdmissionPolicy matched.

	return &base
}

// convertBinding folds one binding into a copy of the base policy.
func convertBinding(
	base *kyverno.ValidatingPolicy,
	binding admissionregistrationv1.ValidatingAdmissionPolicyBinding,
	name string,
	defaultActions []admissionregistrationv1.ValidationAction,
	opts VAPToKyvernoOptions,
	rep *Report,
	source string,
) *kyverno.ValidatingPolicy {
	policy := base.DeepCopy()
	policy.Name = name
	target := targetRef(policy)

	merged, mergeNotes := MergeMatchConstraints(base.Spec.MatchConstraints, binding.Spec.MatchResources)
	policy.Spec.MatchConstraints = merged
	rep.Absorb(mergeNotes, source, target)

	if len(binding.Spec.ValidationActions) > 0 {
		policy.Spec.ValidationActions = append([]admissionregistrationv1.ValidationAction(nil), binding.Spec.ValidationActions...)
	} else {
		policy.Spec.ValidationActions = append([]admissionregistrationv1.ValidationAction(nil), defaultActions...)
		rep.Warnf(source, target, "spec.validationActions",
			"binding %s declares no validationActions; the converted policy uses %v",
			binding.Name, actionStrings(defaultActions))
	}

	if binding.Spec.ParamRef != nil {
		rep.Errorf(source, target, "spec.paramRef",
			"binding %s uses paramRef, which has no ValidatingPolicy equivalent, and it is dropped", binding.Name)
	}

	applyPolicyProvenance(policy, opts, source, binding.Name)
	return policy
}

func applyPolicyProvenance(policy *kyverno.ValidatingPolicy, opts VAPToKyvernoOptions, source, binding string) {
	if opts.OmitProvenance {
		return
	}
	policy.Annotations = applyProvenance(policy.Annotations, opts.tool(), source, binding)
}

// targetRef names a converted Kyverno policy for a Note's Target.
func targetRef(policy *kyverno.ValidatingPolicy) string {
	return objectRef(policy.Kind, policy.Namespace, policy.Name)
}

func vapHasStatus(vap admissionregistrationv1.ValidatingAdmissionPolicy) bool {
	return vap.Status.ObservedGeneration != 0 ||
		vap.Status.TypeChecking != nil ||
		len(vap.Status.Conditions) > 0
}

func actionStrings(in []admissionregistrationv1.ValidationAction) []string {
	out := make([]string, 0, len(in))
	for _, action := range in {
		out = append(out, string(action))
	}
	return out
}

func copyStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func copyMatchConditions(in []admissionregistrationv1.MatchCondition) []admissionregistrationv1.MatchCondition {
	if in == nil {
		return nil
	}
	out := make([]admissionregistrationv1.MatchCondition, len(in))
	copy(out, in)
	return out
}

func copyVariables(in []admissionregistrationv1.Variable) []admissionregistrationv1.Variable {
	if in == nil {
		return nil
	}
	out := make([]admissionregistrationv1.Variable, len(in))
	copy(out, in)
	return out
}

func copyValidations(in []admissionregistrationv1.Validation) []admissionregistrationv1.Validation {
	if in == nil {
		return nil
	}
	out := make([]admissionregistrationv1.Validation, len(in))
	for i := range in {
		in[i].DeepCopyInto(&out[i])
	}
	return out
}

func copyAuditAnnotations(in []admissionregistrationv1.AuditAnnotation) []admissionregistrationv1.AuditAnnotation {
	if in == nil {
		return nil
	}
	out := make([]admissionregistrationv1.AuditAnnotation, len(in))
	copy(out, in)
	return out
}

func copyFailurePolicy(in *admissionregistrationv1.FailurePolicyType) *admissionregistrationv1.FailurePolicyType {
	if in == nil {
		return nil
	}
	value := *in
	return &value
}
