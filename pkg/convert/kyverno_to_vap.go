// Copyright by cenroq AG
// Contact: info@cenroq.com

package convert

import (
	"fmt"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/cenroq/kubeapt/v2/pkg/kyverno"
)

// vapAPIVersion is the group and version of the emitted Kubernetes objects.
const vapAPIVersion = "admissionregistration.k8s.io/v1"

// namespaceNameLabel is set on every namespace by the API server since
// Kubernetes 1.21, which is what lets a binding pin a policy to one namespace.
const namespaceNameLabel = "kubernetes.io/metadata.name"

// defaultBindingNameSuffix names the binding synthesized for a Kyverno policy.
const defaultBindingNameSuffix = "binding"

// KyvernoToVAPOptions tunes Kyverno to ValidatingAdmissionPolicy conversion.
// The zero value is valid and behaves as the documented defaults.
type KyvernoToVAPOptions struct {
	// BindingNameSuffix is appended to the policy name to name the synthesized
	// binding. An empty value means "binding".
	BindingNameSuffix string
	// DefaultValidationActions applies when spec.validationActions is empty. A
	// nil value means Deny.
	DefaultValidationActions []admissionregistrationv1.ValidationAction
	// AllowKyvernoCELExtensions downgrades Kyverno-only CEL findings from
	// LevelError to LevelWarn, for callers who intend to hand-edit the result.
	AllowKyvernoCELExtensions bool
	// ProvenanceTool identifies the converter in the convert.kubeapt.io/tool
	// annotation. An empty value means "kubeapt".
	ProvenanceTool string
	// OmitProvenance suppresses the convert.kubeapt.io/* annotations.
	OmitProvenance bool
	// DropUnmappedAnnotations discards source annotations that have no mapping
	// instead of copying them through.
	DropUnmappedAnnotations bool
}

func (o KyvernoToVAPOptions) actions() []admissionregistrationv1.ValidationAction {
	if len(o.DefaultValidationActions) == 0 {
		return []admissionregistrationv1.ValidationAction{admissionregistrationv1.Deny}
	}
	return append([]admissionregistrationv1.ValidationAction(nil), o.DefaultValidationActions...)
}

func (o KyvernoToVAPOptions) bindingSuffix() string {
	if o.BindingNameSuffix == "" {
		return defaultBindingNameSuffix
	}
	return o.BindingNameSuffix
}

func (o KyvernoToVAPOptions) tool() string {
	if o.ProvenanceTool == "" {
		return defaultProvenanceTool
	}
	return o.ProvenanceTool
}

// KyvernoToVAP converts one Kyverno ValidatingPolicy or
// NamespacedValidatingPolicy into a ValidatingAdmissionPolicy and the
// ValidatingAdmissionPolicyBinding that activates it, because Kyverno folds the
// binding's role into the policy itself.
//
// It returns an error, emitting nothing, only for inputs a
// ValidatingAdmissionPolicy cannot represent at all: an evaluation mode of JSON
// or Envoy, and a NamespacedValidatingPolicy with no metadata.namespace.
// Everything else converts, with a Report describing what changed.
func KyvernoToVAP(policy kyverno.ValidatingPolicy, opts KyvernoToVAPOptions) (
	admissionregistrationv1.ValidatingAdmissionPolicy,
	admissionregistrationv1.ValidatingAdmissionPolicyBinding,
	Report, error) {
	var (
		zeroVAP     admissionregistrationv1.ValidatingAdmissionPolicy
		zeroBinding admissionregistrationv1.ValidatingAdmissionPolicyBinding
		rep         Report
	)

	source := objectRef(policy.Kind, policy.Namespace, policy.Name)

	if group := schema.FromAPIVersionAndKind(policy.APIVersion, policy.Kind).Group; group != kyverno.GroupName {
		return zeroVAP, zeroBinding, rep, fmt.Errorf("convert: %s is not a %s policy", source, kyverno.GroupName)
	}
	if !kyverno.IsKnownAPIVersion(policy.APIVersion) {
		rep.Warnf(source, "", "apiVersion",
			"apiVersion %s is not one kubeapt has verified; the document was read with the %s field set and any unknown fields were ignored",
			policy.APIVersion, kyverno.APIVersionV1)
	}

	if err := checkEvaluation(policy, &rep, source); err != nil {
		return zeroVAP, zeroBinding, rep, err
	}
	if policy.Spec.Autogen != nil {
		rep.Warnf(source, "", "spec.autogen",
			"autogen has no ValidatingAdmissionPolicy equivalent and is dropped; any pod-controller rules kyverno generated from this policy are not reproduced")
	}
	if policy.Spec.WebhookConfiguration != nil {
		rep.Warnf(source, "", "spec.webhookConfiguration",
			"webhookConfiguration has no ValidatingAdmissionPolicy equivalent and is dropped")
	}
	if len(policy.Status) > 0 {
		rep.Infof(source, "", "status", "status is not carried into the converted policy")
	}

	reportCELExtensions(policy, opts, &rep, source)

	target := objectRef("ValidatingAdmissionPolicy", "", policy.Name)

	annotations, annotationNotes := BridgeAnnotations(policy.Annotations, !opts.DropUnmappedAnnotations)
	rep.Absorb(annotationNotes, source, target)

	vap := admissionregistrationv1.ValidatingAdmissionPolicy{
		TypeMeta: metav1.TypeMeta{APIVersion: vapAPIVersion, Kind: "ValidatingAdmissionPolicy"},
		ObjectMeta: metav1.ObjectMeta{
			Name:        policy.Name,
			Labels:      copyStringMap(policy.Labels),
			Annotations: annotations,
		},
		Spec: admissionregistrationv1.ValidatingAdmissionPolicySpec{
			MatchConstraints: policy.Spec.MatchConstraints.DeepCopy(),
			MatchConditions:  copyMatchConditions(policy.Spec.MatchConditions),
			Variables:        copyVariables(policy.Spec.Variables),
			Validations:      copyValidations(policy.Spec.Validations),
			AuditAnnotations: copyAuditAnnotations(policy.Spec.AuditAnnotations),
			FailurePolicy:    copyFailurePolicy(policy.Spec.FailurePolicy),
			ParamKind:        policy.Spec.ParamKind.DeepCopy(),
		},
	}
	if policy.Spec.ParamKind != nil {
		rep.Infof(source, target, "spec.paramKind",
			"mapped from the %s paramKind field, which the current kyverno schema no longer documents", kyverno.APIVersionV1Alpha1)
	}

	bindingMatch, err := namespacePin(policy, &vap, &rep, source, target)
	if err != nil {
		return zeroVAP, zeroBinding, rep, err
	}

	binding := admissionregistrationv1.ValidatingAdmissionPolicyBinding{
		TypeMeta:   metav1.TypeMeta{APIVersion: vapAPIVersion, Kind: "ValidatingAdmissionPolicyBinding"},
		ObjectMeta: metav1.ObjectMeta{Name: derivedName(policy.Name, opts.bindingSuffix())},
		Spec: admissionregistrationv1.ValidatingAdmissionPolicyBindingSpec{
			PolicyName:     policy.Name,
			MatchResources: bindingMatch,
			ParamRef:       policy.Spec.ParamRef.DeepCopy(),
		},
	}
	if policy.Spec.ParamRef != nil {
		rep.Infof(source, target, "spec.paramRef",
			"mapped onto the synthesized binding, where kubernetes expects it")
	}

	if len(policy.Spec.ValidationActions) > 0 {
		binding.Spec.ValidationActions = append([]admissionregistrationv1.ValidationAction(nil), policy.Spec.ValidationActions...)
	} else {
		binding.Spec.ValidationActions = opts.actions()
		rep.Warnf(source, target, "spec.validationActions",
			"policy declares no validationActions; the synthesized binding uses %v", actionStrings(binding.Spec.ValidationActions))
	}

	if !opts.OmitProvenance {
		vap.Annotations = applyProvenance(vap.Annotations, opts.tool(), source, "")
	}

	return vap, binding, rep, nil
}

// KyvernoSetToVAP converts many policies, returning parallel slices in input
// order. A policy that cannot be converted is recorded as a LevelError note
// with an empty Target and skipped. The error is non-nil only when no policy
// converted.
func KyvernoSetToVAP(policies []kyverno.ValidatingPolicy, opts KyvernoToVAPOptions) (
	[]admissionregistrationv1.ValidatingAdmissionPolicy,
	[]admissionregistrationv1.ValidatingAdmissionPolicyBinding,
	Report, error) {
	var (
		vaps     []admissionregistrationv1.ValidatingAdmissionPolicy
		bindings []admissionregistrationv1.ValidatingAdmissionPolicyBinding
		rep      Report
	)

	for _, policy := range policies {
		vap, binding, sub, err := KyvernoToVAP(policy, opts)
		rep.Notes = append(rep.Notes, sub.Notes...)
		if err != nil {
			rep.Errorf(objectRef(policy.Kind, policy.Namespace, policy.Name), "", "", "%v", err)
			continue
		}
		vaps = append(vaps, vap)
		bindings = append(bindings, binding)
	}

	if len(vaps) == 0 {
		return nil, nil, rep, ErrNothingConverted
	}
	return vaps, bindings, rep, nil
}

// checkEvaluation rejects the evaluation modes a ValidatingAdmissionPolicy
// cannot represent and reports the settings it silently loses.
func checkEvaluation(policy kyverno.ValidatingPolicy, rep *Report, source string) error {
	evaluation := policy.Spec.Evaluation
	if evaluation == nil {
		return nil
	}

	switch evaluation.Mode {
	case "", kyverno.EvaluationModeKubernetes:
	case kyverno.EvaluationModeJSON, kyverno.EvaluationModeEnvoy:
		return fmt.Errorf("%w: %s uses evaluation mode %s, which evaluates a payload a ValidatingAdmissionPolicy cannot receive",
			ErrUnsupportedEvaluationMode, source, evaluation.Mode)
	default:
		rep.Warnf(source, "", "spec.evaluation.mode",
			"evaluation mode %s is not one kubeapt recognizes; the policy was converted as if it were %s",
			evaluation.Mode, kyverno.EvaluationModeKubernetes)
	}

	if evaluation.Admission != nil && evaluation.Admission.Enabled != nil && !*evaluation.Admission.Enabled {
		rep.Errorf(source, "", "spec.evaluation.admission.enabled",
			"admission evaluation is disabled on the source policy, but a ValidatingAdmissionPolicy only runs at admission, so the converted policy enforces where the source did not")
	}
	if evaluation.Background != nil {
		rep.Warnf(source, "", "spec.evaluation.background",
			"background scanning has no ValidatingAdmissionPolicy equivalent and is dropped")
	}
	return nil
}

// reportCELExtensions records every Kyverno-only CEL call in the policy.
func reportCELExtensions(policy kyverno.ValidatingPolicy, opts KyvernoToVAPOptions, rep *Report, source string) {
	for _, finding := range DetectInSpec(policy.Spec) {
		level := finding.Extension.Level
		if opts.AllowKyvernoCELExtensions && level == LevelError {
			level = LevelWarn
		}
		rep.Add(level, source, "", finding.Field,
			"expression calls kyverno's %s, which the kubernetes api server cannot compile; %s",
			finding.Extension.Name, finding.Extension.Hint)
	}
}

// namespacePin builds the binding matchResources that scopes a converted
// NamespacedValidatingPolicy to its namespace.
//
// The pin goes on the binding rather than on the policy's matchConstraints
// because Kubernetes puts scope selection in the binding. That keeps the
// converted policy reusable from another binding, and it is what lets a
// Kyverno round trip recover the pin, since converting back merges a binding's
// matchResources into matchConstraints.
func namespacePin(
	policy kyverno.ValidatingPolicy,
	vap *admissionregistrationv1.ValidatingAdmissionPolicy,
	rep *Report,
	source, target string,
) (*admissionregistrationv1.MatchResources, error) {
	if !policy.Namespaced() {
		return nil, nil
	}
	if policy.Namespace == "" {
		return nil, fmt.Errorf("%w: %s", ErrMissingNamespace, source)
	}

	rep.Warnf(source, target, "metadata.namespace",
		"a ValidatingAdmissionPolicy is cluster-scoped, so the synthesized binding pins it to namespace %s with the %s label",
		policy.Namespace, namespaceNameLabel)

	if vap.Spec.MatchConstraints != nil {
		for _, rule := range vap.Spec.MatchConstraints.ResourceRules {
			if rule.Scope != nil && *rule.Scope == admissionregistrationv1.ClusterScope {
				rep.Errorf(source, target, "spec.matchConstraints.resourceRules",
					"a rule targets cluster-scoped resources, which a namespaceSelector cannot restrict, so the converted policy validates them in every namespace")
				break
			}
		}
	}

	return &admissionregistrationv1.MatchResources{
		NamespaceSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{namespaceNameLabel: policy.Namespace},
		},
	}, nil
}
