// Copyright by cenroq AG
// Contact: info@cenroq.com

package convert_test

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cenroq/kubeapt/v2/pkg/convert"
	"github.com/cenroq/kubeapt/v2/pkg/kyverno"
	"github.com/cenroq/kubeapt/v2/pkg/policies"
)

// sampleVAP returns a small, complete ValidatingAdmissionPolicy.
func sampleVAP(name string) admissionregistrationv1.ValidatingAdmissionPolicy {
	failurePolicy := admissionregistrationv1.Fail
	return admissionregistrationv1.ValidatingAdmissionPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "admissionregistration.k8s.io/v1",
			Kind:       "ValidatingAdmissionPolicy",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Labels:      map[string]string{"team": "platform"},
			Annotations: map[string]string{policies.AnnotationDisplayName: "Require Labels"},
		},
		Spec: admissionregistrationv1.ValidatingAdmissionPolicySpec{
			FailurePolicy: &failurePolicy,
			MatchConstraints: &admissionregistrationv1.MatchResources{
				ResourceRules: []admissionregistrationv1.NamedRuleWithOperations{podsRule()},
			},
			MatchConditions: []admissionregistrationv1.MatchCondition{
				{Name: "skip-kube-system", Expression: `object.metadata.namespace != "kube-system"`},
			},
			Variables: []admissionregistrationv1.Variable{
				{Name: "labels", Expression: `object.metadata.?labels.orValue({})`},
			},
			Validations: []admissionregistrationv1.Validation{
				{Expression: `"environment" in variables.labels`, Message: "environment label is required"},
			},
			AuditAnnotations: []admissionregistrationv1.AuditAnnotation{
				{Key: "team", ValueExpression: `"platform"`},
			},
		},
	}
}

func sampleBinding(name, policyName string, actions ...admissionregistrationv1.ValidationAction) admissionregistrationv1.ValidatingAdmissionPolicyBinding {
	return admissionregistrationv1.ValidatingAdmissionPolicyBinding{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "admissionregistration.k8s.io/v1",
			Kind:       "ValidatingAdmissionPolicyBinding",
		},
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: admissionregistrationv1.ValidatingAdmissionPolicyBindingSpec{
			PolicyName:        policyName,
			ValidationActions: actions,
		},
	}
}

// noProvenance keeps generated annotations out of structural comparisons.
var noProvenance = convert.VAPToKyvernoOptions{OmitProvenance: true}

func TestVAPToKyvernoCopiesTheSharedSpec(t *testing.T) {
	vap := sampleVAP("require-labels")
	binding := sampleBinding("require-labels-binding", "require-labels", admissionregistrationv1.Deny)

	got, rep, err := convert.VAPToKyverno(vap, []admissionregistrationv1.ValidatingAdmissionPolicyBinding{binding}, noProvenance)
	if err != nil {
		t.Fatalf("VAPToKyverno: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d policies, want 1", len(got))
	}
	if rep.Has(convert.LevelError) {
		t.Errorf("clean conversion reported errors: %+v", rep.Notes)
	}

	policy := got[0]
	if policy.APIVersion != kyverno.APIVersionV1 || policy.Kind != kyverno.KindValidatingPolicy {
		t.Errorf("got %s %s, want %s %s", policy.APIVersion, policy.Kind, kyverno.APIVersionV1, kyverno.KindValidatingPolicy)
	}
	if policy.Name != "require-labels" {
		t.Errorf("got name %s, want require-labels", policy.Name)
	}
	if !reflect.DeepEqual(policy.Spec.MatchConditions, vap.Spec.MatchConditions) {
		t.Errorf("matchConditions not carried: %+v", policy.Spec.MatchConditions)
	}
	if !reflect.DeepEqual(policy.Spec.Variables, vap.Spec.Variables) {
		t.Errorf("variables not carried: %+v", policy.Spec.Variables)
	}
	if !reflect.DeepEqual(policy.Spec.Validations, vap.Spec.Validations) {
		t.Errorf("validations not carried: %+v", policy.Spec.Validations)
	}
	if !reflect.DeepEqual(policy.Spec.AuditAnnotations, vap.Spec.AuditAnnotations) {
		t.Errorf("auditAnnotations not carried: %+v", policy.Spec.AuditAnnotations)
	}
	if policy.Spec.FailurePolicy == nil || *policy.Spec.FailurePolicy != admissionregistrationv1.Fail {
		t.Errorf("failurePolicy not carried: %+v", policy.Spec.FailurePolicy)
	}
	if !reflect.DeepEqual(policy.Spec.ValidationActions, []admissionregistrationv1.ValidationAction{admissionregistrationv1.Deny}) {
		t.Errorf("got validationActions %v, want [Deny]", policy.Spec.ValidationActions)
	}
	if policy.Labels["team"] != "platform" {
		t.Errorf("labels not carried: %v", policy.Labels)
	}
	if policy.Spec.Autogen != nil {
		t.Errorf("autogen must stay unset so the converted scope matches the source: %+v", policy.Spec.Autogen)
	}
}

func TestVAPToKyvernoNoBindingsDefaultsToDeny(t *testing.T) {
	got, rep, err := convert.VAPToKyverno(sampleVAP("orphan"), nil, noProvenance)
	if err != nil {
		t.Fatalf("VAPToKyverno: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d policies, want 1", len(got))
	}
	if !reflect.DeepEqual(got[0].Spec.ValidationActions, []admissionregistrationv1.ValidationAction{admissionregistrationv1.Deny}) {
		t.Errorf("got validationActions %v, want [Deny]", got[0].Spec.ValidationActions)
	}
	if !hasNote(rep, convert.LevelWarn, "spec.validationActions", "inert in kubernetes") {
		t.Errorf("want a warn about the policy becoming active: %+v", rep.Notes)
	}
}

func TestVAPToKyvernoHonoursDefaultValidationActions(t *testing.T) {
	opts := convert.VAPToKyvernoOptions{
		OmitProvenance:           true,
		DefaultValidationActions: []admissionregistrationv1.ValidationAction{admissionregistrationv1.Audit, admissionregistrationv1.Warn},
	}
	got, _, err := convert.VAPToKyverno(sampleVAP("orphan"), nil, opts)
	if err != nil {
		t.Fatalf("VAPToKyverno: %v", err)
	}
	want := []admissionregistrationv1.ValidationAction{admissionregistrationv1.Audit, admissionregistrationv1.Warn}
	if !reflect.DeepEqual(got[0].Spec.ValidationActions, want) {
		t.Errorf("got %v, want %v", got[0].Spec.ValidationActions, want)
	}
}

func TestVAPToKyvernoBindingWithoutActionsWarns(t *testing.T) {
	binding := sampleBinding("b", "require-labels")
	_, rep, err := convert.VAPToKyverno(sampleVAP("require-labels"), []admissionregistrationv1.ValidatingAdmissionPolicyBinding{binding}, noProvenance)
	if err != nil {
		t.Fatalf("VAPToKyverno: %v", err)
	}
	if !hasNote(rep, convert.LevelWarn, "spec.validationActions", "declares no validationActions") {
		t.Errorf("want a warn about the defaulted actions: %+v", rep.Notes)
	}
}

func TestVAPToKyvernoMergesBindingMatchResources(t *testing.T) {
	binding := sampleBinding("prod-only", "require-labels", admissionregistrationv1.Deny)
	binding.Spec.MatchResources = &admissionregistrationv1.MatchResources{
		NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
	}

	got, _, err := convert.VAPToKyverno(sampleVAP("require-labels"), []admissionregistrationv1.ValidatingAdmissionPolicyBinding{binding}, noProvenance)
	if err != nil {
		t.Fatalf("VAPToKyverno: %v", err)
	}
	selector := got[0].Spec.MatchConstraints.NamespaceSelector
	if selector == nil || selector.MatchLabels["env"] != "prod" {
		t.Errorf("binding namespaceSelector was not folded into matchConstraints: %+v", got[0].Spec.MatchConstraints)
	}
	if len(got[0].Spec.MatchConstraints.ResourceRules) != 1 {
		t.Errorf("policy resourceRules lost: %+v", got[0].Spec.MatchConstraints.ResourceRules)
	}
}

func TestVAPToKyvernoSplitsMultipleBindings(t *testing.T) {
	vap := sampleVAP("require-labels")

	prod := sampleBinding("prod", "require-labels", admissionregistrationv1.Deny)
	prod.Spec.MatchResources = &admissionregistrationv1.MatchResources{
		NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
	}
	dev := sampleBinding("dev", "require-labels", admissionregistrationv1.Audit)
	dev.Spec.MatchResources = &admissionregistrationv1.MatchResources{
		NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "dev"}},
	}

	// Supplied out of order to pin the deterministic sort by binding name.
	got, rep, err := convert.VAPToKyverno(vap, []admissionregistrationv1.ValidatingAdmissionPolicyBinding{prod, dev}, noProvenance)
	if err != nil {
		t.Fatalf("VAPToKyverno: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d policies, want 2", len(got))
	}
	if got[0].Name != "require-labels-dev" || got[1].Name != "require-labels-prod" {
		t.Errorf("got names %s and %s, want require-labels-dev and require-labels-prod", got[0].Name, got[1].Name)
	}
	if got[0].Spec.ValidationActions[0] != admissionregistrationv1.Audit {
		t.Errorf("dev policy should keep Audit, got %v", got[0].Spec.ValidationActions)
	}
	if got[1].Spec.ValidationActions[0] != admissionregistrationv1.Deny {
		t.Errorf("prod policy should keep Deny, got %v", got[1].Spec.ValidationActions)
	}
	if !hasNote(rep, convert.LevelError, "", "cannot express that union") {
		t.Errorf("want a LevelError about the union split: %+v", rep.Notes)
	}

	// The split policies must not share mutable state.
	if got[0].Spec.MatchConstraints == got[1].Spec.MatchConstraints {
		t.Fatal("split policies share one MatchResources pointer")
	}
	got[0].Spec.MatchConstraints.NamespaceSelector.MatchLabels["env"] = "mutated"
	if got[1].Spec.MatchConstraints.NamespaceSelector.MatchLabels["env"] != "prod" {
		t.Error("split policies alias their namespaceSelector")
	}
	got[0].Spec.Validations[0].Message = "mutated"
	if got[1].Spec.Validations[0].Message == "mutated" {
		t.Error("split policies alias their validations")
	}
}

func TestVAPToKyvernoParamKindIsReportedButStillEmits(t *testing.T) {
	vap := sampleVAP("parameterized")
	vap.Spec.ParamKind = &admissionregistrationv1.ParamKind{APIVersion: "rules.example.com/v1", Kind: "ReplicaLimit"}

	got, rep, err := convert.VAPToKyverno(vap, nil, noProvenance)
	if err != nil {
		t.Fatalf("VAPToKyverno: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d policies, want 1; a paramKind policy must still be emitted", len(got))
	}
	if got[0].Spec.ParamKind != nil {
		t.Errorf("paramKind must not be emitted on a converted policy: %+v", got[0].Spec.ParamKind)
	}
	if !hasNote(rep, convert.LevelError, "spec.paramKind", "will not compile") {
		t.Errorf("want a LevelError naming the unbound params identifier: %+v", rep.Notes)
	}
}

func TestVAPToKyvernoBindingParamRefIsReported(t *testing.T) {
	binding := sampleBinding("b", "require-labels", admissionregistrationv1.Deny)
	binding.Spec.ParamRef = &admissionregistrationv1.ParamRef{Name: "limits"}

	_, rep, err := convert.VAPToKyverno(sampleVAP("require-labels"), []admissionregistrationv1.ValidatingAdmissionPolicyBinding{binding}, noProvenance)
	if err != nil {
		t.Fatalf("VAPToKyverno: %v", err)
	}
	if !hasNote(rep, convert.LevelError, "spec.paramRef", "is dropped") {
		t.Errorf("want a LevelError about the dropped paramRef: %+v", rep.Notes)
	}
}

func TestVAPToKyvernoNamespacedTarget(t *testing.T) {
	opts := convert.VAPToKyvernoOptions{OmitProvenance: true, Namespace: "production"}
	got, _, err := convert.VAPToKyverno(sampleVAP("require-labels"), nil, opts)
	if err != nil {
		t.Fatalf("VAPToKyverno: %v", err)
	}
	if !got[0].Namespaced() {
		t.Errorf("got kind %s, want %s", got[0].Kind, kyverno.KindNamespacedValidatingPolicy)
	}
	if got[0].Namespace != "production" {
		t.Errorf("got namespace %s, want production", got[0].Namespace)
	}
}

func TestVAPToKyvernoTargetAPIVersion(t *testing.T) {
	opts := convert.VAPToKyvernoOptions{OmitProvenance: true, TargetAPIVersion: kyverno.APIVersionV1Alpha1}
	got, _, err := convert.VAPToKyverno(sampleVAP("p"), nil, opts)
	if err != nil {
		t.Fatalf("VAPToKyverno: %v", err)
	}
	if got[0].APIVersion != kyverno.APIVersionV1Alpha1 {
		t.Errorf("got apiVersion %s, want %s", got[0].APIVersion, kyverno.APIVersionV1Alpha1)
	}
}

func TestVAPToKyvernoAnnotationsAndProvenance(t *testing.T) {
	vap := sampleVAP("require-labels")
	vap.Annotations = map[string]string{
		policies.AnnotationDisplayName: "Require Labels",
		policies.AnnotationSeverity:    "Critical",
		"team.example.com/owner":       "platform",
	}
	binding := sampleBinding("prod", "require-labels", admissionregistrationv1.Deny)

	got, _, err := convert.VAPToKyverno(vap, []admissionregistrationv1.ValidatingAdmissionPolicyBinding{binding},
		convert.VAPToKyvernoOptions{ProvenanceTool: "kubeapt/9.9.9"})
	if err != nil {
		t.Fatalf("VAPToKyverno: %v", err)
	}

	annotations := got[0].Annotations
	if annotations[policies.KyvernoAnnotationTitle] != "Require Labels" {
		t.Errorf("kyverno title not written: %v", annotations)
	}
	if annotations[policies.AnnotationSeverity] != "Critical" || annotations[policies.KyvernoAnnotationSeverity] != "high" {
		t.Errorf("severity not dual-emitted: %v", annotations)
	}
	if annotations["team.example.com/owner"] != "platform" {
		t.Errorf("unmapped annotation dropped: %v", annotations)
	}
	if annotations[convert.AnnotationConvertSource] != "ValidatingAdmissionPolicy/require-labels" {
		t.Errorf("got source %q, want ValidatingAdmissionPolicy/require-labels", annotations[convert.AnnotationConvertSource])
	}
	if annotations[convert.AnnotationConvertSourceBinding] != "prod" {
		t.Errorf("got source binding %q, want prod", annotations[convert.AnnotationConvertSourceBinding])
	}
	if annotations[convert.AnnotationConvertTool] != "kubeapt/9.9.9" {
		t.Errorf("got tool %q, want kubeapt/9.9.9", annotations[convert.AnnotationConvertTool])
	}

	omitted, _, err := convert.VAPToKyverno(vap, []admissionregistrationv1.ValidatingAdmissionPolicyBinding{binding}, noProvenance)
	if err != nil {
		t.Fatalf("VAPToKyverno: %v", err)
	}
	for _, key := range []string{convert.AnnotationConvertSource, convert.AnnotationConvertSourceBinding, convert.AnnotationConvertTool} {
		if _, ok := omitted[0].Annotations[key]; ok {
			t.Errorf("OmitProvenance did not suppress %s: %v", key, omitted[0].Annotations)
		}
	}
}

func TestVAPToKyvernoDropUnmappedAnnotations(t *testing.T) {
	vap := sampleVAP("p")
	vap.Annotations = map[string]string{
		policies.AnnotationDisplayName: "Kept",
		"team.example.com/owner":       "platform",
	}
	opts := convert.VAPToKyvernoOptions{OmitProvenance: true, DropUnmappedAnnotations: true}

	got, _, err := convert.VAPToKyverno(vap, nil, opts)
	if err != nil {
		t.Fatalf("VAPToKyverno: %v", err)
	}
	if _, ok := got[0].Annotations["team.example.com/owner"]; ok {
		t.Errorf("unmapped annotation should be dropped: %v", got[0].Annotations)
	}
	if got[0].Annotations[policies.AnnotationDisplayName] != "Kept" {
		t.Errorf("bridged annotation should survive: %v", got[0].Annotations)
	}
}

func TestVAPToKyvernoNoValidationsWarns(t *testing.T) {
	vap := sampleVAP("empty")
	vap.Spec.Validations = nil
	_, rep, err := convert.VAPToKyverno(vap, nil, noProvenance)
	if err != nil {
		t.Fatalf("VAPToKyverno: %v", err)
	}
	if !hasNote(rep, convert.LevelWarn, "spec.validations", "declares no validations") {
		t.Errorf("want a warn about the empty validations: %+v", rep.Notes)
	}
}

func TestVAPToKyvernoStatusIsReported(t *testing.T) {
	vap := sampleVAP("observed")
	vap.Status.ObservedGeneration = 3
	_, rep, err := convert.VAPToKyverno(vap, nil, noProvenance)
	if err != nil {
		t.Fatalf("VAPToKyverno: %v", err)
	}
	if !hasNote(rep, convert.LevelInfo, "status", "not carried") {
		t.Errorf("want an info note about the dropped status: %+v", rep.Notes)
	}
}

func TestVAPToKyvernoLongNamesAreTruncatedDeterministically(t *testing.T) {
	long := strings.Repeat("a", 200)
	vap := sampleVAP(long)
	first := sampleBinding(strings.Repeat("b", 200), long, admissionregistrationv1.Deny)
	second := sampleBinding(strings.Repeat("c", 200), long, admissionregistrationv1.Deny)

	got, _, err := convert.VAPToKyverno(vap, []admissionregistrationv1.ValidatingAdmissionPolicyBinding{first, second}, noProvenance)
	if err != nil {
		t.Fatalf("VAPToKyverno: %v", err)
	}
	for _, policy := range got {
		if len(policy.Name) > 253 {
			t.Errorf("name is %d chars, want at most 253", len(policy.Name))
		}
		if strings.HasSuffix(policy.Name, "-") || strings.HasSuffix(policy.Name, ".") {
			t.Errorf("name %q ends with a separator", policy.Name)
		}
	}
	if got[0].Name == got[1].Name {
		t.Error("distinct bindings produced the same truncated name")
	}

	again, _, err := convert.VAPToKyverno(vap, []admissionregistrationv1.ValidatingAdmissionPolicyBinding{first, second}, noProvenance)
	if err != nil {
		t.Fatalf("VAPToKyverno: %v", err)
	}
	if again[0].Name != got[0].Name || again[1].Name != got[1].Name {
		t.Error("truncated names are not stable across runs")
	}
}

func TestVAPSetToKyverno(t *testing.T) {
	first := sampleVAP("first")
	second := sampleVAP("second")
	bindings := []admissionregistrationv1.ValidatingAdmissionPolicyBinding{
		sampleBinding("second-binding", "second", admissionregistrationv1.Audit),
		sampleBinding("first-binding", "first", admissionregistrationv1.Deny),
		sampleBinding("orphan-binding", "missing", admissionregistrationv1.Deny),
	}

	got, rep, err := convert.VAPSetToKyverno(
		[]admissionregistrationv1.ValidatingAdmissionPolicy{first, second}, bindings, noProvenance)
	if err != nil {
		t.Fatalf("VAPSetToKyverno: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d policies, want 2", len(got))
	}
	if got[0].Name != "first" || got[1].Name != "second" {
		t.Errorf("output should follow input policy order, got %s and %s", got[0].Name, got[1].Name)
	}
	if got[0].Spec.ValidationActions[0] != admissionregistrationv1.Deny {
		t.Errorf("first policy got %v, want Deny", got[0].Spec.ValidationActions)
	}
	if got[1].Spec.ValidationActions[0] != admissionregistrationv1.Audit {
		t.Errorf("second policy got %v, want Audit", got[1].Spec.ValidationActions)
	}
	if !hasNote(rep, convert.LevelError, "spec.policyName", "which is not in the input") {
		t.Errorf("want a LevelError about the orphan binding: %+v", rep.Notes)
	}
}

func TestVAPSetToKyvernoNothingConverted(t *testing.T) {
	_, _, err := convert.VAPSetToKyverno(nil, nil, noProvenance)
	if !errors.Is(err, convert.ErrNothingConverted) {
		t.Fatalf("got err %v, want ErrNothingConverted", err)
	}
}

// hasNote reports whether the report holds a note of the given level whose
// Field matches and whose Message contains the substring.
func hasNote(rep convert.Report, level convert.Level, field, contains string) bool {
	for _, note := range rep.Notes {
		if note.Level != level || note.Field != field {
			continue
		}
		if strings.Contains(note.Message, contains) {
			return true
		}
	}
	return false
}
