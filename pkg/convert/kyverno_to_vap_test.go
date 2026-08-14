// Copyright by cenroq AG
// Contact: info@cenroq.com

package convert_test

import (
	"errors"
	"reflect"
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cenroq/kubeapt/v2/pkg/convert"
	"github.com/cenroq/kubeapt/v2/pkg/kyverno"
	"github.com/cenroq/kubeapt/v2/pkg/policies"
)

// sampleKyverno returns a small, complete cluster-scoped ValidatingPolicy.
func sampleKyverno(name string) kyverno.ValidatingPolicy {
	failurePolicy := admissionregistrationv1.Fail
	policy := kyverno.New(name, "")
	policy.Labels = map[string]string{"team": "platform"}
	policy.Annotations = map[string]string{policies.KyvernoAnnotationTitle: "Check Labels"}
	policy.Spec = kyverno.ValidatingPolicySpec{
		MatchConstraints: &admissionregistrationv1.MatchResources{
			ResourceRules: []admissionregistrationv1.NamedRuleWithOperations{podsRule()},
		},
		MatchConditions: []admissionregistrationv1.MatchCondition{
			{Name: "skip-kube-system", Expression: `object.metadata.namespace != "kube-system"`},
		},
		Variables:         []admissionregistrationv1.Variable{{Name: "labels", Expression: `object.metadata.?labels.orValue({})`}},
		Validations:       []admissionregistrationv1.Validation{{Expression: `"environment" in variables.labels`, Message: "required"}},
		AuditAnnotations:  []admissionregistrationv1.AuditAnnotation{{Key: "team", ValueExpression: `"platform"`}},
		FailurePolicy:     &failurePolicy,
		ValidationActions: []admissionregistrationv1.ValidationAction{admissionregistrationv1.Deny},
	}
	return policy
}

var noProvenanceToVAP = convert.KyvernoToVAPOptions{OmitProvenance: true}

func TestKyvernoToVAPSynthesizesABinding(t *testing.T) {
	policy := sampleKyverno("check-labels")

	vap, binding, rep, err := convert.KyvernoToVAP(policy, noProvenanceToVAP)
	if err != nil {
		t.Fatalf("KyvernoToVAP: %v", err)
	}
	if rep.Has(convert.LevelError) {
		t.Errorf("clean conversion reported errors: %+v", rep.Notes)
	}

	if vap.APIVersion != "admissionregistration.k8s.io/v1" || vap.Kind != "ValidatingAdmissionPolicy" {
		t.Errorf("got %s %s", vap.APIVersion, vap.Kind)
	}
	if vap.Name != "check-labels" {
		t.Errorf("got name %s, want check-labels", vap.Name)
	}
	if !reflect.DeepEqual(vap.Spec.MatchConditions, policy.Spec.MatchConditions) {
		t.Errorf("matchConditions not carried: %+v", vap.Spec.MatchConditions)
	}
	if !reflect.DeepEqual(vap.Spec.Validations, policy.Spec.Validations) {
		t.Errorf("validations not carried: %+v", vap.Spec.Validations)
	}
	if vap.Labels["team"] != "platform" {
		t.Errorf("labels not carried: %v", vap.Labels)
	}
	if vap.Annotations[policies.AnnotationDisplayName] != "Check Labels" {
		t.Errorf("kyverno title did not map to displayName: %v", vap.Annotations)
	}

	if binding.Kind != "ValidatingAdmissionPolicyBinding" {
		t.Errorf("got binding kind %s", binding.Kind)
	}
	if binding.Name != "check-labels-binding" {
		t.Errorf("got binding name %s, want check-labels-binding", binding.Name)
	}
	if binding.Spec.PolicyName != "check-labels" {
		t.Errorf("got policyName %s, want check-labels", binding.Spec.PolicyName)
	}
	if binding.Spec.MatchResources != nil {
		t.Errorf("a cluster-scoped policy needs no binding matchResources: %+v", binding.Spec.MatchResources)
	}
	if !reflect.DeepEqual(binding.Spec.ValidationActions, []admissionregistrationv1.ValidationAction{admissionregistrationv1.Deny}) {
		t.Errorf("got validationActions %v, want [Deny]", binding.Spec.ValidationActions)
	}
}

func TestKyvernoToVAPCustomBindingSuffix(t *testing.T) {
	opts := convert.KyvernoToVAPOptions{OmitProvenance: true, BindingNameSuffix: "prod"}
	_, binding, _, err := convert.KyvernoToVAP(sampleKyverno("p"), opts)
	if err != nil {
		t.Fatalf("KyvernoToVAP: %v", err)
	}
	if binding.Name != "p-prod" {
		t.Errorf("got binding name %s, want p-prod", binding.Name)
	}
}

func TestKyvernoToVAPNoActionsDefaultsToDeny(t *testing.T) {
	policy := sampleKyverno("p")
	policy.Spec.ValidationActions = nil

	_, binding, rep, err := convert.KyvernoToVAP(policy, noProvenanceToVAP)
	if err != nil {
		t.Fatalf("KyvernoToVAP: %v", err)
	}
	if !reflect.DeepEqual(binding.Spec.ValidationActions, []admissionregistrationv1.ValidationAction{admissionregistrationv1.Deny}) {
		t.Errorf("got %v, want [Deny]", binding.Spec.ValidationActions)
	}
	if !hasNote(rep, convert.LevelWarn, "spec.validationActions", "synthesized binding uses") {
		t.Errorf("want a warn about the defaulted actions: %+v", rep.Notes)
	}
}

func TestKyvernoToVAPNamespacedPolicyPinsTheBinding(t *testing.T) {
	policy := sampleKyverno("check-replicas")
	policy.Kind = kyverno.KindNamespacedValidatingPolicy
	policy.Namespace = "production"

	_, binding, rep, err := convert.KyvernoToVAP(policy, noProvenanceToVAP)
	if err != nil {
		t.Fatalf("KyvernoToVAP: %v", err)
	}
	if binding.Spec.MatchResources == nil || binding.Spec.MatchResources.NamespaceSelector == nil {
		t.Fatalf("want a namespace pin on the binding: %+v", binding.Spec.MatchResources)
	}
	got := binding.Spec.MatchResources.NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"]
	if got != "production" {
		t.Errorf("got pin %q, want production", got)
	}
	if !hasNote(rep, convert.LevelWarn, "metadata.namespace", "cluster-scoped") {
		t.Errorf("want a warn explaining the pin: %+v", rep.Notes)
	}
}

func TestKyvernoToVAPNamespacedPolicyWithClusterScopedRule(t *testing.T) {
	policy := sampleKyverno("p")
	policy.Kind = kyverno.KindNamespacedValidatingPolicy
	policy.Namespace = "production"
	clusterRule := podsRule()
	clusterRule.Scope = scopePtr(admissionregistrationv1.ClusterScope)
	policy.Spec.MatchConstraints.ResourceRules = []admissionregistrationv1.NamedRuleWithOperations{clusterRule}

	_, _, rep, err := convert.KyvernoToVAP(policy, noProvenanceToVAP)
	if err != nil {
		t.Fatalf("KyvernoToVAP: %v", err)
	}
	if !hasNote(rep, convert.LevelError, "spec.matchConstraints.resourceRules", "every namespace") {
		t.Errorf("want a LevelError about the unrestrictable cluster scope: %+v", rep.Notes)
	}
}

func TestKyvernoToVAPNamespacedPolicyWithoutNamespace(t *testing.T) {
	policy := sampleKyverno("p")
	policy.Kind = kyverno.KindNamespacedValidatingPolicy

	_, _, _, err := convert.KyvernoToVAP(policy, noProvenanceToVAP)
	if !errors.Is(err, convert.ErrMissingNamespace) {
		t.Fatalf("got err %v, want ErrMissingNamespace", err)
	}
}

func TestKyvernoToVAPEvaluationModes(t *testing.T) {
	cases := []struct {
		name    string
		mode    kyverno.EvaluationMode
		wantErr bool
		wantMsg string
	}{
		{name: "unset"},
		{name: "kubernetes", mode: kyverno.EvaluationModeKubernetes},
		{name: "json", mode: kyverno.EvaluationModeJSON, wantErr: true},
		{name: "envoy", mode: kyverno.EvaluationModeEnvoy, wantErr: true},
		{name: "unknown", mode: "Wasm", wantMsg: "is not one kubeapt recognizes"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policy := sampleKyverno("p")
			policy.Spec.Evaluation = &kyverno.EvaluationConfiguration{Mode: tc.mode}

			_, _, rep, err := convert.KyvernoToVAP(policy, noProvenanceToVAP)
			if tc.wantErr {
				if !errors.Is(err, convert.ErrUnsupportedEvaluationMode) {
					t.Fatalf("got err %v, want ErrUnsupportedEvaluationMode", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("KyvernoToVAP: %v", err)
			}
			if tc.wantMsg != "" && !hasNote(rep, convert.LevelWarn, "spec.evaluation.mode", tc.wantMsg) {
				t.Errorf("want a warn about the unknown mode: %+v", rep.Notes)
			}
		})
	}
}

func TestKyvernoToVAPDisabledAdmissionIsAnError(t *testing.T) {
	disabled := false
	policy := sampleKyverno("p")
	policy.Spec.Evaluation = &kyverno.EvaluationConfiguration{
		Admission: &kyverno.AdmissionConfiguration{Enabled: &disabled},
	}

	_, _, rep, err := convert.KyvernoToVAP(policy, noProvenanceToVAP)
	if err != nil {
		t.Fatalf("KyvernoToVAP: %v", err)
	}
	if !hasNote(rep, convert.LevelError, "spec.evaluation.admission.enabled", "enforces where the source did not") {
		t.Errorf("want a LevelError about the enforcement change: %+v", rep.Notes)
	}
}

func TestKyvernoToVAPDropsKyvernoOnlyStanzas(t *testing.T) {
	enabled := true
	timeout := int32(15)
	policy := sampleKyverno("p")
	policy.Spec.Evaluation = &kyverno.EvaluationConfiguration{
		Background: &kyverno.BackgroundConfiguration{Enabled: &enabled},
	}
	policy.Spec.Autogen = &kyverno.AutogenConfiguration{
		PodControllers: &kyverno.PodControllersGenerationConfiguration{Controllers: []string{"deployments"}},
	}
	policy.Spec.WebhookConfiguration = &kyverno.WebhookConfiguration{TimeoutSeconds: &timeout}
	policy.Status = []byte(`{"conditionStatus":{}}`)

	vap, _, rep, err := convert.KyvernoToVAP(policy, noProvenanceToVAP)
	if err != nil {
		t.Fatalf("KyvernoToVAP: %v", err)
	}
	for _, want := range []struct {
		level Level
		field string
		text  string
	}{
		{convert.LevelWarn, "spec.evaluation.background", "background scanning"},
		{convert.LevelWarn, "spec.autogen", "no ValidatingAdmissionPolicy equivalent"},
		{convert.LevelWarn, "spec.webhookConfiguration", "no ValidatingAdmissionPolicy equivalent"},
		{convert.LevelInfo, "status", "not carried"},
	} {
		if !hasNote(rep, want.level, want.field, want.text) {
			t.Errorf("want a %s note on %s: %+v", want.level, want.field, rep.Notes)
		}
	}
	if vap.Status.TypeChecking != nil || vap.Status.ObservedGeneration != 0 || len(vap.Status.Conditions) > 0 {
		t.Errorf("status leaked into the converted policy: %+v", vap.Status)
	}
}

// Level aliases convert.Level so the table above reads cleanly.
type Level = convert.Level

func TestKyvernoToVAPMapsParamFields(t *testing.T) {
	policy := sampleKyverno("p")
	policy.APIVersion = kyverno.APIVersionV1Alpha1
	policy.Spec.ParamKind = &admissionregistrationv1.ParamKind{APIVersion: "rules.example.com/v1", Kind: "Limit"}
	policy.Spec.ParamRef = &admissionregistrationv1.ParamRef{Name: "limits"}

	vap, binding, rep, err := convert.KyvernoToVAP(policy, noProvenanceToVAP)
	if err != nil {
		t.Fatalf("KyvernoToVAP: %v", err)
	}
	if vap.Spec.ParamKind == nil || vap.Spec.ParamKind.Kind != "Limit" {
		t.Errorf("paramKind not mapped onto the policy: %+v", vap.Spec.ParamKind)
	}
	if binding.Spec.ParamRef == nil || binding.Spec.ParamRef.Name != "limits" {
		t.Errorf("paramRef not mapped onto the binding: %+v", binding.Spec.ParamRef)
	}
	if !hasNote(rep, convert.LevelInfo, "spec.paramKind", "mapped from") {
		t.Errorf("want an info note about the paramKind mapping: %+v", rep.Notes)
	}
}

func TestKyvernoToVAPReportsKyvernoCEL(t *testing.T) {
	policy := sampleKyverno("p")
	policy.Spec.Validations = []admissionregistrationv1.Validation{
		{Expression: `http.Get("https://example.internal").ok`},
	}

	_, _, rep, err := convert.KyvernoToVAP(policy, noProvenanceToVAP)
	if err != nil {
		t.Fatalf("KyvernoToVAP: %v", err)
	}
	if !hasNote(rep, convert.LevelError, "spec.validations[0].expression", "http.Get") {
		t.Errorf("want a LevelError about the kyverno-only call: %+v", rep.Notes)
	}

	opts := convert.KyvernoToVAPOptions{OmitProvenance: true, AllowKyvernoCELExtensions: true}
	_, _, rep, err = convert.KyvernoToVAP(policy, opts)
	if err != nil {
		t.Fatalf("KyvernoToVAP: %v", err)
	}
	if rep.Has(convert.LevelError) {
		t.Errorf("AllowKyvernoCELExtensions should downgrade to a warn: %+v", rep.Notes)
	}
	if !hasNote(rep, convert.LevelWarn, "spec.validations[0].expression", "http.Get") {
		t.Errorf("want a downgraded warn: %+v", rep.Notes)
	}
}

func TestKyvernoToVAPUnknownAPIVersionWarns(t *testing.T) {
	policy := sampleKyverno("p")
	policy.APIVersion = "policies.kyverno.io/v1beta1"

	_, _, rep, err := convert.KyvernoToVAP(policy, noProvenanceToVAP)
	if err != nil {
		t.Fatalf("KyvernoToVAP: %v", err)
	}
	if !hasNote(rep, convert.LevelWarn, "apiVersion", "not one kubeapt has verified") {
		t.Errorf("want a warn about the unverified apiVersion: %+v", rep.Notes)
	}
}

func TestKyvernoToVAPRejectsForeignGroup(t *testing.T) {
	policy := sampleKyverno("p")
	policy.APIVersion = "example.com/v1"

	_, _, _, err := convert.KyvernoToVAP(policy, noProvenanceToVAP)
	if err == nil {
		t.Fatal("expected an error for a non-kyverno group")
	}
}

func TestKyvernoToVAPProvenance(t *testing.T) {
	vap, _, _, err := convert.KyvernoToVAP(sampleKyverno("p"),
		convert.KyvernoToVAPOptions{ProvenanceTool: "kubeapt/9.9.9"})
	if err != nil {
		t.Fatalf("KyvernoToVAP: %v", err)
	}
	if vap.Annotations[convert.AnnotationConvertSource] != "ValidatingPolicy/p" {
		t.Errorf("got source %q, want ValidatingPolicy/p", vap.Annotations[convert.AnnotationConvertSource])
	}
	if vap.Annotations[convert.AnnotationConvertTool] != "kubeapt/9.9.9" {
		t.Errorf("got tool %q, want kubeapt/9.9.9", vap.Annotations[convert.AnnotationConvertTool])
	}
	if _, ok := vap.Annotations[convert.AnnotationConvertSourceBinding]; ok {
		t.Errorf("kyverno has no binding, so none should be recorded: %v", vap.Annotations)
	}
}

func TestKyvernoSetToVAP(t *testing.T) {
	good := sampleKyverno("good")
	bad := sampleKyverno("bad")
	bad.Spec.Evaluation = &kyverno.EvaluationConfiguration{Mode: kyverno.EvaluationModeJSON}
	second := sampleKyverno("second")

	vaps, bindings, rep, err := convert.KyvernoSetToVAP(
		[]kyverno.ValidatingPolicy{good, bad, second}, noProvenanceToVAP)
	if err != nil {
		t.Fatalf("KyvernoSetToVAP: %v", err)
	}
	if len(vaps) != 2 || len(bindings) != 2 {
		t.Fatalf("got %d policies and %d bindings, want 2 and 2", len(vaps), len(bindings))
	}
	if vaps[0].Name != "good" || vaps[1].Name != "second" {
		t.Errorf("got %s and %s, want good and second in input order", vaps[0].Name, vaps[1].Name)
	}
	if bindings[0].Spec.PolicyName != "good" || bindings[1].Spec.PolicyName != "second" {
		t.Error("bindings are not parallel to the policies")
	}

	var sawSkip bool
	for _, note := range rep.Notes {
		if note.Level == convert.LevelError && note.Source == "ValidatingPolicy/bad" && note.Target == "" {
			sawSkip = true
		}
	}
	if !sawSkip {
		t.Errorf("want a LevelError with an empty Target for the skipped policy: %+v", rep.Notes)
	}
}

func TestKyvernoSetToVAPNothingConverted(t *testing.T) {
	bad := sampleKyverno("bad")
	bad.Spec.Evaluation = &kyverno.EvaluationConfiguration{Mode: kyverno.EvaluationModeEnvoy}

	_, _, _, err := convert.KyvernoSetToVAP([]kyverno.ValidatingPolicy{bad}, noProvenanceToVAP)
	if !errors.Is(err, convert.ErrNothingConverted) {
		t.Fatalf("got err %v, want ErrNothingConverted", err)
	}
}

func TestKyvernoToVAPDoesNotAliasTheInput(t *testing.T) {
	policy := sampleKyverno("p")
	vap, _, _, err := convert.KyvernoToVAP(policy, noProvenanceToVAP)
	if err != nil {
		t.Fatalf("KyvernoToVAP: %v", err)
	}

	vap.Spec.MatchConstraints.ResourceRules[0].Resources[0] = "deployments"
	vap.Spec.Validations[0].Message = "mutated"
	vap.Labels["team"] = "security"

	if policy.Spec.MatchConstraints.ResourceRules[0].Resources[0] != "pods" {
		t.Error("matchConstraints aliased")
	}
	if policy.Spec.Validations[0].Message != "required" {
		t.Error("validations aliased")
	}
	if policy.Labels["team"] != "platform" {
		t.Error("labels aliased")
	}
}

func TestKyvernoToVAPBindingNameStaysLegal(t *testing.T) {
	long := make([]byte, 250)
	for i := range long {
		long[i] = 'a'
	}
	policy := sampleKyverno(string(long))

	_, binding, _, err := convert.KyvernoToVAP(policy, noProvenanceToVAP)
	if err != nil {
		t.Fatalf("KyvernoToVAP: %v", err)
	}
	if len(binding.Name) > 253 {
		t.Errorf("binding name is %d chars, want at most 253", len(binding.Name))
	}
}

// metav1 keeps the import used when the namespaced pin assertions change.
var _ = metav1.LabelSelector{}
