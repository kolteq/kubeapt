// Copyright by cenroq AG
// Contact: info@cenroq.com

package kyverno_test

import (
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cenroq/kubeapt/v2/pkg/kyverno"
)

func TestNewDefaultsAPIVersion(t *testing.T) {
	cluster := kyverno.New("p", "")
	if cluster.APIVersion != kyverno.APIVersionV1 {
		t.Errorf("got apiVersion %s, want %s", cluster.APIVersion, kyverno.APIVersionV1)
	}
	if cluster.Kind != kyverno.KindValidatingPolicy {
		t.Errorf("got kind %s, want %s", cluster.Kind, kyverno.KindValidatingPolicy)
	}
	if cluster.Namespaced() {
		t.Error("New returned a namespaced policy")
	}

	pinned := kyverno.New("p", kyverno.APIVersionV1Alpha1)
	if pinned.APIVersion != kyverno.APIVersionV1Alpha1 {
		t.Errorf("got apiVersion %s, want %s", pinned.APIVersion, kyverno.APIVersionV1Alpha1)
	}

	namespaced := kyverno.NewNamespaced("p", "prod", "")
	if !namespaced.Namespaced() {
		t.Error("NewNamespaced did not return a namespaced policy")
	}
	if namespaced.Namespace != "prod" {
		t.Errorf("got namespace %s, want prod", namespaced.Namespace)
	}
}

func TestNamespacedOnNil(t *testing.T) {
	var p *kyverno.ValidatingPolicy
	if p.Namespaced() {
		t.Error("nil policy reported as namespaced")
	}
}

// TestDeepCopySpecIsDeep mutates every mutable field on the copy and asserts the
// original is untouched. Multi-binding conversion fans one source policy into
// several outputs, so a shallow copy would silently alias them.
func TestDeepCopySpecIsDeep(t *testing.T) {
	scope := admissionregistrationv1.NamespacedScope
	failurePolicy := admissionregistrationv1.Fail
	enabled := true
	timeout := int32(30)

	original := kyverno.ValidatingPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "source",
			Labels:      map[string]string{"team": "platform"},
			Annotations: map[string]string{"policies.kyverno.io/title": "Source"},
		},
		Spec: kyverno.ValidatingPolicySpec{
			MatchConstraints: &admissionregistrationv1.MatchResources{
				NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
				ResourceRules: []admissionregistrationv1.NamedRuleWithOperations{{
					RuleWithOperations: admissionregistrationv1.RuleWithOperations{
						Operations: []admissionregistrationv1.OperationType{admissionregistrationv1.Create},
						Rule: admissionregistrationv1.Rule{
							APIGroups:   []string{""},
							APIVersions: []string{"v1"},
							Resources:   []string{"pods"},
							Scope:       &scope,
						},
					},
				}},
			},
			MatchConditions:   []admissionregistrationv1.MatchCondition{{Name: "c", Expression: "true"}},
			Variables:         []admissionregistrationv1.Variable{{Name: "v", Expression: "1"}},
			Validations:       []admissionregistrationv1.Validation{{Expression: "true", Message: "ok"}},
			AuditAnnotations:  []admissionregistrationv1.AuditAnnotation{{Key: "k", ValueExpression: "'v'"}},
			FailurePolicy:     &failurePolicy,
			ValidationActions: []admissionregistrationv1.ValidationAction{admissionregistrationv1.Deny},
			Evaluation: &kyverno.EvaluationConfiguration{
				Mode:       kyverno.EvaluationModeKubernetes,
				Admission:  &kyverno.AdmissionConfiguration{Enabled: &enabled},
				Background: &kyverno.BackgroundConfiguration{Enabled: &enabled},
			},
			Autogen: &kyverno.AutogenConfiguration{
				PodControllers:            &kyverno.PodControllersGenerationConfiguration{Controllers: []string{"deployments"}},
				ValidatingAdmissionPolicy: &kyverno.VAPGenerationConfiguration{Enabled: &enabled},
			},
			WebhookConfiguration: &kyverno.WebhookConfiguration{TimeoutSeconds: &timeout},
			ParamKind:            &admissionregistrationv1.ParamKind{APIVersion: "rules.example.com/v1", Kind: "Limit"},
			ParamRef:             &admissionregistrationv1.ParamRef{Name: "limits"},
		},
		Status: []byte(`{"conditionStatus":{}}`),
	}

	copied := original.DeepCopy()

	copied.Name = "copy"
	copied.Labels["team"] = "security"
	copied.Annotations["policies.kyverno.io/title"] = "Copy"
	copied.Spec.MatchConstraints.NamespaceSelector.MatchLabels["env"] = "dev"
	copied.Spec.MatchConstraints.ResourceRules[0].Resources[0] = "deployments"
	copied.Spec.MatchConditions[0].Expression = "false"
	copied.Spec.Variables[0].Expression = "2"
	copied.Spec.Validations[0].Message = "changed"
	copied.Spec.AuditAnnotations[0].ValueExpression = "'other'"
	*copied.Spec.FailurePolicy = admissionregistrationv1.Ignore
	copied.Spec.ValidationActions[0] = admissionregistrationv1.Audit
	*copied.Spec.Evaluation.Admission.Enabled = false
	*copied.Spec.Evaluation.Background.Enabled = false
	copied.Spec.Evaluation.Mode = kyverno.EvaluationModeJSON
	copied.Spec.Autogen.PodControllers.Controllers[0] = "jobs"
	*copied.Spec.Autogen.ValidatingAdmissionPolicy.Enabled = false
	*copied.Spec.WebhookConfiguration.TimeoutSeconds = 1
	copied.Spec.ParamKind.Kind = "Other"
	copied.Spec.ParamRef.Name = "other"
	copied.Status[0] = 'X'

	if original.Name != "source" {
		t.Error("name aliased")
	}
	if original.Labels["team"] != "platform" {
		t.Error("labels aliased")
	}
	if original.Annotations["policies.kyverno.io/title"] != "Source" {
		t.Error("annotations aliased")
	}
	if original.Spec.MatchConstraints.NamespaceSelector.MatchLabels["env"] != "prod" {
		t.Error("namespaceSelector aliased")
	}
	if original.Spec.MatchConstraints.ResourceRules[0].Resources[0] != "pods" {
		t.Error("resourceRules aliased")
	}
	if original.Spec.MatchConditions[0].Expression != "true" {
		t.Error("matchConditions aliased")
	}
	if original.Spec.Variables[0].Expression != "1" {
		t.Error("variables aliased")
	}
	if original.Spec.Validations[0].Message != "ok" {
		t.Error("validations aliased")
	}
	if original.Spec.AuditAnnotations[0].ValueExpression != "'v'" {
		t.Error("auditAnnotations aliased")
	}
	if *original.Spec.FailurePolicy != admissionregistrationv1.Fail {
		t.Error("failurePolicy aliased")
	}
	if original.Spec.ValidationActions[0] != admissionregistrationv1.Deny {
		t.Error("validationActions aliased")
	}
	if !*original.Spec.Evaluation.Admission.Enabled || !*original.Spec.Evaluation.Background.Enabled {
		t.Error("evaluation aliased")
	}
	if original.Spec.Evaluation.Mode != kyverno.EvaluationModeKubernetes {
		t.Error("evaluation mode aliased")
	}
	if original.Spec.Autogen.PodControllers.Controllers[0] != "deployments" {
		t.Error("autogen podControllers aliased")
	}
	if !*original.Spec.Autogen.ValidatingAdmissionPolicy.Enabled {
		t.Error("autogen validatingAdmissionPolicy aliased")
	}
	if *original.Spec.WebhookConfiguration.TimeoutSeconds != 30 {
		t.Error("webhookConfiguration aliased")
	}
	if original.Spec.ParamKind.Kind != "Limit" {
		t.Error("paramKind aliased")
	}
	if original.Spec.ParamRef.Name != "limits" {
		t.Error("paramRef aliased")
	}
	if original.Status[0] != '{' {
		t.Error("status aliased")
	}
}

func TestDeepCopyNil(t *testing.T) {
	var policy *kyverno.ValidatingPolicy
	if policy.DeepCopy() != nil {
		t.Error("DeepCopy of a nil policy is not nil")
	}
	var spec *kyverno.ValidatingPolicySpec
	if spec.DeepCopy() != nil {
		t.Error("DeepCopy of a nil spec is not nil")
	}
	var evaluation *kyverno.EvaluationConfiguration
	if evaluation.DeepCopy() != nil {
		t.Error("DeepCopy of a nil evaluation is not nil")
	}
	var autogen *kyverno.AutogenConfiguration
	if autogen.DeepCopy() != nil {
		t.Error("DeepCopy of a nil autogen is not nil")
	}
	var webhook *kyverno.WebhookConfiguration
	if webhook.DeepCopy() != nil {
		t.Error("DeepCopy of a nil webhookConfiguration is not nil")
	}
}
