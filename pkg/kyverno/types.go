// Copyright by cenroq AG
// Contact: info@cenroq.com

// Package kyverno models the subset of the policies.kyverno.io API that kubeapt
// converts to and from.
//
// Kyverno's ValidatingPolicy is a deliberate superset of the Kubernetes
// ValidatingAdmissionPolicy and reuses the upstream
// k8s.io/api/admissionregistration/v1 types for every field the two share, so
// this package embeds those types rather than restating them. Converting those
// fields is then an assignment rather than a translation.
//
// Field set verified against the Kyverno 1.18 ValidatingPolicy reference on
// 2026-07-30. kubeapt deliberately does not depend on github.com/kyverno/api:
// at v0.0.1-alpha.3 that module's field set lags its own documentation, still
// spelling matchConditions as "conditions" and lacking autogen and
// webhookConfiguration. Because the Kyverno schema is third-party and still
// moving, this package tracks a documented Kyverno release rather than
// promising stability across every Kyverno version.
package kyverno

import (
	"encoding/json"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// API group, versions, and kinds kubeapt recognizes.
const (
	GroupName          = "policies.kyverno.io"
	APIVersionV1       = "policies.kyverno.io/v1"
	APIVersionV1Alpha1 = "policies.kyverno.io/v1alpha1"

	KindValidatingPolicy           = "ValidatingPolicy"
	KindNamespacedValidatingPolicy = "NamespacedValidatingPolicy"
)

// Legacy kyverno.io kinds, recognized only so they can be rejected. They use
// Kyverno's pattern, anchor, and JMESPath rule model, which has no CEL
// equivalent and therefore no faithful ValidatingAdmissionPolicy translation.
const (
	LegacyGroupName   = "kyverno.io"
	KindClusterPolicy = "ClusterPolicy"
	KindPolicy        = "Policy"
)

// ValidatingPolicy models both ValidatingPolicy and NamespacedValidatingPolicy.
// Kyverno gives the two kinds an identical spec and differs only in scope, so a
// single Go type carries both and Kind discriminates; use Namespaced.
type ValidatingPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec ValidatingPolicySpec `json:"spec"`

	// Status is deliberately opaque. kubeapt never writes it and only reports
	// that an input carried one.
	Status json.RawMessage `json:"status,omitempty"`
}

// Namespaced reports whether the policy is a NamespacedValidatingPolicy.
func (p *ValidatingPolicy) Namespaced() bool {
	return p != nil && p.Kind == KindNamespacedValidatingPolicy
}

// ValidatingPolicySpec is the shared spec of both Kyverno validating kinds.
type ValidatingPolicySpec struct {
	MatchConstraints  *admissionregistrationv1.MatchResources    `json:"matchConstraints,omitempty"`
	MatchConditions   []admissionregistrationv1.MatchCondition   `json:"matchConditions,omitempty"`
	Variables         []admissionregistrationv1.Variable         `json:"variables,omitempty"`
	Validations       []admissionregistrationv1.Validation       `json:"validations,omitempty"`
	AuditAnnotations  []admissionregistrationv1.AuditAnnotation  `json:"auditAnnotations,omitempty"`
	FailurePolicy     *admissionregistrationv1.FailurePolicyType `json:"failurePolicy,omitempty"`
	ValidationActions []admissionregistrationv1.ValidationAction `json:"validationActions,omitempty"`

	Evaluation           *EvaluationConfiguration `json:"evaluation,omitempty"`
	Autogen              *AutogenConfiguration    `json:"autogen,omitempty"`
	WebhookConfiguration *WebhookConfiguration    `json:"webhookConfiguration,omitempty"`

	// ParamKind and ParamRef existed in policies.kyverno.io/v1alpha1 and are
	// undocumented in v1. They are decoded so a v1alpha1 input can convert back
	// to a ValidatingAdmissionPolicy without loss; kubeapt never emits them.
	ParamKind *admissionregistrationv1.ParamKind `json:"paramKind,omitempty"`
	ParamRef  *admissionregistrationv1.ParamRef  `json:"paramRef,omitempty"`
}

// UnmarshalJSON decodes a spec, accepting the policies.kyverno.io/v1alpha1
// spelling "conditions" as an alias for "matchConditions". When a document sets
// both, "matchConditions" wins.
func (s *ValidatingPolicySpec) UnmarshalJSON(data []byte) error {
	// Shadow the type so the embedded decode does not recurse into this method.
	type spec ValidatingPolicySpec
	aux := struct {
		*spec
		LegacyConditions []admissionregistrationv1.MatchCondition `json:"conditions,omitempty"`
	}{spec: (*spec)(s)}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if len(s.MatchConditions) == 0 && len(aux.LegacyConditions) > 0 {
		s.MatchConditions = aux.LegacyConditions
	}
	return nil
}

// EvaluationMode selects the payload model a policy evaluates.
type EvaluationMode string

// Evaluation modes Kyverno supports. Only Kubernetes has a
// ValidatingAdmissionPolicy equivalent.
const (
	EvaluationModeKubernetes EvaluationMode = "Kubernetes"
	EvaluationModeJSON       EvaluationMode = "JSON"
	EvaluationModeEnvoy      EvaluationMode = "Envoy"
)

// EvaluationConfiguration controls how and when a policy is evaluated.
type EvaluationConfiguration struct {
	Mode       EvaluationMode           `json:"mode,omitempty"`
	Admission  *AdmissionConfiguration  `json:"admission,omitempty"`
	Background *BackgroundConfiguration `json:"background,omitempty"`
}

// AdmissionConfiguration controls evaluation during admission.
type AdmissionConfiguration struct {
	Enabled *bool `json:"enabled,omitempty"`
}

// BackgroundConfiguration controls evaluation during background scans.
type BackgroundConfiguration struct {
	Enabled *bool `json:"enabled,omitempty"`
}

// AutogenConfiguration opts a policy into Kyverno's rule auto-generation.
// Omitting it generates nothing, so a converted policy keeps the scope of the
// ValidatingAdmissionPolicy it came from.
type AutogenConfiguration struct {
	PodControllers            *PodControllersGenerationConfiguration `json:"podControllers,omitempty"`
	ValidatingAdmissionPolicy *VAPGenerationConfiguration            `json:"validatingAdmissionPolicy,omitempty"`
}

// PodControllersGenerationConfiguration lists the pod controllers to generate
// rules for.
type PodControllersGenerationConfiguration struct {
	Controllers []string `json:"controllers,omitempty"`
}

// VAPGenerationConfiguration controls generation of a ValidatingAdmissionPolicy
// for API-server-side execution.
type VAPGenerationConfiguration struct {
	Enabled *bool `json:"enabled,omitempty"`
}

// WebhookConfiguration tunes the Kyverno admission webhook for this policy.
type WebhookConfiguration struct {
	TimeoutSeconds *int32 `json:"timeoutSeconds,omitempty"`
}

// New returns an empty cluster-scoped ValidatingPolicy with TypeMeta set. An
// empty apiVersion means APIVersionV1.
func New(name, apiVersion string) ValidatingPolicy {
	return ValidatingPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: defaultAPIVersion(apiVersion),
			Kind:       KindValidatingPolicy,
		},
		ObjectMeta: metav1.ObjectMeta{Name: name},
	}
}

// NewNamespaced returns an empty NamespacedValidatingPolicy with TypeMeta set.
// An empty apiVersion means APIVersionV1.
func NewNamespaced(name, namespace, apiVersion string) ValidatingPolicy {
	return ValidatingPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: defaultAPIVersion(apiVersion),
			Kind:       KindNamespacedValidatingPolicy,
		},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
	}
}

func defaultAPIVersion(apiVersion string) string {
	if apiVersion == "" {
		return APIVersionV1
	}
	return apiVersion
}
