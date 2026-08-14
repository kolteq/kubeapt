// Copyright by cenroq AG
// Contact: info@cenroq.com

package kyverno

import (
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
)

// DeepCopy returns a deep copy of the policy. Conversion fans one source policy
// out into several outputs, so the copies must share no mutable state.
func (p *ValidatingPolicy) DeepCopy() *ValidatingPolicy {
	if p == nil {
		return nil
	}
	out := &ValidatingPolicy{
		TypeMeta:   p.TypeMeta,
		ObjectMeta: *p.ObjectMeta.DeepCopy(),
		Spec:       *p.Spec.DeepCopy(),
	}
	if p.Status != nil {
		out.Status = append([]byte(nil), p.Status...)
	}
	return out
}

// DeepCopy returns a deep copy of the spec.
func (s *ValidatingPolicySpec) DeepCopy() *ValidatingPolicySpec {
	if s == nil {
		return nil
	}
	out := &ValidatingPolicySpec{
		MatchConstraints: s.MatchConstraints.DeepCopy(),
		ParamKind:        s.ParamKind.DeepCopy(),
		ParamRef:         s.ParamRef.DeepCopy(),
	}

	if s.MatchConditions != nil {
		out.MatchConditions = make([]admissionregistrationv1.MatchCondition, len(s.MatchConditions))
		copy(out.MatchConditions, s.MatchConditions)
	}
	if s.Variables != nil {
		out.Variables = make([]admissionregistrationv1.Variable, len(s.Variables))
		copy(out.Variables, s.Variables)
	}
	if s.Validations != nil {
		out.Validations = make([]admissionregistrationv1.Validation, len(s.Validations))
		for i := range s.Validations {
			s.Validations[i].DeepCopyInto(&out.Validations[i])
		}
	}
	if s.AuditAnnotations != nil {
		out.AuditAnnotations = make([]admissionregistrationv1.AuditAnnotation, len(s.AuditAnnotations))
		copy(out.AuditAnnotations, s.AuditAnnotations)
	}
	if s.FailurePolicy != nil {
		v := *s.FailurePolicy
		out.FailurePolicy = &v
	}
	if s.ValidationActions != nil {
		out.ValidationActions = make([]admissionregistrationv1.ValidationAction, len(s.ValidationActions))
		copy(out.ValidationActions, s.ValidationActions)
	}

	out.Evaluation = s.Evaluation.DeepCopy()
	out.Autogen = s.Autogen.DeepCopy()
	out.WebhookConfiguration = s.WebhookConfiguration.DeepCopy()
	return out
}

// DeepCopy returns a deep copy of the evaluation configuration.
func (e *EvaluationConfiguration) DeepCopy() *EvaluationConfiguration {
	if e == nil {
		return nil
	}
	out := &EvaluationConfiguration{Mode: e.Mode}
	if e.Admission != nil {
		out.Admission = &AdmissionConfiguration{Enabled: copyBool(e.Admission.Enabled)}
	}
	if e.Background != nil {
		out.Background = &BackgroundConfiguration{Enabled: copyBool(e.Background.Enabled)}
	}
	return out
}

// DeepCopy returns a deep copy of the autogen configuration.
func (a *AutogenConfiguration) DeepCopy() *AutogenConfiguration {
	if a == nil {
		return nil
	}
	out := &AutogenConfiguration{}
	if a.PodControllers != nil {
		out.PodControllers = &PodControllersGenerationConfiguration{}
		if a.PodControllers.Controllers != nil {
			out.PodControllers.Controllers = append([]string(nil), a.PodControllers.Controllers...)
		}
	}
	if a.ValidatingAdmissionPolicy != nil {
		out.ValidatingAdmissionPolicy = &VAPGenerationConfiguration{
			Enabled: copyBool(a.ValidatingAdmissionPolicy.Enabled),
		}
	}
	return out
}

// DeepCopy returns a deep copy of the webhook configuration.
func (w *WebhookConfiguration) DeepCopy() *WebhookConfiguration {
	if w == nil {
		return nil
	}
	out := &WebhookConfiguration{}
	if w.TimeoutSeconds != nil {
		v := *w.TimeoutSeconds
		out.TimeoutSeconds = &v
	}
	return out
}

func copyBool(in *bool) *bool {
	if in == nil {
		return nil
	}
	v := *in
	return &v
}
