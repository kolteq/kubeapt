// Copyright by KolTEQ GmbH
// Contact: benjamin@kolteq.com

package kubernetes

import (
	"fmt"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"

	"github.com/kolteq/kubeapt/internal/cel"
)

type ValidationViolation struct {
	Message string
	Path    string
	Actions []string
}

type ValidationResult struct {
	Compliant  bool
	Violations []ValidationViolation
}

func EvaluateValidations(policy *admissionregistrationv1.ValidatingAdmissionPolicy, binding *admissionregistrationv1.ValidatingAdmissionPolicyBinding, resource map[string]interface{}, namespace string, namespaceLabels map[string]string) (ValidationResult, error) {
	resultData := ValidationResult{Compliant: true}
	normalizeResourceForCEL(resource)

	payload := map[string]interface{}{
		"object":          resource,
		"oldObject":       nil,
		"request":         nil,
		"params":          nil,
		"namespaceObject": buildNamespaceObject(namespace, namespaceLabels),
		"variables":       map[string]interface{}{},
		"resource":        resource,
	}
	varScope := payload["variables"].(map[string]interface{})

	for _, variable := range policy.Spec.Variables {
		val, err := cel.Evaluate(variable.Expression, payload)
		if err != nil {
			return resultData, fmt.Errorf("variable %s evaluation failed for policy %s: %w", variable.Name, policy.Name, err)
		}
		varScope[variable.Name] = val
	}

	if len(policy.Spec.Validations) == 0 {
		return resultData, nil
	}

	for idx, validation := range policy.Spec.Validations {
		ok, err := cel.Check(validation.Expression, payload)
		if err != nil {
			return resultData, fmt.Errorf("cel evaluation failed for policy %s binding %s validation %d: %w", policy.Name, binding.Name, idx, err)
		}

		message := validation.Message
		if message == "" {
			message = validation.Expression
		}

		if ok {
			continue
		}

		resultData.Compliant = false
		actions := binding.Spec.ValidationActions
		if len(actions) == 0 {
			actions = []admissionregistrationv1.ValidationAction{admissionregistrationv1.Deny}
		}
		actionStrings := actionsToStrings(actions)
		resultData.Violations = append(resultData.Violations, ValidationViolation{
			Message: message,
			Actions: actionStrings,
		})
	}

	return resultData, nil
}

func buildNamespaceObject(name string, labels map[string]string) map[string]interface{} {
	if name == "" {
		return nil
	}
	meta := map[string]interface{}{
		"name": name,
	}
	if len(labels) > 0 {
		meta["labels"] = convertStringMap(labels)
	}
	return map[string]interface{}{
		"metadata": meta,
	}
}

func convertStringMap(values map[string]string) map[string]interface{} {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]interface{}, len(values))
	for k, v := range values {
		out[k] = v
	}
	return out
}

func actionsToStrings(actions []admissionregistrationv1.ValidationAction) []string {
	result := make([]string, len(actions))
	for i, action := range actions {
		result[i] = string(action)
	}
	return result
}
