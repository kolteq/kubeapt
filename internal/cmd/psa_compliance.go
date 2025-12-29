// Copyright by KolTEQ GmbH
// Contact: benjamin@kolteq.com

package cmd

import (
	"fmt"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"

	"github.com/kolteq/kubeapt/internal/kubernetes"
)

type psaComplianceCounts struct {
	Compliant    int
	NonCompliant int
	Violations   []violationDetail
}

func evaluatePSACompliance(policies []admissionregistrationv1.ValidatingAdmissionPolicy, bindings []admissionregistrationv1.ValidatingAdmissionPolicyBinding, resources []map[string]interface{}, namespaceLabels map[string]map[string]string, ignoreSelectors bool, level string) (map[string]psaComplianceCounts, error) {
	results := make(map[string]psaComplianceCounts)
	if len(policies) == 0 || len(bindings) == 0 || len(resources) == 0 {
		return results, nil
	}

	policyIndex := make(map[string]*admissionregistrationv1.ValidatingAdmissionPolicy)
	for i := range policies {
		policy := &policies[i]
		policyIndex[policy.Name] = policy
	}

	matched := make(map[string]struct{})
	status := make(map[string]bool)
	resourceNamespace := make(map[string]string)

	for i := range bindings {
		binding := &bindings[i]
		policy, ok := policyIndex[binding.Spec.PolicyName]
		if !ok {
			return nil, fmt.Errorf("binding %s references missing policy %s", binding.Name, binding.Spec.PolicyName)
		}

		for _, resource := range resources {
			nsName := kubernetes.GetMetadataString(resource, "namespace")
			if nsName == "" {
				nsName = kubernetes.ActiveNamespace()
			}
			if nsName == "" {
				nsName = "default"
			}
			nsLabels, nsKnown := namespaceLabels[nsName]
			if level != "" {
				nsLabels = applyPSALevelLabels(nsLabels, level)
				nsKnown = true
			}

			if !kubernetes.MatchesPolicy(policy, resource, nsLabels, nsKnown, false) {
				continue
			}
			if !kubernetes.MatchesBinding(binding, resource, nsLabels, nsKnown, ignoreSelectors, ignoreSelectors) {
				continue
			}

			id := resourceIdentifier(resource)
			matched[id] = struct{}{}
			resourceNamespace[id] = nsName
			if _, ok := status[id]; !ok {
				status[id] = true
			}

			result, err := evaluateValidations(policy, binding, resource, nsName, nsLabels)
			if err != nil {
				return nil, err
			}
			if !result.Compliant {
				status[id] = false
				resName := describeResource(resource)
				for _, violation := range result.Violations {
					detail := violationDetail{
						Policy:   policy.Name,
						Binding:  binding.Name,
						Resource: resName,
						Message:  violation.Message,
						Path:     violation.Path,
						Actions:  violation.Actions,
					}
					nsResult := results[nsName]
					nsResult.Violations = append(nsResult.Violations, detail)
					results[nsName] = nsResult
				}
			}
		}
	}

	for id := range matched {
		nsName := resourceNamespace[id]
		if nsName == "" {
			continue
		}
		counts := results[nsName]
		if status[id] {
			counts.Compliant++
		} else {
			counts.NonCompliant++
		}
		results[nsName] = counts
	}

	return results, nil
}

func applyPSALevelLabels(labels map[string]string, level string) map[string]string {
	if level == "" {
		return labels
	}
	out := make(map[string]string, len(labels)+3)
	for k, v := range labels {
		out[k] = v
	}
	for _, mode := range []string{"warn", "audit", "enforce"} {
		out["pss.security.kolteq.com/"+mode] = level
	}
	return out
}
