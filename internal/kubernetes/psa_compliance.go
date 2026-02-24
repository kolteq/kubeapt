// Copyright by KolTEQ GmbH
// Contact: benjamin@kolteq.com

package kubernetes

import (
	"context"
	"fmt"
	"sync"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"

	"github.com/kolteq/kubeapt/internal/worker"
)

type PSAViolation struct {
	Policy   string
	Binding  string
	Resource string
	Message  string
	Path     string
	Actions  []string
}

type PSAComplianceCounts struct {
	Compliant    int
	NonCompliant int
	Violations   []PSAViolation
}

func EvaluatePSACompliance(policies []admissionregistrationv1.ValidatingAdmissionPolicy, bindings []admissionregistrationv1.ValidatingAdmissionPolicyBinding, resources []map[string]interface{}, namespaceLabels map[string]map[string]string, ignoreBindings bool, level string, onProgress func()) (map[string]PSAComplianceCounts, error) {
	results := make(map[string]PSAComplianceCounts)
	if len(policies) == 0 || len(bindings) == 0 || len(resources) == 0 {
		return results, nil
	}

	expandedLabels := expandPSANamespaceLabelIndex(namespaceLabels)
	policyIndex := make(map[string]*admissionregistrationv1.ValidatingAdmissionPolicy)
	for i := range policies {
		policy := &policies[i]
		policyIndex[policy.Name] = policy
	}

	matched := make(map[string]struct{})
	status := make(map[string]bool)
	resourceNamespace := make(map[string]string)

	var progressCh chan struct{}
	var progressDone chan struct{}
	if onProgress != nil {
		progressCh = make(chan struct{}, 256)
		progressDone = make(chan struct{})
		go func() {
			for range progressCh {
				onProgress()
			}
			close(progressDone)
		}()
		defer func() {
			close(progressCh)
			<-progressDone
		}()
	}

	for i := range bindings {
		binding := &bindings[i]
		policy, ok := policyIndex[binding.Spec.PolicyName]
		if !ok {
			return nil, fmt.Errorf("binding %s references missing policy %s", binding.Name, binding.Spec.PolicyName)
		}

		var mu sync.Mutex
		ctx, cancel := context.WithCancel(context.Background())
		workers := worker.WorkerLimit(len(resources))
		tasks := make(chan map[string]interface{}, workers*2)
		errCh := make(chan error, 1)
		var wg sync.WaitGroup
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-ctx.Done():
						return
					case resource, ok := <-tasks:
						if !ok {
							return
						}
						if progressCh != nil {
							progressCh <- struct{}{}
						}
						namespaceName := MetadataString(resource, "namespace")
						if namespaceName == "" {
							namespaceName = ActiveNamespace()
						}
						if namespaceName == "" {
							namespaceName = "default"
						}
						namespaceLabelValues, namespaceKnown := expandedLabels[namespaceName]
						if level != "" {
							namespaceLabelValues = ApplyPSALevelLabels(namespaceLabelValues, level)
							namespaceKnown = true
						}

						if !MatchesPolicy(policy, resource, namespaceLabelValues, namespaceKnown, false) {
							continue
						}
						if !ignoreBindings {
							if !MatchesBinding(binding, resource, namespaceLabelValues, namespaceKnown, false, false) {
								continue
							}
						}

						result, err := EvaluateValidations(policy, binding, resource, namespaceName, namespaceLabelValues)
						if err != nil {
							select {
							case errCh <- err:
							default:
							}
							cancel()
							return
						}

						resourceKeyValue := resourceKey(resource)
						if result.Compliant {
							mu.Lock()
							matched[resourceKeyValue] = struct{}{}
							resourceNamespace[resourceKeyValue] = namespaceName
							if _, ok := status[resourceKeyValue]; !ok {
								status[resourceKeyValue] = true
							}
							mu.Unlock()
							continue
						}

						resourceName := describeResource(resource)
						violations := make([]PSAViolation, len(result.Violations))
						for i, violation := range result.Violations {
							violations[i] = PSAViolation{
								Policy:   policy.Name,
								Binding:  binding.Name,
								Resource: resourceName,
								Message:  violation.Message,
								Path:     violation.Path,
								Actions:  violation.Actions,
							}
						}
						mu.Lock()
						matched[resourceKeyValue] = struct{}{}
						resourceNamespace[resourceKeyValue] = namespaceName
						if _, ok := status[resourceKeyValue]; !ok {
							status[resourceKeyValue] = true
						}
						status[resourceKeyValue] = false
						namespaceResult := results[namespaceName]
						namespaceResult.Violations = append(namespaceResult.Violations, violations...)
						results[namespaceName] = namespaceResult
						mu.Unlock()
					}
				}
			}()
		}

	resourceLoop:
		for _, resource := range resources {
			select {
			case <-ctx.Done():
				break resourceLoop
			case tasks <- resource:
			}
		}
		close(tasks)
		wg.Wait()
		cancel()
		select {
		case err := <-errCh:
			return nil, err
		default:
		}
	}

	for id := range matched {
		namespaceName := resourceNamespace[id]
		if namespaceName == "" {
			continue
		}
		counts := results[namespaceName]
		if status[id] {
			counts.Compliant++
		} else {
			counts.NonCompliant++
		}
		results[namespaceName] = counts
	}

	return results, nil
}

func ApplyPSALevelLabels(labels map[string]string, level string) map[string]string {
	if level == "" {
		return labels
	}
	out := make(map[string]string, len(labels)+6)
	for k, v := range labels {
		out[k] = v
	}
	for _, mode := range []string{"warn", "audit", "enforce"} {
		out["pss.security.kolteq.com/"+mode] = level
		out["pod-security.kubernetes.io/"+mode] = level
	}
	return out
}

func expandPSANamespaceLabelIndex(labels map[string]map[string]string) map[string]map[string]string {
	if labels == nil {
		return nil
	}
	result := make(map[string]map[string]string, len(labels))
	for namespaceName, namespaceLabels := range labels {
		result[namespaceName] = expandPSANamespaceLabels(namespaceLabels)
	}
	return result
}

func expandPSANamespaceLabels(labels map[string]string) map[string]string {
	if len(labels) == 0 {
		return labels
	}
	result := make(map[string]string, len(labels)+6)
	for k, v := range labels {
		result[k] = v
	}
	for _, mode := range []string{"warn", "audit", "enforce"} {
		nativeKey := "pod-security.kubernetes.io/" + mode
		kolteqKey := "pss.security.kolteq.com/" + mode
		nativeVal, nativeOK := labels[nativeKey]
		kolteqVal, kolteqOK := labels[kolteqKey]
		if nativeOK && !kolteqOK {
			result[kolteqKey] = nativeVal
		}
		if kolteqOK && !nativeOK {
			result[nativeKey] = kolteqVal
		}
	}
	return result
}

func describeResource(obj map[string]interface{}) string {
	kind, _ := obj["kind"].(string)
	name := MetadataString(obj, "name")
	namespace := MetadataString(obj, "namespace")
	if namespace == "" {
		namespace = "<cluster>"
	}
	return fmt.Sprintf("%s %s/%s", kind, namespace, name)
}
