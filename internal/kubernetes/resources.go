// Copyright by KolTEQ GmbH
// Contact: benjamin@kolteq.com

package kubernetes

import (
	"context"
	"fmt"
	"sync"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type ResourceScope string

const (
	ResourceScopeSelected      ResourceScope = "selected"
	ResourceScopeAllNamespaces ResourceScope = "all-namespaces"
)

func FetchResourcesForPoliciesWithProgress(policies []admissionregistrationv1.ValidatingAdmissionPolicy, scope ResourceScope, namespaces []string, onPolicy func()) ([]map[string]interface{}, map[string]map[string]string, error) {
	var all []map[string]interface{}
	nsSet := map[string]struct{}{}
	dedup := map[string]struct{}{}
	allowed := buildNamespaceFilter(namespaces)
	defaultNamespace := ActiveNamespace()

	if len(policies) > 0 {
		workers := workerLimit(len(policies))
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		tasks := make(chan admissionregistrationv1.ValidatingAdmissionPolicy, workers*2)
		errCh := make(chan error, 1)
		var mu sync.Mutex
		var wg sync.WaitGroup

		var progressCh chan struct{}
		var progressDone chan struct{}
		if onPolicy != nil {
			progressCh = make(chan struct{}, 256)
			progressDone = make(chan struct{})
			go func() {
				for range progressCh {
					onPolicy()
				}
				close(progressDone)
			}()
			defer func() {
				close(progressCh)
				<-progressDone
			}()
		}

		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-ctx.Done():
						return
					case policy, ok := <-tasks:
						if !ok {
							return
						}
						if progressCh != nil {
							progressCh <- struct{}{}
						}
						if policy.Spec.MatchConstraints == nil || len(policy.Spec.MatchConstraints.ResourceRules) == 0 {
							continue
						}
						remote, err := FetchRemoteResourcesForRules(policy.Spec.MatchConstraints.ResourceRules)
						if err != nil {
							select {
							case errCh <- err:
							default:
							}
							cancel()
							return
						}
						for _, obj := range remote {
							ns := GetMetadataString(obj, "namespace")
							if !namespaceAllowed(ns, scope, allowed, defaultNamespace) {
								continue
							}
							key := resourceKey(obj)
							mu.Lock()
							if _, ok := dedup[key]; ok {
								mu.Unlock()
								continue
							}
							dedup[key] = struct{}{}
							all = append(all, obj)
							if ns != "" {
								nsSet[ns] = struct{}{}
							}
							mu.Unlock()
						}
					}
				}
			}()
		}

	policyLoop:
		for _, policy := range policies {
			select {
			case <-ctx.Done():
				break policyLoop
			case tasks <- policy:
			}
		}
		close(tasks)
		wg.Wait()

		select {
		case err := <-errCh:
			return nil, nil, err
		default:
		}
	}

	nsLabels, err := loadNamespaceLabels(nsSet)
	if err != nil {
		return nil, nil, err
	}

	return all, nsLabels, nil
}

func buildNamespaceFilter(namespaces []string) map[string]struct{} {
	filter := make(map[string]struct{})
	for _, ns := range namespaces {
		if ns != "" {
			filter[ns] = struct{}{}
		}
	}
	return filter
}

func namespaceAllowed(ns string, scope ResourceScope, allowed map[string]struct{}, defaultNamespace string) bool {
	if ns == "" {
		return true
	}
	if len(allowed) > 0 {
		_, ok := allowed[ns]
		return ok
	}
	if scope == ResourceScopeAllNamespaces {
		return true
	}
	if defaultNamespace == "" {
		return true
	}
	return ns == defaultNamespace
}

func resourceKey(obj map[string]interface{}) string {
	kind, _ := obj["kind"].(string)
	namespace := GetMetadataString(obj, "namespace")
	name := GetMetadataString(obj, "name")
	uid := GetMetadataString(obj, "uid")
	return fmt.Sprintf("%s/%s/%s/%s", kind, namespace, name, uid)
}

func loadNamespaceLabels(names map[string]struct{}) (map[string]map[string]string, error) {
	result := make(map[string]map[string]string, len(names))
	if len(names) == 0 {
		return result, nil
	}
	clientset, err := Init()
	if err != nil {
		return nil, err
	}
	for name := range names {
		ns, err := clientset.CoreV1().Namespaces().Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			continue
		}
		result[name] = ns.Labels
	}
	return result, nil
}
