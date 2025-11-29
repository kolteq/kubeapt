// Copyright by KolTEQ GmbH
// Contact: benjamin@kolteq.com

package kubernetes

import (
	"strings"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	// corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type matchCriteria struct {
	constraints *admissionregistrationv1.MatchResources
}

// GetParsedNamespaceSelector returns the converted LabelSelector which implements labels.Selector
func (m *matchCriteria) GetParsedNamespaceSelector() (labels.Selector, error) {
	return metav1.LabelSelectorAsSelector(m.constraints.NamespaceSelector)
}

// GetParsedObjectSelector returns the converted LabelSelector which implements labels.Selector
func (m *matchCriteria) GetParsedObjectSelector() (labels.Selector, error) {
	return metav1.LabelSelectorAsSelector(m.constraints.ObjectSelector)
}

// GetMatchResources returns the matchConstraints
func (m *matchCriteria) GetMatchResources() admissionregistrationv1.MatchResources {
	return *m.constraints
}

// func Match(vaps []admissionregistrationv1.ValidatingAdmissionPolicy, resources []runtime.Object) []matchResources {

// 	// Return Variable
// 	var matchedResources []matchResources

// 	// Initialize Kubernetes client
// 	clientset, err := Init()
// 	if err != nil {
// 		panic(err.Error())
// 	}

// 	// Setup informer factory
// 	informerFactory := informers.NewSharedInformerFactory(clientset, 0)

// 	// Create the matcher
// 	matcher := matching.NewMatcher(
// 		informerFactory.Core().V1().Namespaces().Lister(),
// 		clientset,
// 	)

// 	if err := matcher.ValidateInitialization(); err != nil {
// 		panic(fmt.Sprintf("Matcher failed to initialize: %v", err))
// 	}

// 	// Start informers
// 	stopCh := make(chan struct{})
// 	defer close(stopCh)
// 	informerFactory.Start(stopCh)
// 	informerFactory.WaitForCacheSync(stopCh)

// 	for _, vap := range vaps {
// 		criteria := &matchCriteria{}
// 		criteria.constraints = vap.Spec.MatchConstraints

// 		for _, resource := range resources {

// 			obj, err := decodeToRuntimeObject(resource.(*corev1.Pod).Raw)

// 			attr := admission.NewAttributesRecord(
// 				obj, // obj
// 				obj, // oldObj
// 				obj.GetObjectKind().GroupVersionKind(), // GVK
// 				"", // namespace
// 				"", // name
//                 obj.GetObjectKind().GroupVersionKind().GroupVersion().WithResource(obj.GetObjectKind().GroupVersionKind().Kind), // GVR
// 				"",               // subresource
// 				admission.Create, // operation
// 				nil,              // operationOptions (can be nil if not needed)
// 				false,            // dryRun
// 				nil,              // object (can be nil if not needed)
// 			)

// 			// Build ObjectInterfaces implementation
// 			var scheme = runtime.NewScheme()
// 			objInterfaces := admission.NewObjectInterfacesFromScheme(scheme)

// 			match, a, b, err := matcher.Matches(attr, objInterfaces, criteria)
// 			if err != nil {
// 				panic(fmt.Sprintf("Match failed: %v", err))
// 			}
// 			if match {
// 				matchedResources = append(matchedResources, matchResources{
// 					vap:       &vap,
// 					resources: resources,
// 				})
// 			}
// 		}
// 	}

// 	pod := &corev1.Pod{}
// 	_ = json.Unmarshal([]byte(`{
// 		"apiVersion": "v1",
// 		"kind": "Pod",
// 		"metadata": {
// 			"name": "example-pod",
// 			"namespace": "test",
// 			}
// 		}
// 	}`), pod)

// 	// // Create admission.Attributes mock for matching
// 	attr := admission.NewAttributesRecord(
// 		pod, // obj
// 		pod, // oldObj
// 		schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Pod"},
// 		"test",        // namespace
// 		"example-pod", // name
// 		schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"},
// 		"",               // subresource
// 		admission.Create, // operation
// 		nil,              // operationOptions (can be nil if not needed)
// 		false,            // dryRun
// 		nil,              // object (can be nil if not needed)
// 	)

// 	return matchedResources
// }

// MatchesPolicy evaluates whether the supplied object satisfies the policy's match constraints.
func MatchesPolicy(vap *admissionregistrationv1.ValidatingAdmissionPolicy, obj map[string]interface{}, namespaceLabels map[string]string, namespaceKnown bool, ignoreNamespaceSelectors bool) bool {
	if vap == nil || vap.Spec.MatchConstraints == nil || obj == nil {
		return false
	}

	return matchResources(obj, namespaceLabels, namespaceKnown, vap.Spec.MatchConstraints, true, ignoreNamespaceSelectors, false)
}

// MatchesBinding evaluates whether a resource satisfies the optional selectors declared on a binding.
func MatchesBinding(binding *admissionregistrationv1.ValidatingAdmissionPolicyBinding, obj map[string]interface{}, namespaceLabels map[string]string, namespaceKnown bool, ignoreNamespaceSelectors bool, ignoreObjectSelectors bool) bool {
	if binding == nil || obj == nil {
		return false
	}

	if binding.Spec.MatchResources == nil {
		return true
	}

	return matchResources(obj, namespaceLabels, namespaceKnown, binding.Spec.MatchResources, false, ignoreNamespaceSelectors, ignoreObjectSelectors)
}

func matchResources(obj map[string]interface{}, namespaceLabels map[string]string, namespaceKnown bool, constraints *admissionregistrationv1.MatchResources, requireResourceRules bool, ignoreNamespaceSelectors bool, ignoreObjectSelectors bool) bool {
	if constraints == nil {
		return !requireResourceRules
	}

	if !namespaceMatches(constraints.NamespaceSelector, obj, namespaceLabels, namespaceKnown, ignoreNamespaceSelectors) {
		return false
	}

	if !objectMatches(constraints.ObjectSelector, obj, ignoreObjectSelectors) {
		return false
	}

	if len(constraints.ExcludeResourceRules) > 0 && matchesAnyRule(obj, constraints.ExcludeResourceRules) {
		return false
	}

	if len(constraints.ResourceRules) == 0 {
		if requireResourceRules {
			return false
		}
	} else if !matchesAnyRule(obj, constraints.ResourceRules) {
		return false
	}

	return true
}

func namespaceMatches(selector *metav1.LabelSelector, obj map[string]interface{}, namespaceLabels map[string]string, namespaceKnown bool, ignore bool) bool {
	if selector == nil || ignore {
		return true
	}

	kind, _ := obj["kind"].(string)
	if strings.EqualFold(kind, "Namespace") {
		// Namespace objects evaluate selectors against their own labels.
		namespaceLabels = GetMetadataLabels(obj)
		namespaceKnown = true
	}

	namespace := GetMetadataString(obj, "namespace")
	if namespace == "" && !strings.EqualFold(kind, "Namespace") {
		return true
	}

	if namespace != "" && !namespaceKnown {
		// Without namespace data we cannot evaluate selector, so match everything.
		return true
	}

	nsSelector, err := metav1.LabelSelectorAsSelector(selector)
	if err != nil {
		return false
	}

	return nsSelector.Matches(labels.Set(namespaceLabels))
}

func objectMatches(selector *metav1.LabelSelector, obj map[string]interface{}, ignore bool) bool {
	if selector == nil || ignore {
		return true
	}

	objSelector, err := metav1.LabelSelectorAsSelector(selector)
	if err != nil {
		return false
	}

	return objSelector.Matches(labels.Set(GetMetadataLabels(obj)))
}

func matchesAnyRule(obj map[string]interface{}, rules []admissionregistrationv1.NamedRuleWithOperations) bool {
	for _, rule := range rules {
		if matchesRule(obj, rule) {
			return true
		}
	}
	return false
}

func matchesRule(obj map[string]interface{}, rule admissionregistrationv1.NamedRuleWithOperations) bool {
	gvk, ok := extractGVK(obj)
	if !ok {
		return false
	}

	if len(rule.Operations) > 0 && !operationMatches(admissionregistrationv1.Create, rule.Operations) {
		return false
	}

	if len(rule.APIGroups) > 0 && !stringMatches(gvk.Group, rule.APIGroups) {
		return false
	}

	if len(rule.APIVersions) > 0 && !stringMatches(gvk.Version, rule.APIVersions) {
		return false
	}

	if len(rule.Resources) > 0 {
		plural, _ := meta.UnsafeGuessKindToResource(gvk)
		if !resourceMatches(plural.Resource, rule.Resources) {
			return false
		}
	}

	if len(rule.ResourceNames) > 0 {
		name := GetMetadataString(obj, "name")
		if !stringMatches(name, rule.ResourceNames) {
			return false
		}
	}

	if rule.Scope != nil && *rule.Scope != admissionregistrationv1.AllScopes {
		scope := detectScope(obj)
		if scope != *rule.Scope {
			return false
		}
	}

	return true
}

func operationMatches(requestOp admissionregistrationv1.OperationType, allowed []admissionregistrationv1.OperationType) bool {
	for _, op := range allowed {
		if op == admissionregistrationv1.OperationAll || op == requestOp {
			return true
		}
	}
	return false
}

func stringMatches(value string, allowed []string) bool {
	for _, ruleValue := range allowed {
		if ruleValue == "*" || ruleValue == value {
			return true
		}
	}
	return false
}

func resourceMatches(resource string, rules []string) bool {
	if resource == "" {
		return false
	}

	for _, rule := range rules {
		if rule == "*" || rule == "*/*" {
			return true
		}

		if strings.Contains(rule, "/") {
			parts := strings.SplitN(rule, "/", 2)
			base := parts[0]
			sub := parts[1]
			if (base == "*" || base == resource) && (sub == "*" || sub == "") {
				return true
			}
			continue
		}

		if rule == resource {
			return true
		}
	}

	return false
}

func extractGVK(obj map[string]interface{}) (schema.GroupVersionKind, bool) {
	apiVersion, _ := obj["apiVersion"].(string)
	kind, _ := obj["kind"].(string)
	if apiVersion == "" || kind == "" {
		return schema.GroupVersionKind{}, false
	}

	gv, err := schema.ParseGroupVersion(apiVersion)
	if err != nil {
		return schema.GroupVersionKind{}, false
	}

	return gv.WithKind(kind), true
}

func detectScope(obj map[string]interface{}) admissionregistrationv1.ScopeType {
	namespace := GetMetadataString(obj, "namespace")
	if namespace == "" {
		return admissionregistrationv1.ClusterScope
	}
	return admissionregistrationv1.NamespacedScope
}

// GetMetadataString returns a metadata string field from the object if present.
func GetMetadataString(obj map[string]interface{}, key string) string {
	metaFields, ok := obj["metadata"].(map[string]interface{})
	if !ok {
		return ""
	}
	if value, ok := metaFields[key]; ok {
		if str, ok := value.(string); ok {
			return str
		}
	}
	return ""
}

// GetMetadataLabels returns the metadata.labels map as strings.
func GetMetadataLabels(obj map[string]interface{}) map[string]string {
	metaFields, ok := obj["metadata"].(map[string]interface{})
	if !ok {
		return nil
	}
	rawLabels, _ := metaFields["labels"].(map[string]interface{})
	return convertToStringMap(rawLabels)
}

func convertToStringMap(values map[string]interface{}) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for k, v := range values {
		if str, ok := v.(string); ok {
			out[k] = str
		}
	}
	return out
}
