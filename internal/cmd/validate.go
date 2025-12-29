// Copyright by KolTEQ GmbH
// Contact: benjamin@kolteq.com

package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/progress"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/spf13/cobra"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"

	"github.com/kolteq/kubeapt/internal/cel"
	"github.com/kolteq/kubeapt/internal/kubernetes"
	"github.com/kolteq/kubeapt/internal/logging"
)

var getLogLevel func() string

type violationDetail struct {
	Policy   string   `json:"policy"`
	Binding  string   `json:"binding"`
	Resource string   `json:"resource"`
	Message  string   `json:"message"`
	Path     string   `json:"path"`
	Actions  []string `json:"actions"`
}

type bindingReport struct {
	Policy       string            `json:"policy"`
	Binding      string            `json:"binding"`
	Mode         string            `json:"mode"`
	Total        int               `json:"total"`
	Compliant    int               `json:"compliant"`
	NonCompliant int               `json:"nonCompliant"`
	Violations   []violationDetail `json:"violations,omitempty"`
}

type violationRecord struct {
	Message string
	Path    string
	Actions []string
}

type validationResult struct {
	Compliant  bool
	Violations []violationRecord
}

func ValidateCmd(logLevelGetter func() string) *cobra.Command {
	getLogLevel = logLevelGetter
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validation utilities",
	}
	cmd.PersistentFlags().Bool("pipeline", false, "Indicate the command runs inside CI/CD")
	cmd.PersistentFlags().BoolP("all-namespaces", "A", false, "Use all namespaces instead of the active one")
	cmd.PersistentFlags().StringP("namespaces", "n", "", "Comma separated list of namespaces to evaluate")
	cmd.PersistentFlags().StringP("format", "f", "table", "Specify the report output format: table or json")
	cmd.PersistentFlags().String("output", "", "Write the report to a file path instead of stdout")
	cmd.AddCommand(newValidateVAPCmd())
	cmd.AddCommand(newValidatePSACmd())
	return cmd
}

func newValidateVAPCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:    "vap",
		Short:  "Validate ValidatingAdmissionPolicies and PodSecurityAdmission labels against resources",
		PreRun: vapPreRun,
		RunE:   runValidateVAP,
	}

	cmd.Flags().StringP("policies", "p", "", "Specify the file or folder to the ValidatingAdmissionPolicy YAML file")
	cmd.Flags().StringP("bindings", "b", "", "Specify the file or folder to the ValidatingAdmissionPolicyBinding YAML file")
	cmd.Flags().StringP("resources", "r", "", "Specify the file or folder to the resource YAML file to validate")
	cmd.Flags().String("log-file", "", "Optional file to capture WARN/AUDIT output")
	cmd.Flags().String("report", "summary", "Specify the final report type: summary or all")
	cmd.Flags().Bool("remote-resources", false, "Fetch resources from the Kubernetes API instead of local files")
	cmd.Flags().Bool("ignore-selectors", false, "Ignore binding selectors and match policies on all selected resources")
	cmd.Flags().Bool("remote-policies", false, "Specify if policies from the Kubernetes API should be used for validation")

	return cmd
}

func vapPreRun(cmd *cobra.Command, _ []string) {
	if !cmd.Flag("remote-policies").Changed {
		cmd.MarkFlagRequired("policies")
	}
	if !cmd.Flag("remote-resources").Changed {
		cmd.MarkFlagRequired("resources")
	}
}

func runValidateVAP(cmd *cobra.Command, _ []string) error {
	flags := cmd.Flags()
	policyFile, err := flags.GetString("policies")
	if err != nil {
		return err
	}
	ignoreSelectors, err := flags.GetBool("ignore-selectors")
	if err != nil {
		return err
	}
	bindingFile, err := flags.GetString("bindings")
	if err != nil {
		return err
	}
	resourceFile, err := flags.GetString("resources")
	if err != nil {
		return err
	}
	remotePolicies, err := flags.GetBool("remote-policies")
	if err != nil {
		return err
	}
	remoteResources, err := flags.GetBool("remote-resources")
	if err != nil {
		return err
	}
	allNamespaces, err := flags.GetBool("all-namespaces")
	if err != nil {
		return err
	}
	namespaceList, err := flags.GetString("namespaces")
	if err != nil {
		return err
	}
	namespaces := parseNamespaces(namespaceList)
	logFile, err := flags.GetString("log-file")
	if err != nil {
		return err
	}
	reportMode := strings.ToLower(cmd.Flag("report").Value.String())
	format := strings.ToLower(cmd.Flag("format").Value.String())
	outputPath := strings.TrimSpace(cmd.Flag("output").Value.String())

	if reportMode != "summary" && reportMode != "all" {
		return fmt.Errorf("invalid report type %s, expected summary or all", reportMode)
	}
	if format != "table" && format != "json" {
		return fmt.Errorf("invalid output format %s, expected table or json", format)
	}

	if allNamespaces && len(namespaces) > 0 {
		return fmt.Errorf("--all-namespaces cannot be used together with --namespaces")
	}
	if len(namespaces) == 0 && !allNamespaces {
		namespaces = []string{kubernetes.ActiveNamespace()}
	}

	if err := logging.Init(logFile, getLogLevel()); err != nil {
		return err
	}
	defer logging.Close()

	progressEnabled := true
	writer := io.Writer(os.Stdout)
	tableStyle := table.StyleRounded
	useColor := true
	if outputPath != "" {
		f, err := os.Create(outputPath)
		if err != nil {
			return fmt.Errorf("failed to open output file: %w", err)
		}
		defer f.Close()
		writer = f
		tableStyle = table.StyleDefault
		useColor = false
	}

	var vaps []admissionregistrationv1.ValidatingAdmissionPolicy
	var bindings []admissionregistrationv1.ValidatingAdmissionPolicyBinding

	if remotePolicies {
		err = withProgress("Fetching remote policies", 2, progressEnabled, func(tracker *progress.Tracker) error {
			vaps, err = kubernetes.GetRemoteValidatingAdmissionPolicies()
			if err != nil {
				return err
			}
			tracker.Increment(1)

			bindings, err = kubernetes.GetRemoteValidatingAdmissionPolicyBindings()
			if err != nil {
				return err
			}
			tracker.Increment(1)
			return nil
		})
		if err != nil {
			return err
		}
	} else {
		if bindingFile == "" {
			bindingFile = policyFile
			logging.Debugf("No bindings path provided, reusing %s", policyFile)
		}
		policyFiles, err := kubernetes.CountManifestFiles(policyFile)
		if err != nil {
			return err
		}
		bindingFiles, err := kubernetes.CountManifestFiles(bindingFile)
		if err != nil {
			return err
		}
		total := maxInt64(int64(policyFiles+bindingFiles), 1)
		err = withProgress("Reading policies", total, progressEnabled, func(tracker *progress.Tracker) error {
			vaps, err = kubernetes.GetLocalValidatingAdmissionPoliciesWithProgress(policyFile, func(string) {
				tracker.Increment(1)
			})
			if err != nil {
				return err
			}
			bindings, err = kubernetes.GetLocalValidatingAdmissionPolicyBindingsWithProgress(bindingFile, func(string) {
				tracker.Increment(1)
			})
			return err
		})
		if err != nil {
			return err
		}
	}

	var resources []map[string]interface{}
	namespaceLabels := make(map[string]map[string]string)

	if resourceFile != "" {
		localRes, localNS, err := loadLocalResources(resourceFile)
		if err != nil {
			return err
		}
		localRes = filterResourcesByNamespaces(localRes, namespaces, allNamespaces)
		logging.Debugf("Loaded %d resources from %s", len(localRes), resourceFile)
		resources = append(resources, localRes...)
		namespaceLabels = mergeFilteredNamespaceLabels(namespaceLabels, localNS, namespaces, allNamespaces)
	}

	if remoteResources {
		scope := kubernetes.ResourceScopeSelected
		if allNamespaces {
			scope = kubernetes.ResourceScopeAllNamespaces
		}
		total := maxInt64(int64(len(vaps)), 1)
		err = withProgress("Fetching remote resources", total, progressEnabled, func(tracker *progress.Tracker) error {
			remoteRes, remoteNS, err := kubernetes.FetchResourcesForPoliciesWithProgress(vaps, scope, namespaces, func() {
				tracker.Increment(1)
			})
			if err != nil {
				return err
			}
			logging.Debugf("Loaded %d resources from cluster", len(remoteRes))
			resources = append(resources, remoteRes...)
			namespaceLabels = mergeFilteredNamespaceLabels(namespaceLabels, remoteNS, namespaces, allNamespaces)
			return nil
		})
		if err != nil {
			return err
		}
	}

	if len(resources) == 0 {
		return fmt.Errorf("no resources available for validation")
	}

	resourceTotals := countResourcesByKind(resources)
	resourceDetails := collectResourceDetails(resources)

	if len(bindings) == 0 {
		logging.Debugf("No ValidatingAdmissionPolicyBindings available to evaluate")
		return nil
	}

	policyIndex := make(map[string]*admissionregistrationv1.ValidatingAdmissionPolicy)
	for i := range vaps {
		policy := &vaps[i]
		policyIndex[policy.Name] = policy
	}

	var reports []*bindingReport
	hasFailures := false

	totalWork := len(resources) * len(bindings)
	tracker, stop := startProgress("Validating resources", int64(totalWork), progressEnabled)
	defer stop()

	for i := range bindings {
		binding := &bindings[i]
		policy, ok := policyIndex[binding.Spec.PolicyName]
		if !ok {
			return fmt.Errorf("binding %s references missing policy %s", binding.Name, binding.Spec.PolicyName)
		}

		bReport := &bindingReport{
			Policy:  policy.Name,
			Binding: binding.Name,
			Mode:    bindingMode(binding),
		}
		reports = append(reports, bReport)

		logging.Debugf("Evaluating binding %s targeting policy %s", binding.Name, policy.Name)
		matched := false
		for _, resource := range resources {
			nsName := kubernetes.GetMetadataString(resource, "namespace")
			nsLabels, nsKnown := namespaceLabels[nsName]

			tracker.Increment(1)

			if !kubernetes.MatchesPolicy(policy, resource, nsLabels, nsKnown, false) {
				continue
			}
			ignoreNS := ignoreSelectors
			if !kubernetes.MatchesBinding(binding, resource, nsLabels, nsKnown, ignoreNS, ignoreSelectors) {
				continue
			}

			matched = true
			logging.Debugf("  Matched %s", describeResource(resource))
			bReport.Total++
			result, err := evaluateValidations(policy, binding, resource, nsName, nsLabels)
			if err != nil {
				return err
			}
			if result.Compliant {
				bReport.Compliant++
			} else {
				bReport.NonCompliant++
				hasFailures = true
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
					bReport.Violations = append(bReport.Violations, detail)
				}
			}
		}

		if !matched {
			logging.Debugf("  No resources matched binding %s", binding.Name)
		}
	}

	if err := renderReport(reportMode, format, reports, resourceTotals, resourceDetails, writer, tableStyle, useColor); err != nil {
		return err
	}

	if hasFailures && isPipeline(cmd) {
		return fmt.Errorf("validation failures detected")
	}

	return nil
}

// func getRemoteMatchingResource(vap admissionregistrationv1.ValidatingAdmissionPolicy) []interface{} {
// 	// MatchConstraints
// 	// resourceRules
// 	var res []interface{}
// 	for _, resourceRule := range vap.Spec.MatchConstraints.ResourceRules {
// 		apiGroups := resourceRule.APIGroups
// 		apiVersions := resourceRule.APIVersions
// 		resources := resourceRule.Resources

// 		x, err := kubernetes.GetRemoteGeneric(apiGroups, apiVersions, resources)
// 		if err != nil {
// 			println("Error getting resources:", err)
// 			continue
// 		}
// 		res = append(x, res...)

// 	}
// 	// excludeResourceRules not supported
// 	if vap.Spec.MatchConstraints.ExcludeResourceRules != nil {
// 		println("ExcludeResourceRules are currently not supported. Ignoring and matching all resources.")
// 	}
// 	// matchPolicy not supported
// 	if *vap.Spec.MatchConstraints.MatchPolicy != admissionregistrationv1.Equivalent {
// 		println("MatchPolicy is currently not supported. Ignoring and matching all resources.")
// 	}
// 	// namespaceSelector not supported
// 	if vap.Spec.MatchConstraints.NamespaceSelector.MatchLabels != nil || vap.Spec.MatchConstraints.NamespaceSelector.MatchExpressions != nil {
// 		println("NamespaceSelector is currently not supported. Ignoring and matching all resources.")
// 	}
// 	// objectSelector not supported
// 	if vap.Spec.MatchConstraints.ObjectSelector.MatchLabels != nil || vap.Spec.MatchConstraints.ObjectSelector.MatchExpressions != nil {
// 		println("ObjectSelector is currently not supported. Ignoring and matching all resources.")
// 	}

// 	// MatchCondition not supported
// 	if vap.Spec.MatchConditions != nil {
// 		println("MatchConditions are currently not supported. Ignoring and matching all resources.")
// 	}

// 	return res
// }

func loadLocalResources(path string) ([]map[string]interface{}, map[string]map[string]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, nil, err
	}

	if info.IsDir() {
		files, err := collectFiles(path)
		if err != nil {
			return nil, nil, err
		}
		var objs []map[string]interface{}
		for _, file := range files {
			items, err := readResourceFile(file)
			if err != nil {
				logging.Debugf("Skipping resource file %s: %v", file, err)
				continue
			}
			objs = append(objs, items...)
		}
		return objs, buildNamespaceLabelIndex(objs), nil
	}

	objects, err := readResourceFile(path)
	if err != nil {
		return nil, nil, err
	}
	return objects, buildNamespaceLabelIndex(objects), nil
}

func readResourceFile(path string) ([]map[string]interface{}, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return decodeResources(f)
}

func decodeResources(r io.Reader) ([]map[string]interface{}, error) {
	decoder := utilyaml.NewYAMLOrJSONDecoder(r, 4096)
	var resources []map[string]interface{}

	for {
		var raw runtime.RawExtension
		if err := decoder.Decode(&raw); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}

		if len(bytes.TrimSpace(raw.Raw)) == 0 {
			continue
		}

		var obj map[string]interface{}
		if err := json.Unmarshal(raw.Raw, &obj); err != nil {
			return nil, err
		}

		if len(obj) == 0 {
			continue
		}

		if apiVersion, _ := obj["apiVersion"].(string); apiVersion == "" {
			continue
		}
		if kind, _ := obj["kind"].(string); kind == "" {
			continue
		}

		resources = append(resources, obj)
	}

	return resources, nil
}

func buildNamespaceLabelIndex(resources []map[string]interface{}) map[string]map[string]string {
	index := make(map[string]map[string]string)
	for _, obj := range resources {
		kind, _ := obj["kind"].(string)
		if strings.EqualFold(kind, "Namespace") {
			name := kubernetes.GetMetadataString(obj, "name")
			if name == "" {
				continue
			}
			index[name] = kubernetes.GetMetadataLabels(obj)
		}
	}
	return index
}

func describeResource(obj map[string]interface{}) string {
	kind, _ := obj["kind"].(string)
	name := kubernetes.GetMetadataString(obj, "name")
	namespace := kubernetes.GetMetadataString(obj, "namespace")
	if namespace == "" {
		namespace = "<cluster>"
	}
	return fmt.Sprintf("%s %s/%s", kind, namespace, name)
}

func describeResourceRef(obj map[string]interface{}) logging.ResourceRef {
	kind, _ := obj["kind"].(string)
	name := kubernetes.GetMetadataString(obj, "name")
	namespace := kubernetes.GetMetadataString(obj, "namespace")
	return logging.ResourceRef{
		Kind:      kind,
		Namespace: namespace,
		Name:      name,
	}
}

func evaluateValidations(policy *admissionregistrationv1.ValidatingAdmissionPolicy, binding *admissionregistrationv1.ValidatingAdmissionPolicyBinding, resource map[string]interface{}, namespace string, namespaceLabels map[string]string) (validationResult, error) {
	resultData := validationResult{Compliant: true}

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
		logging.Debugf("    Policy %s defines no validations", policy.Name)
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
			logging.Debugf("    Validation[%d] PASSED (%s)", idx, message)
			continue
		}

		resultData.Compliant = false
		actions := binding.Spec.ValidationActions
		if len(actions) == 0 {
			actions = []admissionregistrationv1.ValidationAction{admissionregistrationv1.Deny}
		}
		actionStrings := actionsToStrings(actions)
		resultData.Violations = append(resultData.Violations, violationRecord{
			Message: message,
			Actions: actionStrings,
		})

		// No realtime logging here; reporting handles output later.
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

func startProgress(message string, total int64, enabled bool) (*progress.Tracker, func()) {
	if !enabled {
		tracker := &progress.Tracker{
			Message: message,
			Total:   maxInt64(total, 1),
		}
		return tracker, func() {}
	}
	pw := progress.NewWriter()
	pw.SetOutputWriter(os.Stdout)
	pw.SetAutoStop(false)
	pw.SetTrackerLength(40)
	pw.SetSortBy(progress.SortByNone)
	pw.SetMessageWidth(28)

	tracker := &progress.Tracker{
		Message: message,
		Total:   maxInt64(total, 1),
	}
	pw.AppendTracker(tracker)
	go pw.Render()

	stop := func() {
		tracker.MarkAsDone()
		pw.Stop()
		fmt.Println()
	}
	return tracker, stop
}

func withProgress(message string, total int64, enabled bool, fn func(*progress.Tracker) error) error {
	tracker, stop := startProgress(message, total, enabled)
	defer stop()
	return fn(tracker)
}

func resourceIdentifier(obj map[string]interface{}) string {
	kind, _ := obj["kind"].(string)
	namespace := kubernetes.GetMetadataString(obj, "namespace")
	name := kubernetes.GetMetadataString(obj, "name")
	uid := kubernetes.GetMetadataString(obj, "uid")
	return fmt.Sprintf("%s/%s/%s/%s", kind, namespace, name, uid)
}

func bindingMode(binding *admissionregistrationv1.ValidatingAdmissionPolicyBinding) string {
	actions := binding.Spec.ValidationActions
	if len(actions) == 0 {
		return string(admissionregistrationv1.Deny)
	}
	return strings.Join(actionsToStrings(actions), ",")
}

func violationSeverityColor(actions []string) (string, *color.Color) {
	has := func(target string) bool {
		for _, action := range actions {
			if strings.EqualFold(action, target) {
				return true
			}
		}
		return false
	}

	switch {
	case has("Deny"):
		return "deny", color.New(color.FgHiRed, color.Bold)
	case has("Audit"):
		return "audit", color.New(color.FgHiBlue, color.Bold)
	case has("Warn"):
		return "warn", color.New(color.FgHiYellow, color.Bold)
	default:
		return "info", color.New(color.FgWhite)
	}
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func mergeFilteredNamespaceLabels(dest, src map[string]map[string]string, namespaces []string, includeAll bool) map[string]map[string]string {
	if dest == nil {
		dest = make(map[string]map[string]string)
	}
	useFilter := !includeAll && len(namespaces) > 0
	allowed := make(map[string]struct{})
	if useFilter {
		for _, ns := range namespaces {
			allowed[ns] = struct{}{}
		}
	}
	for ns, labels := range src {
		if useFilter {
			if _, ok := allowed[ns]; !ok {
				continue
			}
		}
		dest[ns] = convertPSANamespaceLabels(labels)
	}
	if useFilter {
		for ns := range dest {
			if _, ok := allowed[ns]; !ok {
				delete(dest, ns)
			}
		}
	}
	return dest
}

func filterResourcesByNamespaces(resources []map[string]interface{}, namespaces []string, includeAll bool) []map[string]interface{} {
	if includeAll || len(namespaces) == 0 {
		return resources
	}
	allowed := make(map[string]struct{})
	for _, ns := range namespaces {
		if ns != "" {
			allowed[ns] = struct{}{}
		}
	}
	var filtered []map[string]interface{}
	for _, res := range resources {
		ns := kubernetes.GetMetadataString(res, "namespace")
		if ns == "" {
			filtered = append(filtered, res)
			continue
		}
		if _, ok := allowed[ns]; ok {
			filtered = append(filtered, res)
		}
	}
	return filtered
}

func parseNamespaces(arg string) []string {
	if arg == "" {
		return nil
	}
	parts := strings.Split(arg, ",")
	var result []string
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func mergeLabelMaps(dest, src map[string]map[string]string) map[string]map[string]string {
	if dest == nil {
		dest = make(map[string]map[string]string)
	}
	for ns, labels := range src {
		dest[ns] = convertPSANamespaceLabels(labels)
	}
	return dest
}

func extractPodsFromResources(resources []map[string]interface{}) ([]corev1.Pod, error) {
	var pods []corev1.Pod
	for _, obj := range resources {
		kind, _ := obj["kind"].(string)
		if !strings.EqualFold(kind, "Pod") {
			continue
		}
		raw, err := json.Marshal(obj)
		if err != nil {
			return nil, err
		}
		var pod corev1.Pod
		if err := json.Unmarshal(raw, &pod); err != nil {
			return nil, err
		}
		if pod.Namespace == "" {
			pod.Namespace = kubernetes.ActiveNamespace()
		}
		pods = append(pods, pod)
	}
	return pods, nil
}

func fetchRemotePods(namespaces []string, all bool) ([]corev1.Pod, map[string]map[string]string, error) {
	clientset, err := kubernetes.Init()
	if err != nil {
		return nil, nil, err
	}
	nsLabels := make(map[string]map[string]string)
	var pods []corev1.Pod

	if all {
		podList, err := clientset.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			return nil, nil, err
		}
		pods = append(pods, podList.Items...)

		nsList, err := clientset.CoreV1().Namespaces().List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			return nil, nil, err
		}
		for _, ns := range nsList.Items {
			nsLabels[ns.Name] = convertPSANamespaceLabels(ns.Labels)
		}
		return pods, nsLabels, nil
	}

	target := namespaces
	if len(target) == 0 {
		target = []string{kubernetes.ActiveNamespace()}
	}
	for _, ns := range target {
		if ns == "" {
			continue
		}
		podList, err := clientset.CoreV1().Pods(ns).List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			return nil, nil, err
		}
		pods = append(pods, podList.Items...)
		nsObj, err := clientset.CoreV1().Namespaces().Get(context.TODO(), ns, metav1.GetOptions{})
		if err == nil {
			nsLabels[ns] = convertPSANamespaceLabels(nsObj.Labels)
		}
	}
	return pods, nsLabels, nil
}

func fetchNamespaceLabels(namespaces []string, all bool) (map[string]map[string]string, error) {
	clientset, err := kubernetes.Init()
	if err != nil {
		return nil, err
	}
	result := make(map[string]map[string]string)
	if all || len(namespaces) == 0 {
		nsList, err := clientset.CoreV1().Namespaces().List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		for _, ns := range nsList.Items {
			result[ns.Name] = convertPSANamespaceLabels(ns.Labels)
		}
		return result, nil
	}

	for _, ns := range namespaces {
		if ns == "" {
			continue
		}
		obj, err := clientset.CoreV1().Namespaces().Get(context.TODO(), ns, metav1.GetOptions{})
		if err != nil {
			continue
		}
		result[ns] = convertPSANamespaceLabels(obj.Labels)
	}
	return result, nil
}

func countResourcesByKind(resources []map[string]interface{}) map[string]int {
	totals := make(map[string]int)
	seen := make(map[string]struct{})
	for _, res := range resources {
		id := resourceIdentifier(res)
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		if kind, _ := res["kind"].(string); kind != "" {
			totals[kind]++
		}
	}
	return totals
}

func renderReport(reportMode, format string, reports []*bindingReport, resourceTotals map[string]int, resourceDetails []resourceDetail, w io.Writer, style table.Style, useColor bool) error {
	switch format {
	case "json":
		return renderJSONReport(reportMode, reports, resourceTotals, resourceDetails, w)
	case "table":
		printSummaryTables(reports, w, style)
		printResourceTotals(resourceTotals, w, style)
		printResourceNames(resourceDetails, w, style)
		if reportMode == "all" {
			printViolationLogs(reports, w, useColor)
		}
	default:
		return fmt.Errorf("unsupported format %s", format)
	}
	return nil
}

func renderJSONReport(reportMode string, reports []*bindingReport, resourceTotals map[string]int, details []resourceDetail, w io.Writer) error {
	type jsonReport struct {
		Report    string           `json:"report"`
		Format    string           `json:"format"`
		Data      []*bindingReport `json:"bindings"`
		Totals    map[string]int   `json:"resourceTotals,omitempty"`
		Resources []resourceDetail `json:"resources,omitempty"`
	}

	payload := jsonReport{
		Report: reportMode,
		Format: "json",
		Totals: resourceTotals,
	}

	if len(details) > 0 {
		payload.Resources = details
	}

	for _, br := range reports {
		copyReport := *br
		if reportMode != "all" {
			copyReport.Violations = nil
		}
		payload.Data = append(payload.Data, &copyReport)
	}

	encoded, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	fmt.Fprintln(w, string(encoded))
	return nil
}

func printSummaryTables(reports []*bindingReport, w io.Writer, style table.Style) {
	if len(reports) == 0 {
		fmt.Fprintln(w, "No policies evaluated.")
		return
	}

	t := table.NewWriter()
	t.SetOutputMirror(w)
	t.SetStyle(style)
	t.Style().Title.Align = text.AlignLeft

	t.AppendHeader(table.Row{"Policy", "Binding", "Mode", "Total", "Compliant", "NonCompliant"})
	var totalTotal, totalCompliant, totalNon int
	for _, br := range reports {
		t.AppendRow(table.Row{br.Policy, br.Binding, br.Mode, br.Total, br.Compliant, br.NonCompliant})
		totalTotal += br.Total
		totalCompliant += br.Compliant
		totalNon += br.NonCompliant
	}
	t.AppendSeparator()
	t.AppendRow(table.Row{"Totals", "", "", totalTotal, totalCompliant, totalNon})
	t.SetTitle("Policy Compliance Overview")
	fmt.Fprintln(w)
	t.Render()
}

func printResourceTotals(counts map[string]int, w io.Writer, style table.Style) {
	if len(counts) == 0 {
		return
	}

	t := table.NewWriter()
	t.SetOutputMirror(w)
	t.SetStyle(style)
	t.SetTitle("Resources by Kind")
	t.AppendHeader(table.Row{"Kind", "Total"})
	kinds := make([]string, 0, len(counts))
	for kind := range counts {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	for _, kind := range kinds {
		t.AppendRow(table.Row{kind, counts[kind]})
	}
	fmt.Fprintln(w)
	t.Render()
}

type resourceDetail struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
}

func collectResourceDetails(resources []map[string]interface{}) []resourceDetail {
	seen := make(map[string]struct{})
	var details []resourceDetail
	for _, res := range resources {
		id := resourceIdentifier(res)
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		kind, _ := res["kind"].(string)
		details = append(details, resourceDetail{
			Kind:      kind,
			Namespace: kubernetes.GetMetadataString(res, "namespace"),
			Name:      kubernetes.GetMetadataString(res, "name"),
		})
	}
	sort.Slice(details, func(i, j int) bool {
		if details[i].Kind == details[j].Kind {
			if details[i].Namespace == details[j].Namespace {
				return details[i].Name < details[j].Name
			}
			return details[i].Namespace < details[j].Namespace
		}
		return details[i].Kind < details[j].Kind
	})
	return details
}

func printResourceNames(details []resourceDetail, w io.Writer, style table.Style) {
	if len(details) == 0 {
		return
	}

	t := table.NewWriter()
	t.SetOutputMirror(w)
	t.SetStyle(style)
	t.SetTitle("Resources")
	t.AppendHeader(table.Row{"Kind", "Namespace", "Name"})
	for _, detail := range details {
		ns := detail.Namespace
		if ns == "" {
			ns = "<cluster>"
		}
		t.AppendRow(table.Row{detail.Kind, ns, detail.Name})
	}
	fmt.Fprintln(w)
	t.Render()
}

func printViolationLogs(reports []*bindingReport, w io.Writer, useColor bool) {
	fmt.Fprintln(w, "\nViolations")
	found := false
	for _, br := range reports {
		for _, violation := range br.Violations {
			found = true
			severity, formatter := violationSeverityColor(violation.Actions)
			if useColor {
				formatter.Fprintf(w, "[%s] Policy %s / Binding %s\n", strings.ToUpper(severity), violation.Policy, violation.Binding)
			} else {
				fmt.Fprintf(w, "[%s] Policy %s / Binding %s\n", strings.ToUpper(severity), violation.Policy, violation.Binding)
			}
			fmt.Fprintf(w, "Resource : %s\n", violation.Resource)
			fmt.Fprintf(w, "Message  : %s\n", violation.Message)
		}
	}
	if !found {
		fmt.Fprintln(w, "No violations detected.")
	}
}
func collectFiles(dir string) ([]string, error) {
	dirEntries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, entry := range dirEntries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !isManifestFile(name) {
			continue
		}
		files = append(files, filepath.Join(dir, name))
	}
	return files, nil
}

func isManifestFile(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".json")
}

func isPipeline(cmd *cobra.Command) bool {
	return lookupBoolFlag(cmd, "pipeline")
}

func lookupBoolFlag(cmd *cobra.Command, name string) bool {
	if cmd == nil {
		return false
	}
	if flag := cmd.Flags().Lookup(name); flag != nil {
		val, err := strconv.ParseBool(flag.Value.String())
		if err == nil {
			return val
		}
	}
	return lookupBoolFlag(cmd.Parent(), name)
}

// PSA Validation

func newValidatePSACmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "psa",
		Short: "Validate Pod Security Admission labels",
		RunE:  runValidatePSA,
	}
	cmd.Flags().StringP("resources", "r", "", "Path to resource manifest file or directory")
	cmd.Flags().Bool("remote-namespaces", false, "Fetch namespace labels from the Kubernetes API")
	cmd.Flags().String("report", "summary", "Report type: summary or all")
	cmd.Flags().String("level", "", "PSS level to evaluate: baseline or restricted")
	return cmd
}

func runValidatePSA(cmd *cobra.Command, _ []string) error {
	nsArg := cmd.Flags().Lookup("namespaces").Value.String()
	allNamespaces := lookupBoolFlag(cmd, "all-namespaces")
	format := strings.ToLower(cmd.Flags().Lookup("format").Value.String())
	outputPath := strings.TrimSpace(cmd.Flags().Lookup("output").Value.String())
	report := strings.ToLower(cmd.Flags().Lookup("report").Value.String())
	level := strings.ToLower(strings.TrimSpace(cmd.Flags().Lookup("level").Value.String()))
	if format != "table" && format != "json" {
		return fmt.Errorf("invalid output format %s, expected table or json", format)
	}
	if report != "summary" && report != "all" {
		return fmt.Errorf("invalid report type %s, expected summary or all", report)
	}
	if level != "" && level != "baseline" && level != "restricted" {
		return fmt.Errorf("invalid level %s, expected baseline or restricted", level)
	}

	resourcePath := cmd.Flags().Lookup("resources").Value.String()
	remoteNamespaces := lookupBoolFlag(cmd, "remote-namespaces")

	if resourcePath == "" && !remoteNamespaces {
		return fmt.Errorf("either --resources or --remote-namespaces must be specified")
	}
	if allNamespaces && !remoteNamespaces {
		return fmt.Errorf("--all-namespaces can only be used with --remote-namespaces")
	}
	if nsArg != "" && !remoteNamespaces {
		return fmt.Errorf("--namespaces can only be used with --remote-namespaces")
	}

	namespaces := parseNamespaces(nsArg)
	if allNamespaces && len(namespaces) > 0 {
		return fmt.Errorf("--all-namespaces cannot be used together with --namespaces")
	}
	if len(namespaces) == 0 && !allNamespaces && remoteNamespaces {
		namespaces = []string{kubernetes.ActiveNamespace()}
	}

	namespaceLabels := make(map[string]map[string]string)
	var pods []corev1.Pod
	var resources []map[string]interface{}

	if resourcePath != "" {
		localRes, localNS, err := loadLocalResources(resourcePath)
		if err != nil {
			return err
		}
		localRes = filterResourcesByNamespaces(localRes, namespaces, allNamespaces)
		namespaceLabels = mergeLabelMaps(namespaceLabels, localNS)
		resources = append(resources, localRes...)
		localPods, err := extractPodsFromResources(localRes)
		if err != nil {
			return err
		}
		pods = append(pods, localPods...)
	}

	if remoteNamespaces {
		remoteNS, err := fetchNamespaceLabels(namespaces, allNamespaces)
		if err != nil {
			return err
		}
		namespaceLabels = mergeLabelMaps(namespaceLabels, remoteNS)
	}

	policiesPath, bindingsPath, ok, err := locatePSAPolicies()
	if err != nil {
		return err
	}
	compliance := map[string]psaComplianceCounts{}
	vaps := []admissionregistrationv1.ValidatingAdmissionPolicy{}
	bindings := []admissionregistrationv1.ValidatingAdmissionPolicyBinding{}
	if ok {
		vaps, bindings, err = loadPSAPolicies(policiesPath, bindingsPath)
		if err != nil {
			return err
		}
		if resourcePath == "" && remoteNamespaces {
			scope := kubernetes.ResourceScopeSelected
			if allNamespaces {
				scope = kubernetes.ResourceScopeAllNamespaces
			}
			remoteRes, remoteNS, err := kubernetes.FetchResourcesForPolicies(vaps, scope, namespaces)
			if err != nil {
				return err
			}
			resources = append(resources, remoteRes...)
			namespaceLabels = mergeLabelMaps(namespaceLabels, remoteNS)
			remotePods, err := extractPodsFromResources(remoteRes)
			if err != nil {
				return err
			}
			pods = append(pods, remotePods...)
		}
		compliance, err = evaluatePSACompliance(vaps, bindings, resources, namespaceLabels, false, level)
		if err != nil {
			return err
		}
	} else {
		root, err := psaPoliciesDir()
		if err != nil {
			return err
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "PSA policy bundle not found in %s. Run `kubeapt policies psa download` to install.\n", root)
	}

	results, usesKolteq := summarizePSALevels(pods, namespaceLabels, namespaces, allNamespaces, compliance)
	hasViolations := false
	for _, res := range results {
		if res.NonCompliant > 0 {
			hasViolations = true
			break
		}
	}

	writer := io.Writer(os.Stdout)
	style := table.StyleRounded
	if outputPath != "" {
		f, err := os.Create(outputPath)
		if err != nil {
			return fmt.Errorf("failed to open output file: %w", err)
		}
		defer f.Close()
		writer = f
		style = table.StyleDefault
	}

	switch format {
	case "json":
		if err := renderPSAJSON(report, results, writer); err != nil {
			return err
		}
	default:
		printPSATable(results, usesKolteq, writer, style)
		if report == "all" {
			printPSAViolationLogs(results, writer, false)
		}
	}

	if hasViolations && isPipeline(cmd) {
		return fmt.Errorf("psa violations detected")
	}

	return nil
}

type psaNamespaceResult struct {
	Namespace    string            `json:"namespace"`
	Modes        map[string]string `json:"modes"`
	Pods         int               `json:"podsChecked"`
	Compliant    int               `json:"compliant"`
	NonCompliant int               `json:"nonCompliant"`
	Kolteq       map[string]bool   `json:"-"`
	Violations   []violationDetail `json:"violations,omitempty"`
}

func summarizePSALevels(pods []corev1.Pod, namespaceLabels map[string]map[string]string, namespaces []string, all bool, compliance map[string]psaComplianceCounts) ([]psaNamespaceResult, bool) {
	results := make(map[string]*psaNamespaceResult)
	usesKolteq := namespaceLabelsUseKolteq(namespaceLabels)
	target := make(map[string]struct{})
	for _, ns := range namespaces {
		if ns != "" {
			target[ns] = struct{}{}
		}
	}
	includeNamespace := func(ns string) bool {
		if all || len(target) == 0 {
			return true
		}
		_, ok := target[ns]
		return ok
	}

	addNamespace := func(ns string, labels map[string]string) *psaNamespaceResult {
		if res, ok := results[ns]; ok {
			return res
		}
		labels = convertPSANamespaceLabels(labels)
		kolteqModes := make(map[string]bool)
		for _, mode := range []string{"enforce", "audit", "warn"} {
			if _, ok := labels["pss.security.kolteq.com/"+mode]; ok {
				kolteqModes[mode] = true
				usesKolteq = true
				continue
			}
			if _, ok := labels["pss.kolteq.com/"+mode]; ok {
				kolteqModes[mode] = true
				usesKolteq = true
			}
		}
		res := &psaNamespaceResult{
			Namespace: ns,
			Modes:     convertPSALabels(labels),
			Kolteq:    kolteqModes,
		}
		results[ns] = res
		return res
	}

	for _, pod := range pods {
		ns := pod.Namespace
		if ns == "" {
			ns = kubernetes.ActiveNamespace()
		}
		if ns == "" {
			ns = "default"
		}
		if !includeNamespace(ns) {
			continue
		}
		nsLabels := namespaceLabels[ns]
		nsResult := addNamespace(ns, nsLabels)
		nsResult.Pods++
	}

	for ns, labels := range namespaceLabels {
		if !includeNamespace(ns) {
			continue
		}
		addNamespace(ns, labels)
	}

	for _, ns := range namespaces {
		if ns == "" {
			continue
		}
		if _, ok := results[ns]; !ok && includeNamespace(ns) {
			addNamespace(ns, nil)
		}
	}

	for ns, counts := range compliance {
		if !includeNamespace(ns) {
			continue
		}
		res := addNamespace(ns, namespaceLabels[ns])
		res.Compliant = counts.Compliant
		res.NonCompliant = counts.NonCompliant
		res.Violations = counts.Violations
	}

	var sorted []psaNamespaceResult
	for _, res := range results {
		sorted = append(sorted, *res)
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Namespace < sorted[j].Namespace
	})

	return sorted, usesKolteq
}

func renderPSAJSON(report string, results []psaNamespaceResult, w io.Writer) error {
	payload := make([]psaNamespaceResult, 0, len(results))
	for _, res := range results {
		copyRes := res
		if report != "all" {
			copyRes.Violations = nil
		} else {
			copyRes.Violations = mergePSAViolations(copyRes.Violations)
		}
		payload = append(payload, copyRes)
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	fmt.Fprintln(w, string(data))
	return nil
}

func printPSATable(results []psaNamespaceResult, kolteq bool, w io.Writer, style table.Style) {
	t := table.NewWriter()
	t.SetOutputMirror(w)
	t.SetStyle(style)
	t.SetTitle("PSA Namespace Levels")
	t.AppendHeader(table.Row{"Namespace", "Enforce", "Audit", "Warn", "Compliant", "Incompliant"})
	var totalCompliant, totalNonCompliant int
	for _, res := range results {
		t.AppendRow(table.Row{
			res.Namespace,
			formatPSAMode(res.Modes, res.Kolteq, "enforce", kolteq),
			formatPSAMode(res.Modes, res.Kolteq, "audit", kolteq),
			formatPSAMode(res.Modes, res.Kolteq, "warn", kolteq),
			res.Compliant,
			res.NonCompliant,
		})
		totalCompliant += res.Compliant
		totalNonCompliant += res.NonCompliant
	}
	if len(results) > 0 {
		t.AppendSeparator()
		t.AppendRow(table.Row{"Totals", "", "", "", totalCompliant, totalNonCompliant})
	}
	fmt.Fprintln(w)
	t.Render()
}

func printPSAViolationLogs(results []psaNamespaceResult, w io.Writer, useColor bool) {
	fmt.Fprintln(w, "\nViolations")
	found := false
	for _, res := range results {
		for _, violation := range mergePSAViolations(res.Violations) {
			found = true
			_, formatter := violationSeverityColor(violation.Actions)
			label := strings.ToUpper(strings.Join(formatViolationActions(violation.Actions), "/"))
			if useColor {
				formatter.Fprintf(w, "[%s] Policy %s / Binding %s\n", label, violation.Policy, violation.Binding)
			} else {
				fmt.Fprintf(w, "[%s] Policy %s / Binding %s\n", label, violation.Policy, violation.Binding)
			}
			fmt.Fprintf(w, "Resource : %s\n", violation.Resource)
			fmt.Fprintf(w, "Message  : %s\n", violation.Message)
			if violation.Path != "" {
				fmt.Fprintf(w, "Path     : %s\n", violation.Path)
			}
		}
	}
	if !found {
		fmt.Fprintln(w, "No violations detected.")
	}
}

func mergePSAViolations(violations []violationDetail) []violationDetail {
	type agg struct {
		detail      violationDetail
		actionSet   map[string]struct{}
		bestAction  int
		seenBinding bool
	}
	aggMap := make(map[string]*agg)
	for _, v := range violations {
		base := psaBindingBase(v.Binding)
		key := strings.Join([]string{v.Policy, base, v.Resource, v.Message, v.Path}, "|")
		entry, ok := aggMap[key]
		if !ok {
			entry = &agg{
				detail:    violationDetail{Policy: v.Policy, Binding: v.Binding, Resource: v.Resource, Message: v.Message, Path: v.Path},
				actionSet: make(map[string]struct{}),
			}
			aggMap[key] = entry
		}
		for _, action := range v.Actions {
			canonical := canonicalAction(action)
			entry.actionSet[canonical] = struct{}{}
			if priority := actionPriority(canonical); priority > entry.bestAction {
				entry.bestAction = priority
				entry.detail.Binding = v.Binding
				entry.seenBinding = true
			}
		}
		if !entry.seenBinding {
			entry.detail.Binding = v.Binding
		}
	}

	merged := make([]violationDetail, 0, len(aggMap))
	for _, entry := range aggMap {
		entry.detail.Actions = formatViolationActionsFromSet(entry.actionSet)
		merged = append(merged, entry.detail)
	}
	return merged
}

func psaBindingBase(name string) string {
	for _, suffix := range []string{"-deny", "-audit", "-warn"} {
		if strings.HasSuffix(name, suffix) {
			return strings.TrimSuffix(name, suffix)
		}
	}
	return name
}

func canonicalAction(action string) string {
	switch strings.ToLower(action) {
	case "deny":
		return "Deny"
	case "warn":
		return "Warn"
	case "audit":
		return "Audit"
	default:
		return action
	}
}

func actionPriority(action string) int {
	switch strings.ToLower(action) {
	case "deny":
		return 3
	case "audit":
		return 2
	case "warn":
		return 1
	default:
		return 0
	}
}

func formatViolationActions(actions []string) []string {
	return formatViolationActionsFromSet(listToSet(actions))
}

func formatViolationActionsFromSet(actions map[string]struct{}) []string {
	ordered := make([]string, 0, len(actions))
	for _, action := range []string{"Deny", "Warn", "Audit"} {
		if _, ok := actions[action]; ok {
			ordered = append(ordered, action)
			delete(actions, action)
		}
	}
	for action := range actions {
		ordered = append(ordered, action)
	}
	return ordered
}

func listToSet(actions []string) map[string]struct{} {
	set := make(map[string]struct{}, len(actions))
	for _, action := range actions {
		set[canonicalAction(action)] = struct{}{}
	}
	return set
}

func formatPSAMode(modes map[string]string, kolteqModes map[string]bool, mode string, kolteq bool) string {
	if modes == nil {
		return "-"
	}
	label := modes[mode]
	if label == "" {
		return "-"
	}
	if kolteq && kolteqModes != nil && kolteqModes[mode] {
		return label + " (KolTEQ)"
	}
	return label
}

func convertPSALabels(labels map[string]string) map[string]string {
	result := make(map[string]string)
	if labels == nil {
		return result
	}
	for k, v := range labels {
		canonical := ""
		switch {
		case strings.HasPrefix(k, "pod-security.kubernetes.io/"):
			canonical = strings.TrimPrefix(k, "pod-security.kubernetes.io/")
		case strings.HasPrefix(k, "pss.security.kolteq.com/"):
			canonical = strings.TrimPrefix(k, "pss.security.kolteq.com/")
		default:
			continue
		}
		if canonical != "enforce" && canonical != "audit" && canonical != "warn" {
			continue
		}
		if v == "" {
			continue
		}
		result[canonical] = v
	}
	return result
}

func namespaceLabelsUseKolteq(labels map[string]map[string]string) bool {
	for _, nsLabels := range labels {
		for k := range nsLabels {
			if strings.Contains(k, "pss.security.kolteq.com/") {
				return true
			}
		}
	}
	return false
}

func hasKolteqMode(labels map[string]string, mode string) bool {
	if labels == nil {
		return false
	}
	for k := range labels {
		if strings.HasSuffix(k, "/"+mode) && strings.Contains(k, "pss.security.kolteq.com/") {
			return true
		}
	}
	return false
}

func convertPSANamespaceLabels(labels map[string]string) map[string]string {
	if len(labels) == 0 {
		return make(map[string]string)
	}

	result := make(map[string]string, len(labels))
	for k, v := range labels {
		result[k] = v
	}

	return result
}
