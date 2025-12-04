// Copyright by KolTEQ GmbH
// Contact: benjamin@kolteq.com

package cmd

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/spf13/cobra"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubeclient "k8s.io/client-go/kubernetes"

	"github.com/kolteq/kubeapt/internal/kubernetes"
)

const (
	psaLabelEnforce = "pod-security.kubernetes.io/enforce"
	psaLabelAudit   = "pod-security.kubernetes.io/audit"
	psaLabelWarn    = "pod-security.kubernetes.io/warn"
)

func ScanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan the connected cluster for admission safeguards",
		RunE:  runScan,
	}
	return cmd
}

func runScan(cmd *cobra.Command, _ []string) error {
	clientset, err := kubernetes.Init()
	if err != nil {
		return err
	}

	fmt.Println("[1/3] Inspecting namespaces and admission controllers...")
	if err := reportPSSAndPolicies(clientset); err != nil {
		return err
	}

	fmt.Println("\n[2/3] Inspecting built-in admission plugins...")
	if err := reportBuiltInAdmissionControllers(clientset); err != nil {
		return err
	}

	fmt.Println("\n[3/3] Inspecting registered webhooks...")
	if err := reportWebhooks(clientset); err != nil {
		return err
	}

	return nil
}

func reportPSSAndPolicies(clientset *kubeclient.Clientset) error {
	nsList, err := clientset.CoreV1().Namespaces().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.SetStyle(table.StyleRounded)
	t.Style().Title.Align = text.AlignLeft
	t.SetTitle("PSA Namespace Summary")
	t.AppendHeader(table.Row{"Namespace", "Enforce", "Audit", "Warn", "Pods", "Violations"})

	for _, ns := range nsList.Items {
		labels := convertPSALabels(map[string]string{
			"pod-security.kubernetes.io/enforce": ns.Labels[psaLabelEnforce],
			"pod-security.kubernetes.io/audit":   ns.Labels[psaLabelAudit],
			"pod-security.kubernetes.io/warn":    ns.Labels[psaLabelWarn],
		})
		t.AppendRow(table.Row{
			ns.Name,
			formatPSAMode(labels, "enforce"),
			formatPSAMode(labels, "audit"),
			formatPSAMode(labels, "warn"),
			"-",
			"-",
		})
	}

	fmt.Println()
	t.Render()

	vaps, err := kubernetes.GetRemoteValidatingAdmissionPolicies()
	if err != nil {
		fmt.Printf("Error fetching ValidatingAdmissionPolicies: %v\n", err)
	} else if len(vaps) > 0 {
		fmt.Printf("ValidatingAdmissionPolicies present: %d\n", len(vaps))
	} else {
		fmt.Println("No ValidatingAdmissionPolicies detected.")
	}

	kyverno, gatekeeper := detectThirdPartyAdmissionControllers(clientset)
	if kyverno {
		fmt.Println("Kyverno detected in cluster")
	}
	if gatekeeper {
		fmt.Println("OPA Gatekeeper detected in cluster")
	}
	if !kyverno && !gatekeeper {
		fmt.Println("No Kyverno/Gatekeeper controllers detected.")
	}

	return nil
}

func extractPSSLabels(labels map[string]string) []string {
	result := make([]string, 0, 3)
	for k, v := range labels {
		if strings.HasPrefix(k, "pod-security.kubernetes.io/") && v != "" {
			result = append(result, fmt.Sprintf("%s=%s", strings.TrimPrefix(k, "pod-security.kubernetes.io/"), v))
		}
	}
	sort.Strings(result)
	return result
}

func detectThirdPartyAdmissionControllers(clientset *kubeclient.Clientset) (kyverno bool, gatekeeper bool) {
	deployments, err := clientset.AppsV1().Deployments("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return false, false
	}
	for _, dep := range deployments.Items {
		name := strings.ToLower(dep.Name)
		ns := strings.ToLower(dep.Namespace)
		if strings.Contains(name, "kyverno") || ns == "kyverno" {
			kyverno = true
		}
		if strings.Contains(name, "gatekeeper") || ns == "gatekeeper-system" {
			gatekeeper = true
		}
	}
	return
}

func reportBuiltInAdmissionControllers(clientset *kubeclient.Clientset) error {
	pods, err := clientset.CoreV1().Pods("kube-system").List(context.TODO(), metav1.ListOptions{LabelSelector: "component=kube-apiserver"})
	if err != nil {
		return err
	}
	if len(pods.Items) == 0 {
		pods, err = clientset.CoreV1().Pods("kube-system").List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			return err
		}
	}

	enabled := map[string]struct{}{}
	disabled := map[string]struct{}{}

	for _, pod := range pods.Items {
		if !strings.Contains(pod.Name, "kube-apiserver") {
			continue
		}
		args := append([]string{}, pod.Spec.Containers[0].Command...)
		args = append(args, pod.Spec.Containers[0].Args...)
		for _, arg := range args {
			if strings.HasPrefix(arg, "--enable-admission-plugins=") {
				list := strings.TrimPrefix(arg, "--enable-admission-plugins=")
				for _, plugin := range strings.Split(list, ",") {
					plugin = strings.TrimSpace(plugin)
					if plugin != "" {
						enabled[plugin] = struct{}{}
					}
				}
			}
			if strings.HasPrefix(arg, "--disable-admission-plugins=") {
				list := strings.TrimPrefix(arg, "--disable-admission-plugins=")
				for _, plugin := range strings.Split(list, ",") {
					plugin = strings.TrimSpace(plugin)
					if plugin != "" {
						disabled[plugin] = struct{}{}
					}
				}
			}
			if strings.HasPrefix(arg, "--admission-control=") {
				list := strings.TrimPrefix(arg, "--admission-control=")
				for _, plugin := range strings.Split(list, ",") {
					plugin = strings.TrimSpace(plugin)
					if plugin != "" {
						enabled[plugin] = struct{}{}
					}
				}
			}
		}
	}

	if len(enabled) == 0 {
		fmt.Println("Could not determine enabled admission plugins (kube-apiserver pod not found or flags missing).")
		return nil
	}

	fmt.Println("Enabled admission plugins:")
	fmt.Println(strings.Join(sortedKeys(enabled), ", "))
	if len(disabled) > 0 {
		fmt.Println("Disabled admission plugins:")
		fmt.Println(strings.Join(sortedKeys(disabled), ", "))
	}

	return nil
}

func sortedKeys(m map[string]struct{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func reportWebhooks(clientset *kubeclient.Clientset) error {
	validating, err := clientset.AdmissionregistrationV1().ValidatingWebhookConfigurations().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return err
	}
	mutating, err := clientset.AdmissionregistrationV1().MutatingWebhookConfigurations().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	if len(validating.Items) > 0 {
		printWebhookTable("Validating Webhook Configurations", validatingWebhookRows(validating.Items))
	} else {
		fmt.Println("No ValidatingWebhookConfigurations found.")
	}

	if len(mutating.Items) > 0 {
		printWebhookTable("Mutating Webhook Configurations", mutatingWebhookRows(mutating.Items))
	} else {
		fmt.Println("No MutatingWebhookConfigurations found.")
	}

	return nil
}

func printWebhookTable(title string, rows []table.Row) {
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.SetStyle(table.StyleRounded)
	t.Style().Title.Align = text.AlignLeft
	t.SetTitle(title)
	t.AppendHeader(table.Row{"Config", "Webhook", "Target"})
	for _, row := range rows {
		t.AppendRow(row)
	}
	fmt.Println()
	t.Render()
}

func validatingWebhookRows(configs []admissionv1.ValidatingWebhookConfiguration) []table.Row {
	var rows []table.Row
	for _, cfg := range configs {
		for _, wh := range cfg.Webhooks {
			rows = append(rows, table.Row{cfg.Name, wh.Name, describeClientConfig(wh.ClientConfig)})
		}
	}
	return rows
}

func mutatingWebhookRows(configs []admissionv1.MutatingWebhookConfiguration) []table.Row {
	var rows []table.Row
	for _, cfg := range configs {
		for _, wh := range cfg.Webhooks {
			rows = append(rows, table.Row{cfg.Name, wh.Name, describeClientConfig(wh.ClientConfig)})
		}
	}
	return rows
}

func describeClientConfig(cfg admissionv1.WebhookClientConfig) string {
	if cfg.URL != nil && *cfg.URL != "" {
		return *cfg.URL
	}
	if cfg.Service != nil {
		host := fmt.Sprintf("%s/%s", cfg.Service.Namespace, cfg.Service.Name)
		if cfg.Service.Path != nil {
			host += *cfg.Service.Path
		}
		return host
	}
	return "<unknown>"
}
