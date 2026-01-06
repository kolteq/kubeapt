// Copyright by KolTEQ GmbH
// Contact: benjamin@kolteq.com

package cmd

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/restmapper"

	"github.com/kolteq/kubeapt/internal/kubernetes"
)

const (
	psaPoliciesArchiveURL = "https://github.com/kolteq/validating-admission-policies-pss/archive/refs/heads/main.tar.gz"
	psaPoliciesDirName    = "pod-security-standards"
	psaPoliciesSubdir     = "policies"
	psaBindingsSubdir     = "bindings"
	psaLabelPrefixNative  = "pod-security.kubernetes.io/"
	psaLabelPrefixKolteq  = "pss.security.kolteq.com/"
)

func PoliciesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policies",
		Short: "Manage policy bundles",
	}
	cmd.AddCommand(newPoliciesPSACmd())
	return cmd
}

func newPoliciesPSACmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "psa",
		Short: "Pod Security Admission policies",
	}
	cmd.AddCommand(newPoliciesPSADownloadCmd())
	cmd.AddCommand(newPoliciesPSADeployCmd())
	cmd.AddCommand(newPoliciesPSADeleteDeployCmd())
	cmd.AddCommand(newPoliciesPSALabelCmd("enforce"))
	cmd.AddCommand(newPoliciesPSALabelCmd("audit"))
	cmd.AddCommand(newPoliciesPSALabelCmd("warn"))
	return cmd
}

func newPoliciesPSADownloadCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "download",
		Short: "Download the KolTEQ Pod Security Standards policies",
		RunE:  runPoliciesPSADownload,
	}
	return cmd
}

func newPoliciesPSADeployCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "deploy",
		Short: "Deploy PSA policies to the cluster",
		RunE:  runPoliciesPSADeploy,
	}
	return cmd
}

func newPoliciesPSADeleteDeployCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete-deploy",
		Short: "Remove PSA policies from the cluster",
		RunE:  runPoliciesPSADeleteDeploy,
	}
	return cmd
}

func runPoliciesPSADeploy(cmd *cobra.Command, _ []string) error {
	policiesPath, _, ok, err := locatePSAPolicies()
	if err != nil {
		return err
	}
	if !ok {
		root, err := psaPoliciesDir()
		if err != nil {
			return err
		}
		return fmt.Errorf("PSA policy bundle not found in %s. Run `kubeapt policies psa download` to install", root)
	}
	resources, err := loadPSAKustomizeResources(policiesPath)
	if err != nil {
		return err
	}
	tracker, stop := startProgress("Deploying PSA policies", int64(len(resources)), true)
	defer stop()
	return applyKustomizeResources(resources, func() {
		tracker.Increment(1)
	})
}

func runPoliciesPSADeleteDeploy(cmd *cobra.Command, _ []string) error {
	policiesPath, _, ok, err := locatePSAPolicies()
	if err != nil {
		return err
	}
	if !ok {
		root, err := psaPoliciesDir()
		if err != nil {
			return err
		}
		return fmt.Errorf("PSA policy bundle not found in %s. Run `kubeapt policies psa download` to install", root)
	}
	resources, err := loadPSAKustomizeResources(policiesPath)
	if err != nil {
		return err
	}
	tracker, stop := startProgress("Deleting PSA policies", int64(len(resources)), true)
	defer stop()
	return deleteKustomizeResources(resources, func() {
		tracker.Increment(1)
	})
}

func newPoliciesPSALabelCmd(mode string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   fmt.Sprintf("%s <level>", mode),
		Short: fmt.Sprintf("Set the PSA %s level on a namespace", mode),
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPoliciesPSALabel(cmd, mode, args[0])
		},
	}
	cmd.Flags().StringP("namespace", "n", "", "Namespace to label")
	cmd.Flags().BoolP("all-namespaces", "A", false, "Apply the label to all namespaces")
	cmd.Flags().Bool("kubernetes-native", false, "Use the Kubernetes native Pod Security label")
	cmd.Flags().Bool("overwrite", false, "Overwrite an existing PSA label")
	cmd.Flags().Bool("remove", false, "Remove the PSA label instead of setting it")
	return cmd
}

func runPoliciesPSALabel(cmd *cobra.Command, mode, levelArg string) error {
	level := strings.ToLower(strings.TrimSpace(levelArg))
	if !isValidPSALevel(level) {
		return fmt.Errorf("invalid level %s, expected baseline, restricted, or privileged", levelArg)
	}
	flags := cmd.Flags()
	namespace, err := flags.GetString("namespace")
	if err != nil {
		return err
	}
	allNamespaces, err := flags.GetBool("all-namespaces")
	if err != nil {
		return err
	}
	if allNamespaces && namespace != "" {
		return fmt.Errorf("--all-namespaces cannot be used together with --namespace")
	}
	if !allNamespaces && namespace == "" {
		return fmt.Errorf("either --namespace or --all-namespaces must be specified")
	}
	useNative, err := flags.GetBool("kubernetes-native")
	if err != nil {
		return err
	}
	overwrite, err := flags.GetBool("overwrite")
	if err != nil {
		return err
	}
	remove, err := flags.GetBool("remove")
	if err != nil {
		return err
	}

	clientset, err := kubernetes.Init()
	if err != nil {
		return err
	}

	nativeKey := psaLabelPrefixNative + mode
	kolteqKey := psaLabelPrefixKolteq + mode
	targetKey := kolteqKey
	if useNative {
		targetKey = nativeKey
	}

	namespaces := []string{namespace}
	if allNamespaces {
		nsList, err := clientset.CoreV1().Namespaces().List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			return err
		}
		namespaces = make([]string, 0, len(nsList.Items))
		for _, ns := range nsList.Items {
			namespaces = append(namespaces, ns.Name)
		}
	}

	if !overwrite && !remove {
		for _, nsName := range namespaces {
			nsObj, err := clientset.CoreV1().Namespaces().Get(context.TODO(), nsName, metav1.GetOptions{})
			if err != nil {
				return err
			}
			labels := nsObj.Labels
			if labels == nil {
				continue
			}
			if _, has := labels[nativeKey]; has {
				return fmt.Errorf("namespace %s already has a PSA %s label; use --overwrite to update it", nsName, mode)
			}
			if _, has := labels[kolteqKey]; has {
				return fmt.Errorf("namespace %s already has a PSA %s label; use --overwrite to update it", nsName, mode)
			}
		}
	}

	for _, nsName := range namespaces {
		nsObj, err := clientset.CoreV1().Namespaces().Get(context.TODO(), nsName, metav1.GetOptions{})
		if err != nil {
			return err
		}
		labels := nsObj.Labels
		if labels == nil {
			labels = make(map[string]string)
		}

		if remove {
			if _, ok := labels[targetKey]; !ok {
				if !allNamespaces {
					return fmt.Errorf("label %s is not set on namespace %s", targetKey, nsName)
				}
				continue
			}
			delete(labels, targetKey)
			nsObj.Labels = labels
			if _, err := clientset.CoreV1().Namespaces().Update(context.TODO(), nsObj, metav1.UpdateOptions{}); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Removed %s from namespace %s\n", targetKey, nsName)
			continue
		}

		if overwrite {
			delete(labels, nativeKey)
			delete(labels, kolteqKey)
		}
		labels[targetKey] = level
		nsObj.Labels = labels
		if _, err := clientset.CoreV1().Namespaces().Update(context.TODO(), nsObj, metav1.UpdateOptions{}); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Set %s=%s on namespace %s\n", targetKey, level, nsName)
	}

	return nil
}

type kustomizationSpec struct {
	Resources []string `yaml:"resources"`
	Bases     []string `yaml:"bases"`
}

func loadPSAKustomizeResources(root string) ([]*unstructured.Unstructured, error) {
	manifestFiles, err := collectKustomizeManifestFiles(root)
	if err != nil {
		return nil, err
	}
	if len(manifestFiles) == 0 {
		return nil, fmt.Errorf("no resources found in %s", root)
	}
	return loadUnstructuredResources(manifestFiles)
}

func collectKustomizeManifestFiles(root string) ([]string, error) {
	kustomizationPath, err := findKustomizationFile(root)
	if err != nil {
		return nil, err
	}
	if kustomizationPath == "" {
		return collectManifestFilesRecursive(root)
	}
	spec, err := readKustomization(kustomizationPath)
	if err != nil {
		return nil, err
	}
	resources := append([]string{}, spec.Resources...)
	resources = append(resources, spec.Bases...)
	if len(resources) == 0 {
		return nil, fmt.Errorf("kustomization in %s does not declare resources", root)
	}
	var files []string
	baseDir := filepath.Dir(kustomizationPath)
	for _, entry := range resources {
		if entry == "" {
			continue
		}
		path := entry
		if !filepath.IsAbs(path) {
			path = filepath.Join(baseDir, entry)
		}
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		if info.IsDir() {
			nested, err := collectKustomizeManifestFiles(path)
			if err != nil {
				return nil, err
			}
			files = append(files, nested...)
			continue
		}
		if isKustomizationFile(filepath.Base(path)) {
			continue
		}
		files = append(files, path)
	}
	return files, nil
}

func findKustomizationFile(root string) (string, error) {
	info, err := os.Stat(root)
	if err != nil {
		return "", err
	}
	dir := root
	if !info.IsDir() {
		dir = filepath.Dir(root)
	}
	for _, name := range []string{"kustomization.yaml", "kustomization.yml", "Kustomization"} {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}
	return "", nil
}

func isKustomizationFile(name string) bool {
	switch strings.ToLower(name) {
	case "kustomization", "kustomization.yaml", "kustomization.yml":
		return true
	default:
		return false
	}
}

func readKustomization(path string) (kustomizationSpec, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return kustomizationSpec{}, err
	}
	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return kustomizationSpec{}, err
	}
	allowed := map[string]struct{}{
		"resources":  {},
		"bases":      {},
		"apiVersion": {},
		"kind":       {},
	}
	for key := range raw {
		if _, ok := allowed[key]; !ok {
			return kustomizationSpec{}, fmt.Errorf("kustomization field %q is not supported", key)
		}
	}
	var spec kustomizationSpec
	if err := yaml.Unmarshal(data, &spec); err != nil {
		return kustomizationSpec{}, err
	}
	return spec, nil
}

func loadUnstructuredResources(files []string) ([]*unstructured.Unstructured, error) {
	var resources []*unstructured.Unstructured
	for _, path := range files {
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		decoder := utilyaml.NewYAMLOrJSONDecoder(file, 4096)
		for {
			var raw runtime.RawExtension
			if err := decoder.Decode(&raw); err != nil {
				if err == io.EOF {
					break
				}
				file.Close()
				return nil, err
			}
			if len(bytes.TrimSpace(raw.Raw)) == 0 {
				continue
			}
			var obj map[string]interface{}
			if err := json.Unmarshal(raw.Raw, &obj); err != nil {
				file.Close()
				return nil, err
			}
			if len(obj) == 0 {
				continue
			}
			resources = append(resources, &unstructured.Unstructured{Object: obj})
		}
		file.Close()
	}
	return resources, nil
}

func applyKustomizeResources(resources []*unstructured.Unstructured, onProgress func()) error {
	config, err := kubernetes.Config()
	if err != nil {
		return err
	}
	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return err
	}
	discoveryClient, err := discovery.NewDiscoveryClientForConfig(config)
	if err != nil {
		return err
	}
	groupResources, err := restmapper.GetAPIGroupResources(discoveryClient)
	if err != nil {
		return err
	}
	mapper := restmapper.NewDiscoveryRESTMapper(groupResources)

	for _, resource := range resources {
		gvk := resource.GroupVersionKind()
		if gvk.Empty() {
			return fmt.Errorf("resource is missing apiVersion or kind")
		}
		mapping, err := mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
		if err != nil {
			return err
		}
		name := resource.GetName()
		if name == "" {
			return fmt.Errorf("resource %s missing metadata.name", gvk.String())
		}
		var client dynamic.ResourceInterface
		if mapping.Scope.Name() == meta.RESTScopeNameNamespace {
			ns := resource.GetNamespace()
			if ns == "" {
				ns = kubernetes.ActiveNamespace()
				if ns == "" {
					ns = "default"
				}
				resource.SetNamespace(ns)
			}
			client = dynamicClient.Resource(mapping.Resource).Namespace(ns)
		} else {
			client = dynamicClient.Resource(mapping.Resource)
		}
		payload, err := json.Marshal(resource.Object)
		if err != nil {
			return err
		}
		_, err = client.Patch(context.TODO(), name, types.ApplyPatchType, payload, metav1.PatchOptions{
			FieldManager: "kubeapt",
		})
		if err != nil {
			return err
		}
		if onProgress != nil {
			onProgress()
		}
	}
	return nil
}

func deleteKustomizeResources(resources []*unstructured.Unstructured, onProgress func()) error {
	config, err := kubernetes.Config()
	if err != nil {
		return err
	}
	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return err
	}
	discoveryClient, err := discovery.NewDiscoveryClientForConfig(config)
	if err != nil {
		return err
	}
	groupResources, err := restmapper.GetAPIGroupResources(discoveryClient)
	if err != nil {
		return err
	}
	mapper := restmapper.NewDiscoveryRESTMapper(groupResources)

	for i := len(resources) - 1; i >= 0; i-- {
		resource := resources[i]
		gvk := resource.GroupVersionKind()
		if gvk.Empty() {
			return fmt.Errorf("resource is missing apiVersion or kind")
		}
		mapping, err := mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
		if err != nil {
			return err
		}
		name := resource.GetName()
		if name == "" {
			return fmt.Errorf("resource %s missing metadata.name", gvk.String())
		}
		var client dynamic.ResourceInterface
		if mapping.Scope.Name() == meta.RESTScopeNameNamespace {
			ns := resource.GetNamespace()
			if ns == "" {
				ns = kubernetes.ActiveNamespace()
				if ns == "" {
					ns = "default"
				}
				resource.SetNamespace(ns)
			}
			client = dynamicClient.Resource(mapping.Resource).Namespace(ns)
		} else {
			client = dynamicClient.Resource(mapping.Resource)
		}
		err = client.Delete(context.TODO(), name, metav1.DeleteOptions{})
		if apierrors.IsNotFound(err) {
			if onProgress != nil {
				onProgress()
			}
			continue
		}
		if err != nil {
			return err
		}
		if onProgress != nil {
			onProgress()
		}
	}
	return nil
}

func isValidPSALevel(level string) bool {
	switch level {
	case "baseline", "restricted", "privileged":
		return true
	default:
		return false
	}
}

func runPoliciesPSADownload(cmd *cobra.Command, _ []string) error {
	dest, err := psaPoliciesDir()
	if err != nil {
		return err
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Downloading PSA policies to %s\n", dest)
	if err := downloadPSAPolicies(dest); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "PSA policies ready in %s\n", dest)
	return nil
}

func psaPoliciesDir() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(configDir, "kubeapt", psaPoliciesDirName), nil
}

func psaPoliciesPath() (string, error) {
	root, err := psaPoliciesDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, psaPoliciesSubdir), nil
}

func psaBindingsPath() (string, error) {
	root, err := psaPoliciesDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, psaBindingsSubdir), nil
}

func locatePSAPolicies() (string, string, bool, error) {
	policiesPath, err := psaPoliciesPath()
	if err != nil {
		return "", "", false, err
	}
	info, err := os.Stat(policiesPath)
	if err != nil {
		if os.IsNotExist(err) {
			return policiesPath, "", false, nil
		}
		return "", "", false, err
	}
	if !info.IsDir() {
		return "", "", false, fmt.Errorf("psa policies path %s is not a directory", policiesPath)
	}

	bindingsPath, err := psaBindingsPath()
	if err != nil {
		return "", "", false, err
	}
	if info, err := os.Stat(bindingsPath); err == nil && info.IsDir() {
		return policiesPath, bindingsPath, true, nil
	}
	return policiesPath, policiesPath, true, nil
}

func loadPoliciesFromFilesWithProgress(files []string, onFile func()) ([]admissionregistrationv1.ValidatingAdmissionPolicy, error) {
	var policies []admissionregistrationv1.ValidatingAdmissionPolicy
	for _, file := range files {
		items, err := kubernetes.GetLocalValidatingAdmissionPolicies(file)
		if err != nil {
			return nil, err
		}
		policies = append(policies, items...)
		if onFile != nil {
			onFile()
		}
	}
	return policies, nil
}

func loadBindingsFromFilesWithProgress(files []string, onFile func()) ([]admissionregistrationv1.ValidatingAdmissionPolicyBinding, error) {
	var bindings []admissionregistrationv1.ValidatingAdmissionPolicyBinding
	for _, file := range files {
		items, err := kubernetes.GetLocalValidatingAdmissionPolicyBindings(file)
		if err != nil {
			return nil, err
		}
		bindings = append(bindings, items...)
		if onFile != nil {
			onFile()
		}
	}
	return bindings, nil
}

func collectManifestFilesRecursive(root string) ([]string, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return []string{root}, nil
	}
	var files []string
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		name := strings.ToLower(entry.Name())
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".json") {
			return nil
		}
		files = append(files, path)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return files, nil
}

func downloadPSAPolicies(dest string) error {
	parentDir := filepath.Dir(dest)
	if err := os.MkdirAll(parentDir, 0o755); err != nil {
		return err
	}

	tempDir, err := os.MkdirTemp(parentDir, "psa-download-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tempDir)

	archivePath := filepath.Join(tempDir, "psa-policies.tar.gz")
	if err := downloadFile(psaPoliciesArchiveURL, archivePath); err != nil {
		return err
	}

	extractDir := filepath.Join(tempDir, "extract")
	if err := os.MkdirAll(extractDir, 0o755); err != nil {
		return err
	}
	if err := extractTarGz(archivePath, extractDir); err != nil {
		return err
	}

	rootDir, err := findSingleDir(extractDir)
	if err != nil {
		return err
	}
	if rootDir == "" {
		rootDir = extractDir
	}

	if err := os.RemoveAll(dest); err != nil {
		return err
	}
	if err := os.Rename(rootDir, dest); err == nil {
		return nil
	}

	if err := os.MkdirAll(dest, 0o755); err != nil {
		return err
	}
	return copyDir(rootDir, dest)
}

func downloadFile(url, dest string) error {
	client := &http.Client{Timeout: 60 * time.Second}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "kubeapt")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: %s", resp.Status)
	}

	out, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

func extractTarGz(archivePath, dest string) error {
	file, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer file.Close()

	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gzipReader.Close()

	reader := tar.NewReader(gzipReader)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		target, err := safeJoin(dest, header.Name)
		if err != nil {
			return err
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(header.Mode)); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(header.Mode))
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, reader); err != nil {
				out.Close()
				return err
			}
			if err := out.Close(); err != nil {
				return err
			}
		case tar.TypeSymlink, tar.TypeLink:
			return fmt.Errorf("unsupported archive entry %s", header.Name)
		default:
			continue
		}
	}

	return nil
}

func safeJoin(base, target string) (string, error) {
	clean := filepath.Clean(target)
	if filepath.IsAbs(clean) {
		return "", fmt.Errorf("invalid archive path %s", target)
	}
	joined := filepath.Join(base, clean)
	rel, err := filepath.Rel(base, joined)
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(rel, "..") {
		return "", fmt.Errorf("invalid archive path %s", target)
	}
	return joined, nil
}

func findSingleDir(path string) (string, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return "", err
	}
	if len(entries) != 1 || !entries[0].IsDir() {
		return "", nil
	}
	return filepath.Join(path, entries[0].Name()), nil
}

func copyDir(src, dest string) error {
	return filepath.WalkDir(src, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		target := filepath.Join(dest, rel)
		if entry.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("unsupported symlink %s", path)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		mode := info.Mode()
		if entry.IsDir() {
			return os.MkdirAll(target, mode.Perm())
		}
		return copyFile(path, target, mode.Perm())
	})
}

func copyFile(src, dest string, perm fs.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}
