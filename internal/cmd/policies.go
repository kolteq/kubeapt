// Copyright by KolTEQ GmbH
// Contact: benjamin@kolteq.com

package cmd

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"

	"github.com/kolteq/kubeapt/internal/kubernetes"
)

const (
	psaPoliciesArchiveURL = "https://github.com/kolteq/validating-admission-policies-pss/archive/refs/heads/main.tar.gz"
	psaPoliciesDirName    = "pod-security-standards"
	psaPoliciesSubdir     = "policies"
	psaBindingsSubdir     = "bindings"
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
	return cmd
}

func newPoliciesPSADownloadCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "download",
		Short: "Download the Pod Security Standards policies",
		RunE:  runPoliciesPSADownload,
	}
	return cmd
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

func loadPSAPolicies(policiesPath, bindingsPath string) ([]admissionregistrationv1.ValidatingAdmissionPolicy, []admissionregistrationv1.ValidatingAdmissionPolicyBinding, error) {
	policyFiles, err := collectManifestFilesRecursive(policiesPath)
	if err != nil {
		return nil, nil, err
	}
	policies, err := loadPoliciesFromFiles(policyFiles)
	if err != nil {
		return nil, nil, err
	}

	bindingFiles := policyFiles
	if bindingsPath != policiesPath {
		bindingFiles, err = collectManifestFilesRecursive(bindingsPath)
		if err != nil {
			return nil, nil, err
		}
	}
	bindings, err := loadBindingsFromFiles(bindingFiles)
	if err != nil {
		return nil, nil, err
	}
	return policies, bindings, nil
}

func loadPoliciesFromFiles(files []string) ([]admissionregistrationv1.ValidatingAdmissionPolicy, error) {
	var policies []admissionregistrationv1.ValidatingAdmissionPolicy
	for _, file := range files {
		items, err := kubernetes.GetLocalValidatingAdmissionPolicies(file)
		if err != nil {
			return nil, err
		}
		policies = append(policies, items...)
	}
	return policies, nil
}

func loadBindingsFromFiles(files []string) ([]admissionregistrationv1.ValidatingAdmissionPolicyBinding, error) {
	var bindings []admissionregistrationv1.ValidatingAdmissionPolicyBinding
	for _, file := range files {
		items, err := kubernetes.GetLocalValidatingAdmissionPolicyBindings(file)
		if err != nil {
			return nil, err
		}
		bindings = append(bindings, items...)
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
