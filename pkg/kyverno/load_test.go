// Copyright by cenroq AG
// Contact: info@cenroq.com

package kyverno_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/cenroq/kubeapt/v2/pkg/kyverno"
)

// writeFile writes content under dir and returns the full path.
func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

func TestLoadValidatingPoliciesFromFile(t *testing.T) {
	dir := t.TempDir()
	path := writeFile(t, dir, "policies.yaml", validatingPolicyYAML+"---\n"+namespacedValidatingPolicyYAML)

	got, err := kyverno.LoadValidatingPolicies(path)
	if err != nil {
		t.Fatalf("LoadValidatingPolicies: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d policies, want 2", len(got))
	}
}

func TestLoadValidatingPoliciesFromDirectoryIsNotRecursive(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.yaml", validatingPolicyYAML)
	writeFile(t, dir, "b.yml", namespacedValidatingPolicyYAML)
	writeFile(t, dir, "notes.txt", "ignored")
	writeFile(t, dir, "nested/c.yaml", validatingPolicyYAML)

	got, err := kyverno.LoadValidatingPolicies(dir)
	if err != nil {
		t.Fatalf("LoadValidatingPolicies: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d policies, want 2 (subdirectories must not be walked)", len(got))
	}
}

func TestLoadValidatingPoliciesMissingPath(t *testing.T) {
	_, err := kyverno.LoadValidatingPolicies(filepath.Join(t.TempDir(), "absent.yaml"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("got err %v, want os.ErrNotExist", err)
	}
}

// TestLoadValidatingPoliciesRejectsMalformedFileInDirectory pins the deliberate
// divergence from the ValidatingAdmissionPolicy loader, which skips such files.
func TestLoadValidatingPoliciesRejectsMalformedFileInDirectory(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "good.yaml", validatingPolicyYAML)
	writeFile(t, dir, "bad.yaml", "apiVersion: policies.kyverno.io/v1\n\tkind: [oops\n")

	_, err := kyverno.LoadValidatingPolicies(dir)
	if err == nil {
		t.Fatal("expected an error for a malformed file in directory mode")
	}
}

func TestLoadValidatingPoliciesPropagatesLegacyPolicy(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "legacy.yaml", legacyClusterPolicyYAML)

	_, err := kyverno.LoadValidatingPolicies(dir)
	if !errors.Is(err, kyverno.ErrLegacyPolicy) {
		t.Fatalf("got err %v, want ErrLegacyPolicy", err)
	}
}

func TestLoadValidatingPoliciesEmptyDirectory(t *testing.T) {
	got, err := kyverno.LoadValidatingPolicies(t.TempDir())
	if err != nil {
		t.Fatalf("LoadValidatingPolicies: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d policies, want 0", len(got))
	}
}
