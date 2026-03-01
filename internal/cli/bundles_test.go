package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
)

func TestValidateBundleSegment(t *testing.T) {
	if err := validateBundleSegment("bundle", ""); err == nil {
		t.Fatalf("expected error for empty value")
	}
	if err := validateBundleSegment("bundle", "../bad"); err == nil {
		t.Fatalf("expected error for path traversal")
	}
	if err := validateBundleSegment("bundle", "good-name"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBundleIndexHelpers(t *testing.T) {
	bundles := []bundleIndexEntry{{Name: "demo", LatestVersion: "1.2.3", Versions: []string{"1.0.0", "1.2.3"}}}

	if v, err := resolveBundleVersionFromIndex(bundles, "demo", ""); err != nil || v != "1.2.3" {
		t.Fatalf("unexpected result: %v %v", v, err)
	}
	if _, err := resolveBundleVersionFromIndex(bundles, "missing", ""); err == nil {
		t.Fatalf("expected error for missing bundle")
	}

	if entry, ok := findBundleIndexEntry(bundles, "demo"); !ok || entry.Name != "demo" {
		t.Fatalf("expected to find bundle entry")
	}
	if bundleVersionInIndex(bundles[0], "9.9.9") {
		t.Fatalf("expected version to be missing")
	}
}

func TestBundleURLAndSourceHelpers(t *testing.T) {
	if got := bundleJSONURL("demo", "1.0.0"); got == "" {
		t.Fatalf("expected bundle URL to be built")
	}

	source, err := selectBundleSource([]string{"file.txt", "archive.tar.gz"})
	if err != nil || source != "archive.tar.gz" {
		t.Fatalf("unexpected source selection: %v %v", source, err)
	}

	base, err := basenameFromURL("https://example.com/path/archive.tar.gz")
	if err != nil || base != "archive.tar.gz" {
		t.Fatalf("unexpected basename: %v %v", base, err)
	}
}

func TestPathHelpers(t *testing.T) {
	if got := pathBase("/a/b/c.tar.gz"); got != "c.tar.gz" {
		t.Fatalf("unexpected path base: %s", got)
	}

	dir := t.TempDir()
	if _, err := safeJoin(dir, "../evil"); err == nil {
		t.Fatalf("expected error for unsafe join")
	}
	if got, err := safeJoin(dir, "nested/file.txt"); err != nil || got != filepath.Join(dir, "nested/file.txt") {
		t.Fatalf("unexpected safe join: %v %v", got, err)
	}
}

func TestBundleBindingMode(t *testing.T) {
	binding := &admissionregistrationv1.ValidatingAdmissionPolicyBinding{}
	if got := bundleBindingMode(binding); got != string(admissionregistrationv1.Deny) {
		t.Fatalf("expected default deny, got %q", got)
	}
	binding.Spec.ValidationActions = []admissionregistrationv1.ValidationAction{admissionregistrationv1.Audit}
	if got := bundleBindingMode(binding); got != "Audit" {
		t.Fatalf("unexpected binding mode: %q", got)
	}
}

func TestVerifySHA256(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(target, []byte("hello"), 0o644); err != nil {
		t.Fatalf("failed to write target: %v", err)
	}

	checksum := filepath.Join(dir, "file.txt.sha256")
	// precomputed sha256 for "hello"
	if err := os.WriteFile(checksum, []byte("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"), 0o644); err != nil {
		t.Fatalf("failed to write checksum: %v", err)
	}

	if err := verifySHA256(target, checksum); err != nil {
		t.Fatalf("unexpected checksum error: %v", err)
	}
}

func TestLocalBundleIndexSetsLatest(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	versions := []string{"0.9.0", "1.0.0"}
	for _, v := range versions {
		path := filepath.Join(home, ".config", "kubeapt", "bundles", "telekom", v)
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatalf("failed to create version dir: %v", err)
		}
	}

	bundles, err := localBundleIndex()
	if err != nil {
		t.Fatalf("localBundleIndex error: %v", err)
	}
	if len(bundles) != 1 {
		t.Fatalf("expected 1 bundle, got %d", len(bundles))
	}
	got := bundles[0]
	if got.LatestVersion != "1.0.0" {
		t.Fatalf("expected latest version 1.0.0, got %s", got.LatestVersion)
	}
	if !got.LocalOnly {
		t.Fatalf("expected LocalOnly to be true for local bundle")
	}
}

func TestMergeBundleIndexesAddsLocalOnly(t *testing.T) {
	remote := []bundleIndexEntry{{
		Name:          "demo",
		LatestVersion: "1.0.0",
		Versions:      []string{"1.0.0"},
	}}
	local := []bundleIndexEntry{
		{
			Name:     "demo",
			Versions: []string{"0.9.0"},
		},
		{
			Name:     "telekom",
			Versions: []string{"0.1.0"},
		},
	}

	merged := mergeBundleIndexes(remote, local)

	var demo bundleIndexEntry
	var telekom bundleIndexEntry
	for _, b := range merged {
		switch b.Name {
		case "demo":
			demo = b
		case "telekom":
			telekom = b
		}
	}

	if telekom.Name != "telekom" {
		t.Fatalf("expected telekom bundle to be present")
	}
	if telekom.LatestVersion != "0.1.0" {
		t.Fatalf("expected telekom latest 0.1.0, got %s", telekom.LatestVersion)
	}
	if !telekom.LocalOnly {
		t.Fatalf("expected telekom to be marked LocalOnly")
	}
	if demo.Name != "demo" || len(demo.Versions) != 2 {
		t.Fatalf("expected demo bundle to have merged versions, got %+v", demo)
	}
	if demo.LatestVersion != "1.0.0" {
		t.Fatalf("expected demo latest to remain 1.0.0, got %s", demo.LatestVersion)
	}
	if demo.LocalOnly {
		t.Fatalf("expected demo to not be marked LocalOnly")
	}
}

func TestMarkBundleOrigins(t *testing.T) {
	bundles := []bundleIndexEntry{
		{Name: "demo", LocalOnly: true},
		{Name: "telekom", LocalOnly: true},
	}
	remote := []bundleIndexEntry{
		{Name: "demo"},
	}

	got := markBundleOrigins(bundles, remote, true)

	if got[0].LocalOnly {
		t.Fatalf("expected demo to be remote")
	}
	if !got[1].LocalOnly {
		t.Fatalf("expected telekom to stay local-only")
	}
}

func TestEnsureBundleVersionAvailablePrefersLocalWhenMissingInIndex(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	versionDir := filepath.Join(home, ".config", "kubeapt", "bundles", "custom", "v1.2.3")
	if err := os.MkdirAll(versionDir, 0o755); err != nil {
		t.Fatalf("failed creating custom bundle: %v", err)
	}

	cmd := &cobra.Command{}
	got, err := ensureBundleVersionAvailable(cmd, "custom", "")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if got != "v1.2.3" {
		t.Fatalf("expected to pick local version v1.2.3, got %s", got)
	}
}
