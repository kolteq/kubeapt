package cli

import (
	"encoding/json"
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

func TestDeprecatedBundleIndex(t *testing.T) {
	data := []byte(`[
		{"name":"cenroq-best-practices","latest-version":"v0.1.1","versions":["v0.1.1"]},
		{"name":"pod-security-admission","latest-version":"v1.36.0-cenroq","versions":["v1.36.0-cenroq"]},
		{"name":"pod-security-admission","latest-version":"v1.36.0","deprecated":1782856800,"versions":["v1.36.0","v1.35.0"]}
	]`)
	var index []bundleIndexEntry
	if err := json.Unmarshal(data, &index); err != nil {
		t.Fatalf("unmarshal index: %v", err)
	}

	// The deprecated timestamp is parsed onto the entry.
	var depTS int64
	for _, b := range index {
		if b.Name == "pod-security-admission" && b.Deprecated != 0 {
			depTS = b.Deprecated
		}
	}
	if depTS != 1782856800 {
		t.Fatalf("expected deprecated timestamp to be parsed, got %d", depTS)
	}

	// Merge keeps the current + deprecated duplicates as two separate rows.
	merged := mergeBundleIndexes(index, nil)
	psaRows := 0
	for _, b := range merged {
		if b.Name == "pod-security-admission" {
			psaRows++
		}
	}
	if psaRows != 2 {
		t.Fatalf("expected current + deprecated pod-security-admission rows, got %d", psaRows)
	}

	// Lookups prefer the current (non-deprecated) entry...
	entry, ok := findBundleIndexEntry(index, "pod-security-admission")
	if !ok || entry.Deprecated != 0 || entry.LatestVersion != "v1.36.0-cenroq" {
		t.Fatalf("expected current entry preferred, got %+v (ok=%v)", entry, ok)
	}
	if v, err := resolveBundleVersionFromIndex(merged, "pod-security-admission", ""); err != nil || v != "v1.36.0-cenroq" {
		t.Fatalf("expected latest to resolve to current v1.36.0-cenroq, got %v %v", v, err)
	}

	// ...but a still-published deprecated version stays discoverable for download.
	if !indexHasBundleVersion(index, "pod-security-admission", "v1.35.0") {
		t.Fatalf("expected deprecated version v1.35.0 to be downloadable")
	}
	if indexHasBundleVersion(index, "pod-security-admission", "v9.9.9") {
		t.Fatalf("did not expect unknown version to be found")
	}
}

func TestMergeBundleIndexesDeprecatedLocalDownloads(t *testing.T) {
	const depTS = int64(1782856800)
	remote := []bundleIndexEntry{
		{Name: "cenroq-best-practices", LatestVersion: "v0.1.1", Versions: []string{"v0.1.1"}},
		{Name: "pod-security-admission", LatestVersion: "v1.36.0-cenroq", Versions: []string{"v1.36.0-cenroq"}},
		{Name: "legacy-best-practices", LatestVersion: "v0.1.1", Versions: []string{"v0.1.1", "v0.1.0"}, Deprecated: depTS},
		{Name: "pod-security-admission", LatestVersion: "v1.36.0", Versions: []string{"v1.36.0", "v1.35.0", "v1.34.0"}, Deprecated: depTS},
	}
	// Everything downloaded locally belongs to the deprecated (legacy) lineage.
	local := []bundleIndexEntry{
		{Name: "legacy-best-practices", Versions: []string{"v0.1.0", "v0.1.1"}},
		{Name: "pod-security-admission", Versions: []string{"v1.34.0", "v1.36.0"}},
		{Name: "telekom", Versions: []string{"v5.0.0"}},
	}

	merged := mergeBundleIndexes(remote, local)

	rows := map[string]int{}
	for _, b := range merged {
		rows[b.Name]++
	}
	// A deprecated-only bundle that is also downloaded locally must not duplicate.
	if rows["legacy-best-practices"] != 1 {
		t.Fatalf("expected legacy-best-practices to appear once, got %d", rows["legacy-best-practices"])
	}
	if rows["pod-security-admission"] != 2 {
		t.Fatalf("expected pod-security-admission current + deprecated rows, got %d", rows["pod-security-admission"])
	}
	if rows["telekom"] != 1 {
		t.Fatalf("expected telekom local-only row, got %d", rows["telekom"])
	}

	for _, b := range merged {
		// The current entry must not be polluted with deprecated-lineage versions.
		if b.Name == "pod-security-admission" && b.Deprecated == 0 {
			if len(b.Versions) != 1 || b.Versions[0] != "v1.36.0-cenroq" {
				t.Fatalf("current pod-security-admission should list only v1.36.0-cenroq, got %v", b.Versions)
			}
		}
		if b.Name == "telekom" && !b.LocalOnly {
			t.Fatalf("expected telekom to be marked local-only")
		}
	}
}
