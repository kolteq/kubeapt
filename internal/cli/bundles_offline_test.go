// Copyright by KolTEQ GmbH
// Contact: benjamin@kolteq.com

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/kolteq/kubeapt/internal/config"
)

const (
	testBundleName    = "test-bundle"
	testBundleVersion = "1.0.0"

	fixturePoliciesYAML = "apiVersion: admissionregistration.k8s.io/v1\nkind: ValidatingAdmissionPolicy\nmetadata:\n  name: p\n"
	fixtureBindingsYAML = "apiVersion: admissionregistration.k8s.io/v1\nkind: ValidatingAdmissionPolicyBinding\nmetadata:\n  name: b\nspec:\n  policyName: p\n"
)

// seedInstalledBundle writes a fake bundle into the kubeapt config dir rooted
// at the t.Setenv("HOME", ...) value, then returns the on-disk version dir.
func seedInstalledBundle(t *testing.T) string {
	t.Helper()
	versionDir, err := config.BundleVersionDir(testBundleName, testBundleVersion)
	if err != nil {
		t.Fatalf("BundleVersionDir: %v", err)
	}
	if err := os.MkdirAll(versionDir, 0o755); err != nil {
		t.Fatalf("mkdir bundle: %v", err)
	}

	manifest := bundleManifest{Name: testBundleName, Version: testBundleVersion, Description: "fixture"}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	writes := map[string][]byte{
		"bundle.json":   manifestBytes,
		"policies.yaml": []byte(fixturePoliciesYAML),
		"bindings.yaml": []byte(fixtureBindingsYAML),
	}
	for name, data := range writes {
		if err := os.WriteFile(filepath.Join(versionDir, name), data, 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return versionDir
}

func TestBundleExportImportRoundTrip(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	versionDir := seedInstalledBundle(t)

	outDir := t.TempDir()
	archivePath := filepath.Join(outDir, "bundle.tar.gz")
	if err := runBundleExport(&cobra.Command{}, testBundleName, testBundleVersion, archivePath); err != nil {
		t.Fatalf("runBundleExport: %v", err)
	}
	if _, err := os.Stat(archivePath); err != nil {
		t.Errorf("archive not written: %v", err)
	}
	if _, err := os.Stat(archivePath + ".sha256"); err != nil {
		t.Errorf("sha256 sidecar not written: %v", err)
	}

	// Wipe the installed bundle so import can rebuild it from the archive.
	if err := os.RemoveAll(versionDir); err != nil {
		t.Fatal(err)
	}

	if err := runBundleImport(&cobra.Command{}, archivePath, "", false); err != nil {
		t.Fatalf("runBundleImport: %v", err)
	}

	// Verify the round-tripped files match what was seeded.
	for name, want := range map[string]string{
		"policies.yaml": fixturePoliciesYAML,
		"bindings.yaml": fixtureBindingsYAML,
	} {
		got, err := os.ReadFile(filepath.Join(versionDir, name))
		if err != nil {
			t.Errorf("read %s: %v", name, err)
			continue
		}
		if string(got) != want {
			t.Errorf("%s mismatch after round-trip:\n got: %q\nwant: %q", name, got, want)
		}
	}
}

func TestBundleImport_RejectsTamperedArchive(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	versionDir := seedInstalledBundle(t)
	outDir := t.TempDir()
	archivePath := filepath.Join(outDir, "bundle.tar.gz")
	if err := runBundleExport(&cobra.Command{}, testBundleName, testBundleVersion, archivePath); err != nil {
		t.Fatalf("runBundleExport: %v", err)
	}

	// Corrupt the archive bytes without touching the sidecar.
	data, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-10] ^= 0xFF
	if err := os.WriteFile(archivePath, data, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := os.RemoveAll(versionDir); err != nil {
		t.Fatal(err)
	}

	err = runBundleImport(&cobra.Command{}, archivePath, "", false)
	if err == nil {
		t.Fatal("runBundleImport on tampered archive = nil, want error")
	}
	if !strings.Contains(err.Error(), "checksum") {
		t.Errorf("err = %v, want checksum-related error", err)
	}
}

func TestBundleImport_RequiresChecksum(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	seedInstalledBundle(t)
	outDir := t.TempDir()
	archivePath := filepath.Join(outDir, "bundle.tar.gz")
	if err := runBundleExport(&cobra.Command{}, testBundleName, testBundleVersion, archivePath); err != nil {
		t.Fatalf("runBundleExport: %v", err)
	}
	// Remove the sidecar so the import has no checksum source.
	if err := os.Remove(archivePath + ".sha256"); err != nil {
		t.Fatal(err)
	}

	err := runBundleImport(&cobra.Command{}, archivePath, "", true)
	if err == nil {
		t.Fatal("runBundleImport without checksum = nil, want error")
	}
	if !strings.Contains(err.Error(), "checksum") {
		t.Errorf("err = %v, want checksum-related error", err)
	}
}

func TestBundleImport_RefusesOverwriteWithoutForce(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	seedInstalledBundle(t)
	outDir := t.TempDir()
	archivePath := filepath.Join(outDir, "bundle.tar.gz")
	if err := runBundleExport(&cobra.Command{}, testBundleName, testBundleVersion, archivePath); err != nil {
		t.Fatalf("runBundleExport: %v", err)
	}

	// Bundle is still installed on disk; import without --force must refuse.
	err := runBundleImport(&cobra.Command{}, archivePath, "", false)
	if err == nil {
		t.Fatal("runBundleImport over existing = nil, want error")
	}
	if !strings.Contains(err.Error(), "--force") {
		t.Errorf("err = %v, want '--force' hint", err)
	}

	// With --force the import should succeed.
	if err := runBundleImport(&cobra.Command{}, archivePath, "", true); err != nil {
		t.Errorf("runBundleImport --force: %v", err)
	}
}
