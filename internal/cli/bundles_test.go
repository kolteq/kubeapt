package cli

import (
    "os"
    "path/filepath"
    "testing"

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
