package config

import (
    "os"
    "path/filepath"
    "reflect"
    "sort"
    "testing"
)

func setupHome(t *testing.T) string {
    t.Helper()
    home := t.TempDir()
    t.Setenv("HOME", home)
    return home
}

func TestParseVersionParts(t *testing.T) {
    parts, ok := parseVersionParts("v1.2.3")
    if !ok || !reflect.DeepEqual(parts, []int{1, 2, 3}) {
        t.Fatalf("unexpected parts: %v ok=%v", parts, ok)
    }

    parts, ok = parseVersionParts("1.2.3-beta")
    if !ok || !reflect.DeepEqual(parts, []int{1, 2, 3}) {
        t.Fatalf("unexpected parts for prerelease: %v ok=%v", parts, ok)
    }

    if _, ok := parseVersionParts("1..2"); ok {
        t.Fatalf("expected invalid version")
    }
    if _, ok := parseVersionParts("abc"); ok {
        t.Fatalf("expected invalid version")
    }
}

func TestCompareVersions(t *testing.T) {
    if compareVersions("1.2.3", "1.10.0") >= 0 {
        t.Fatalf("expected 1.2.3 < 1.10.0")
    }
    if compareVersions("1.2.10", "1.2.3") <= 0 {
        t.Fatalf("expected 1.2.10 > 1.2.3")
    }
    if compareVersions("beta", "alpha") <= 0 {
        t.Fatalf("expected beta > alpha by string compare")
    }
}

func TestPolicyAndBundleVersions(t *testing.T) {
    setupHome(t)

    policiesDir, err := PoliciesDir()
    if err != nil {
        t.Fatalf("failed to get policies dir: %v", err)
    }
    if err := os.MkdirAll(policiesDir, 0o755); err != nil {
        t.Fatalf("failed to create policies dir: %v", err)
    }
    versions := []string{"1.2.10", "1.2.2", "1.10.0"}
    for _, v := range versions {
        if err := os.MkdirAll(filepath.Join(policiesDir, v), 0o755); err != nil {
            t.Fatalf("failed to create version dir: %v", err)
        }
    }

    got, err := PolicyVersions()
    if err != nil {
        t.Fatalf("PolicyVersions error: %v", err)
    }
    want := []string{"1.2.2", "1.2.10", "1.10.0"}
    if !reflect.DeepEqual(got, want) {
        t.Fatalf("expected %v, got %v", want, got)
    }

    bundlesDir, err := BundleDir("demo")
    if err != nil {
        t.Fatalf("failed to get bundle dir: %v", err)
    }
    if err := os.MkdirAll(bundlesDir, 0o755); err != nil {
        t.Fatalf("failed to create bundle dir: %v", err)
    }
    for _, v := range versions {
        if err := os.MkdirAll(filepath.Join(bundlesDir, v), 0o755); err != nil {
            t.Fatalf("failed to create bundle version dir: %v", err)
        }
    }

    gotBundles, err := BundleVersions("demo")
    if err != nil {
        t.Fatalf("BundleVersions error: %v", err)
    }
    if !reflect.DeepEqual(gotBundles, want) {
        t.Fatalf("expected %v, got %v", want, gotBundles)
    }
}

func TestLocateBundleFiles(t *testing.T) {
    setupHome(t)

    versionDir, err := BundleVersionDir("bundle", "1.0.0")
    if err != nil {
        t.Fatalf("failed to get bundle version dir: %v", err)
    }
    if err := os.MkdirAll(versionDir, 0o755); err != nil {
        t.Fatalf("failed to create bundle version dir: %v", err)
    }

    policiesPath, err := BundlePoliciesPath("bundle", "1.0.0")
    if err != nil {
        t.Fatalf("failed to get policies path: %v", err)
    }
    bindingsPath, err := BundleBindingsPath("bundle", "1.0.0")
    if err != nil {
        t.Fatalf("failed to get bindings path: %v", err)
    }

    if err := os.WriteFile(policiesPath, []byte("policies"), 0o644); err != nil {
        t.Fatalf("failed to write policies: %v", err)
    }
    if err := os.WriteFile(bindingsPath, []byte("bindings"), 0o644); err != nil {
        t.Fatalf("failed to write bindings: %v", err)
    }

    gotPolicies, gotBindings, ok, err := LocateBundleFiles("bundle", "")
    if err != nil {
        t.Fatalf("LocateBundleFiles error: %v", err)
    }
    if !ok {
        t.Fatalf("expected ok=true")
    }
    if gotPolicies != policiesPath || gotBindings != bindingsPath {
        t.Fatalf("unexpected paths: %s %s", gotPolicies, gotBindings)
    }

    os.Remove(bindingsPath)
    _, _, ok, err = LocateBundleFiles("bundle", "1.0.0")
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if ok {
        t.Fatalf("expected ok=false when bindings missing")
    }
}

func TestCollectManifestFilesRecursive(t *testing.T) {
    root := t.TempDir()
    nested := filepath.Join(root, "nested")
    if err := os.MkdirAll(nested, 0o755); err != nil {
        t.Fatalf("failed to create nested: %v", err)
    }

    files := []string{
        filepath.Join(root, "a.yaml"),
        filepath.Join(root, "b.json"),
        filepath.Join(nested, "c.yml"),
        filepath.Join(nested, "ignore.txt"),
    }
    for _, f := range files {
        if err := os.WriteFile(f, []byte("test"), 0o644); err != nil {
            t.Fatalf("failed to write file: %v", err)
        }
    }

    got, err := CollectManifestFilesRecursive(root)
    if err != nil {
        t.Fatalf("CollectManifestFilesRecursive error: %v", err)
    }
    sort.Strings(got)

    want := []string{files[0], files[1], files[2]}
    sort.Strings(want)
    if !reflect.DeepEqual(got, want) {
        t.Fatalf("expected %v, got %v", want, got)
    }
}
