package cli

import (
    "os"
    "path/filepath"
    "reflect"
    "testing"

    admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
)

func TestParseNamespaces(t *testing.T) {
    got := parseNamespaces("a, b, ,c")
    want := []string{"a", "b", "c"}
    if !reflect.DeepEqual(got, want) {
        t.Fatalf("expected %v, got %v", want, got)
    }
}

func TestManifestHelpers(t *testing.T) {
    if !isManifestFile("demo.YAML") {
        t.Fatalf("expected YAML to be recognized")
    }
    if isManifestFile("demo.txt") {
        t.Fatalf("expected txt to be ignored")
    }

    dir := t.TempDir()
    valid := filepath.Join(dir, "a.yaml")
    invalid := filepath.Join(dir, "b.txt")
    if err := os.WriteFile(valid, []byte("x"), 0o644); err != nil {
        t.Fatalf("write valid: %v", err)
    }
    if err := os.WriteFile(invalid, []byte("x"), 0o644); err != nil {
        t.Fatalf("write invalid: %v", err)
    }

    files, err := collectFiles(dir)
    if err != nil {
        t.Fatalf("collectFiles error: %v", err)
    }
    if len(files) != 1 || files[0] != valid {
        t.Fatalf("unexpected files: %v", files)
    }
}

func TestResourceDisplayAndKey(t *testing.T) {
    obj := map[string]interface{}{
        "kind": "Pod",
        "metadata": map[string]interface{}{
            "name":      "demo",
            "namespace": "ns1",
            "uid":       "u1",
        },
    }
    kind, name := resourceDisplayName(obj)
    if kind != "Pod" || name != "ns1/demo" {
        t.Fatalf("unexpected display name: %s %s", kind, name)
    }
    if key := resourceKey(obj); key != "Pod/ns1/demo/u1" {
        t.Fatalf("unexpected key: %s", key)
    }
}

func TestBindingModeAndSeverity(t *testing.T) {
    binding := &admissionregistrationv1.ValidatingAdmissionPolicyBinding{}
    if got := bindingMode(binding); got != string(admissionregistrationv1.Deny) {
        t.Fatalf("expected default deny, got %q", got)
    }

    binding.Spec.ValidationActions = []admissionregistrationv1.ValidationAction{admissionregistrationv1.Audit, admissionregistrationv1.Warn}
    if got := bindingMode(binding); got != "Audit,Warn" {
        t.Fatalf("unexpected mode: %q", got)
    }

    if sev, _ := violationSeverityColor([]string{"Warn"}); sev != "warn" {
        t.Fatalf("expected warn severity, got %q", sev)
    }
    if sev, _ := violationSeverityColor([]string{"Deny"}); sev != "deny" {
        t.Fatalf("expected deny severity, got %q", sev)
    }
    if sev, _ := violationSeverityColor([]string{}); sev != "info" {
        t.Fatalf("expected info severity, got %q", sev)
    }
}

func TestUniqueViolationFields(t *testing.T) {
    violations := []violationDetail{
        {Policy: "p1"},
        {Policy: "p2"},
        {Policy: "p1"},
        {Policy: ""},
    }
    got := uniqueViolationFields(violations, func(v violationDetail) string { return v.Policy })
    want := []string{"p1", "p2"}
    if !reflect.DeepEqual(got, want) {
        t.Fatalf("expected %v, got %v", want, got)
    }
}

func TestPSALabelHelpers(t *testing.T) {
    labels := map[string]string{
        "pod-security.kubernetes.io/enforce": "baseline",
        "pss.security.kolteq.com/warn":       "restricted",
        "other":                              "ignore",
    }
    converted := convertPSALabels(labels)
    if converted["enforce"] != "baseline" || converted["warn"] != "restricted" {
        t.Fatalf("unexpected PSA labels: %v", converted)
    }

    modes := map[string]string{"enforce": "baseline"}
    if got := formatPSAMode(modes, map[string]bool{"enforce": true}, "enforce", true); got != "baseline (KolTEQ)" {
        t.Fatalf("unexpected PSA mode format: %s", got)
    }
}
