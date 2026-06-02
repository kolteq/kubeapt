package cli

import (
    "bytes"
    "encoding/json"
    "os"
    "path/filepath"
    "reflect"
    "strings"
    "testing"

    "github.com/jedib0t/go-pretty/v6/table"
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

    if label, _ := violationSeverityLabel("high"); label != "HIGH" {
        t.Fatalf("expected HIGH label, got %q", label)
    }
    if label, _ := violationSeverityLabel("Critical"); label != "CRITICAL" {
        t.Fatalf("expected CRITICAL label, got %q", label)
    }
    if label, _ := violationSeverityLabel(""); label != "NOT RATED" {
        t.Fatalf("expected NOT RATED label, got %q", label)
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

func TestHighestResourceSeverity(t *testing.T) {
    // A resource carrying multiple violations is bucketed under the most
    // severe one, so per-namespace severity columns sum to NonCompliant.
    got := highestResourceSeverity([]violationDetail{
        {Severity: "low"},
        {Severity: "Critical"},
        {Severity: "moderate"},
    })
    if got != severityCritical {
        t.Fatalf("expected %q, got %q", severityCritical, got)
    }

    // No violations at all → defaults to Not Rated so the bucket is never empty.
    if got := highestResourceSeverity(nil); got != severityNotRated {
        t.Fatalf("expected %q for empty input, got %q", severityNotRated, got)
    }

    // Unrecognized strings normalize to Not Rated rather than disappearing.
    if got := highestResourceSeverity([]violationDetail{{Severity: "bogus"}}); got != severityNotRated {
        t.Fatalf("expected %q for unknown severity, got %q", severityNotRated, got)
    }
}

func TestVisibleSeverityColumnsHidesZeros(t *testing.T) {
    reports := []namespaceReport{
        {Namespace: "ns1", SeverityCounts: map[string]int{severityHigh: 2, severityLow: 1}},
        {Namespace: "ns2", SeverityCounts: map[string]int{severityHigh: 3}},
    }
    visible, totals := visibleSeverityColumns(reports)
    // Only High and Low should appear; Critical/Moderate/Info/Not Rated stay hidden.
    want := []string{severityHigh, severityLow}
    if !reflect.DeepEqual(visible, want) {
        t.Fatalf("visible severities = %v, want %v", visible, want)
    }
    if totals[severityHigh] != 5 || totals[severityLow] != 1 {
        t.Fatalf("totals = %v, want High=5 Low=1", totals)
    }
}

func TestPrintNamespaceTableShowsSeverityColumns(t *testing.T) {
    reports := []namespaceReport{
        {Namespace: "prod-api", Total: 24, Compliant: 19, NonCompliant: 5,
            SeverityCounts: map[string]int{severityCritical: 2, severityHigh: 3}},
        {Namespace: "prod-web", Total: 18, Compliant: 18, NonCompliant: 0},
    }
    var buf bytes.Buffer
    printNamespaceTable(reports, &buf, table.StyleDefault)
    out := buf.String()
    // go-pretty uppercases header text; row values keep their case.
    upperOut := strings.ToUpper(out)
    for _, want := range []string{severityCritical, severityHigh} {
        if !strings.Contains(upperOut, strings.ToUpper(want)) {
            t.Errorf("table missing header %q\noutput:\n%s", want, out)
        }
    }
    for _, want := range []string{"prod-api", "Totals"} {
        if !strings.Contains(out, want) {
            t.Errorf("table missing %q\noutput:\n%s", want, out)
        }
    }
    // Moderate/Low/Info/Not Rated have zero totals and must not appear as headers.
    for _, hidden := range []string{severityModerate, severityLow, severityInfo, severityNotRated} {
        if strings.Contains(upperOut, strings.ToUpper(hidden)) {
            t.Errorf("table should hide zero-count column %q\noutput:\n%s", hidden, out)
        }
    }
}

func TestBuildNamespaceJSONReportMirrorsSeverity(t *testing.T) {
    reports := []namespaceReport{
        {Namespace: "ns1", Total: 5, Compliant: 3, NonCompliant: 2,
            SeverityCounts: map[string]int{severityHigh: 1, severityLow: 1}},
        {Namespace: "ns2", Total: 4, Compliant: 4},
    }
    payload := buildNamespaceJSONReport("summary", reports, nil)
    if payload.SeverityTotals[severityHigh] != 1 || payload.SeverityTotals[severityLow] != 1 {
        t.Errorf("SeverityTotals = %v, want High=1 Low=1", payload.SeverityTotals)
    }
    encoded, err := json.Marshal(payload)
    if err != nil {
        t.Fatalf("marshal: %v", err)
    }
    if !strings.Contains(string(encoded), `"severityCounts"`) {
        t.Errorf("expected per-namespace severityCounts in JSON, got %s", encoded)
    }
    if !strings.Contains(string(encoded), `"severityTotals"`) {
        t.Errorf("expected top-level severityTotals in JSON, got %s", encoded)
    }
}
