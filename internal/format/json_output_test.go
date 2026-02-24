package format

import (
    "bytes"
    "encoding/json"
    "os"
    "reflect"
    "testing"
    "time"

    "github.com/spf13/cobra"
)

func TestUniqueSortedStrings(t *testing.T) {
    if got := UniqueSortedStrings(nil); got != nil {
        t.Fatalf("expected nil for nil input, got %v", got)
    }

    input := []string{" b ", "a", "", "a", "b", "  "}
    got := UniqueSortedStrings(input)
    want := []string{"a", "b"}
    if !reflect.DeepEqual(got, want) {
        t.Fatalf("expected %v, got %v", want, got)
    }
}

func TestBuildJSONMetadata(t *testing.T) {
    cmd := &cobra.Command{Use: "kubeapt"}
    originalArgs := os.Args
    os.Args = []string{}
    t.Cleanup(func() { os.Args = originalArgs })

    start := time.Unix(10, 0)
    stop := time.Unix(20, 0)
    meta := BuildJSONMetadata(cmd, "policy", []string{"ns1", "ns1", "", "ns2"}, nil, start, stop)

    if meta.Command != cmd.CommandPath() {
        t.Fatalf("expected command path %q, got %q", cmd.CommandPath(), meta.Command)
    }
    if meta.View != "policies" {
        t.Fatalf("expected view policies, got %q", meta.View)
    }
    if meta.Kubernetes.Name == "" {
        t.Fatalf("expected kubernetes name to be set")
    }
    if !reflect.DeepEqual(meta.Kubernetes.Namespaces, []string{"ns1", "ns2"}) {
        t.Fatalf("unexpected namespaces: %v", meta.Kubernetes.Namespaces)
    }
    if meta.Time.Start != start.Unix() || meta.Time.Stop != stop.Unix() {
        t.Fatalf("unexpected time window: %+v", meta.Time)
    }
}

func TestWriteJSONEnvelope(t *testing.T) {
    meta := JSONMetadata{Command: "cmd", View: "policies"}
    buf := &bytes.Buffer{}
    err := WriteJSONEnvelope(buf, meta, map[string]string{"ok": "yes"})
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }

    var decoded JSONEnvelope
    if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
        t.Fatalf("failed to decode json: %v", err)
    }
    if decoded.Metadata.Command != "cmd" {
        t.Fatalf("unexpected metadata: %+v", decoded.Metadata)
    }
}

func TestJSONViewLabel(t *testing.T) {
    cases := map[string]string{
        "policy":    "policies",
        "namespace": "namespaces",
        "resource":  "resources",
        "other":     "other",
    }
    for input, want := range cases {
        if got := jsonViewLabel(input); got != want {
            t.Fatalf("input %q: expected %q, got %q", input, want, got)
        }
    }
}
