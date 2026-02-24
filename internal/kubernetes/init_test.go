package kubernetes

import (
    "os"
    "path/filepath"
    "testing"
)

func writeKubeconfig(t *testing.T, namespace, cluster string) string {
    t.Helper()
    content := "apiVersion: v1\nkind: Config\nclusters:\n- name: " + cluster + "\n  cluster:\n    server: https://example.com\ncontexts:\n- name: ctx\n  context:\n    cluster: " + cluster + "\n    user: user\n    namespace: " + namespace + "\ncurrent-context: ctx\nusers:\n- name: user\n  user:\n    token: dummy\n"
    dir := t.TempDir()
    path := filepath.Join(dir, "config")
    if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
        t.Fatalf("failed to write kubeconfig: %v", err)
    }
    return path
}

func TestSetKubeconfig(t *testing.T) {
    original := kubeconfigPath
    t.Cleanup(func() { kubeconfigPath = original })

    SetKubeconfig("/tmp/demo")
    if kubeconfigPath != "/tmp/demo" {
        t.Fatalf("expected kubeconfig path to be set")
    }
    SetKubeconfig("")
    if kubeconfigPath != "" {
        t.Fatalf("expected kubeconfig path to reset")
    }
}

func TestDetectNamespaceAndClusterName(t *testing.T) {
    path := writeKubeconfig(t, "ns1", "cluster1")
    if got := detectNamespace(path); got != "ns1" {
        t.Fatalf("expected namespace ns1, got %q", got)
    }
    if got := detectClusterName(path); got != "cluster1" {
        t.Fatalf("expected cluster1, got %q", got)
    }

    if got := detectNamespace(""); got != "default" {
        t.Fatalf("expected default namespace, got %q", got)
    }
    if got := detectClusterName(""); got != "" {
        t.Fatalf("expected empty cluster name for empty path, got %q", got)
    }
}
