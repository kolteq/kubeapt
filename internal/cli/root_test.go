package cli

import "testing"

func TestRootCommandAndLogLevel(t *testing.T) {
    if rootCmd.Use != "kubeapt" {
        t.Fatalf("expected root command use to be kubeapt, got %q", rootCmd.Use)
    }
    if rootCmd.Version != appVersion {
        t.Fatalf("expected version %q, got %q", appVersion, rootCmd.Version)
    }

    original := logLevel
    logLevel = "debug"
    t.Cleanup(func() { logLevel = original })

    if got := getLogLevel(); got != "debug" {
        t.Fatalf("expected log level debug, got %q", got)
    }
}
