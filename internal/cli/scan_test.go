package cli

import "testing"

func TestLatestVersion(t *testing.T) {
    versions := []string{"1.2.0", "1.10.0", "1.3.5"}
    if got := latestVersion(versions); got != "1.10.0" {
        t.Fatalf("expected 1.10.0, got %q", got)
    }

    nonSemver := []string{"beta", "alpha"}
    if got := latestVersion(nonSemver); got != "beta" {
        t.Fatalf("expected beta for lexicographic fallback, got %q", got)
    }
}

func TestIsVersionNewer(t *testing.T) {
    if !isVersionNewer("1.2.0", "1.1.9") {
        t.Fatalf("expected 1.2.0 to be newer")
    }
    if isVersionNewer("1.0.0", "1.0.0") {
        t.Fatalf("expected equal versions to be not newer")
    }
}
