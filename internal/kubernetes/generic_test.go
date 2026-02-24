package kubernetes

import "testing"

func TestExtractPrimaryResources(t *testing.T) {
    got := extractPrimaryResources([]string{"pods/status", "services", ""})
    if len(got) != 2 || got[0] != "pods" || got[1] != "services" {
        t.Fatalf("unexpected resources: %v", got)
    }

    got = extractPrimaryResources([]string{"", ""})
    if len(got) != 1 || got[0] != "*" {
        t.Fatalf("expected wildcard, got %v", got)
    }
}

func TestDraftURLsNoWildcard(t *testing.T) {
    urls, err := draftURLs(nil, []string{""}, []string{"v1"}, []string{"pods", "services"})
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    if len(urls) != 2 {
        t.Fatalf("expected 2 urls, got %v", urls)
    }
    if urls[0] != "/api/v1/pods" || urls[1] != "/api/v1/services" {
        t.Fatalf("unexpected urls: %v", urls)
    }
}
