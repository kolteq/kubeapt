// Copyright by KolTEQ GmbH
// Contact: benjamin@kolteq.com

// Package types defines the shared primitives exposed by kubeapt's scanner API.
package types

// Manifest is a Kubernetes manifest in kubeapt's native parsed shape.
//
// It is a type alias (not a defined type), so callers can pass an existing
// []map[string]any directly to Scanner.Scan without a conversion loop.
type Manifest = map[string]any

// Severity is kubeapt's native severity scale, taken verbatim from policy
// annotations. Callers are expected to translate to their own scale at the
// consumer boundary; kubeapt does not normalize to a generic info/low/.../critical
// vocabulary at the API surface.
type Severity string

// The Severity constants below match the values kubeapt's internal severity
// normalization produces from the security.kubeapt.io/severity annotation.
const (
	SeverityCritical Severity = "Critical"
	SeverityHigh     Severity = "High"
	SeverityModerate Severity = "Moderate"
	SeverityLow      Severity = "Low"
	SeverityInfo     Severity = "Info"
	SeverityNotRated Severity = "Not Rated"
)

// ResourceRef identifies a single Kubernetes resource scanned by Scanner.Scan.
type ResourceRef struct {
	APIVersion string
	Kind       string
	Namespace  string
	Name       string
	UID        string
}

// Finding is a single rule violation produced by the scanner.
//
// PolicyID pairs back to policies.Bundle.Get(id) so the consumer can attach
// the source YAML to the finding when shipping a remediation artifact.
type Finding struct {
	PolicyID string
	Resource ResourceRef
	Severity Severity
	Message  string
	Path     string
	Actions  []string
}

// ScanError reports a non-fatal evaluation failure against a single
// (policy, resource) pair. The Err is passed through verbatim; the consumer
// decides how to surface it.
type ScanError struct {
	PolicyID string
	Resource ResourceRef
	Err      error
}

// Result is the aggregate output of a single Scanner.Scan call.
type Result struct {
	Findings   []Finding
	ScanErrors []ScanError
}
