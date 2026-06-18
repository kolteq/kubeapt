// Copyright by KolTEQ GmbH
// Contact: benjamin@kolteq.com

// Package types defines the shared primitives exposed by kubeapt's scanner API.
package types

// Manifest is a parsed Kubernetes manifest as a map alias.
type Manifest = map[string]any

// Severity is kubeapt's native severity scale from policy annotations.
type Severity string

// Severity constants match kubeapt's normalized severity annotation values.
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

// GVR identifies a resource by group, version, and plural resource.
type GVR struct {
	Group    string
	Version  string
	Resource string
}

// Finding is a single rule violation produced by the scanner.
type Finding struct {
	PolicyID string
	Resource ResourceRef
	Severity Severity
	Message  string
	Path     string
	Actions  []string
}

// ScanError reports a non-fatal failure for one policy-resource pair.
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
