// Copyright by KolTEQ GmbH
// Contact: benjamin@kolteq.com

package types_test

import (
	"testing"

	"github.com/kolteq/kubeapt/pkg/types"
)

// TestManifestIsAlias asserts that types.Manifest is a Go type alias
// (declared with `=`) rather than a defined type. If a future edit silently
// converts the declaration to `type Manifest map[string]any`, these
// assignments will stop compiling and the test will fail to build.
//
// Callers rely on this so that an existing []map[string]any (e.g.,
// fsdump.Resource.Manifest on the consumer side) can be passed directly
// to Scanner.Scan with no conversion loop.
func TestManifestIsAlias(t *testing.T) {
	// Single-value interchange in both directions.
	var asAlias types.Manifest = map[string]any{"kind": "Pod"}
	var asMap map[string]any = types.Manifest{"kind": "Pod"}
	_ = asAlias
	_ = asMap

	// Slice-of-Manifest interchanges with slice-of-map without conversion.
	var asAliasSlice []types.Manifest = []map[string]any{{"kind": "Pod"}}
	var asMapSlice []map[string]any = []types.Manifest{{"kind": "Pod"}}
	_ = asAliasSlice
	_ = asMapSlice

	// Function-parameter interchange — proves a function declared with one
	// signature accepts the other directly.
	takesMap := func(_ map[string]any) {}
	takesManifest := func(_ types.Manifest) {}
	takesMap(types.Manifest{})
	takesManifest(map[string]any{})
}

// TestSeverityConstantValues pins the wire values of the Severity constants.
// External consumers may switch on these strings, so accidentally changing
// "Not Rated" to "NotRated" or "Critical" to "critical" would be a breaking
// change that this test catches at the unit-test layer.
func TestSeverityConstantValues(t *testing.T) {
	cases := map[types.Severity]string{
		types.SeverityCritical: "Critical",
		types.SeverityHigh:     "High",
		types.SeverityModerate: "Moderate",
		types.SeverityLow:      "Low",
		types.SeverityInfo:     "Info",
		types.SeverityNotRated: "Not Rated",
	}
	for sev, want := range cases {
		if string(sev) != want {
			t.Errorf("Severity = %q, want %q", string(sev), want)
		}
	}
}
