// Copyright by cenroq AG
// Contact: info@cenroq.com

package convert_test

import (
	"reflect"
	"testing"

	"github.com/cenroq/kubeapt/v2/pkg/convert"
	"github.com/cenroq/kubeapt/v2/pkg/policies"
	"github.com/cenroq/kubeapt/v2/pkg/types"
)

func TestSeverityToKyverno(t *testing.T) {
	cases := []struct {
		raw       string
		wantValue string
		wantLossy bool
		wantOK    bool
	}{
		{raw: "Critical", wantValue: "high", wantLossy: true, wantOK: true},
		{raw: "critical", wantValue: "high", wantLossy: true, wantOK: true},
		{raw: "High", wantValue: "high", wantOK: true},
		{raw: "Moderate", wantValue: "medium", wantOK: true},
		{raw: " low ", wantValue: "low", wantOK: true},
		{raw: "Info", wantValue: "low", wantLossy: true, wantOK: true},
		{raw: "Not Rated"},
		{raw: ""},
		{raw: "bogus"},
	}

	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			value, lossy, ok := convert.SeverityToKyverno(tc.raw)
			if value != tc.wantValue || lossy != tc.wantLossy || ok != tc.wantOK {
				t.Errorf("got (%q, %v, %v), want (%q, %v, %v)",
					value, lossy, ok, tc.wantValue, tc.wantLossy, tc.wantOK)
			}
		})
	}
}

func TestSeverityFromKyverno(t *testing.T) {
	cases := []struct {
		raw  string
		want types.Severity
		ok   bool
	}{
		{raw: "critical", want: types.SeverityCritical, ok: true},
		{raw: "High", want: types.SeverityHigh, ok: true},
		{raw: "medium", want: types.SeverityModerate, ok: true},
		{raw: " low", want: types.SeverityLow, ok: true},
		{raw: "info", want: types.SeverityNotRated},
		{raw: "", want: types.SeverityNotRated},
	}

	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			got, ok := convert.SeverityFromKyverno(tc.raw)
			if got != tc.want || ok != tc.ok {
				t.Errorf("got (%q, %v), want (%q, %v)", got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestBridgeAnnotationsDualEmits(t *testing.T) {
	in := map[string]string{
		policies.AnnotationDisplayName: "Require Labels",
		policies.AnnotationDescription: "every pod needs an environment label",
		policies.AnnotationCategory:    "Best Practices",
		policies.AnnotationSeverity:    "Critical",
	}

	got, rep := convert.BridgeAnnotations(in, true)

	want := map[string]string{
		policies.AnnotationDisplayName:        "Require Labels",
		policies.AnnotationDescription:        "every pod needs an environment label",
		policies.AnnotationCategory:           "Best Practices",
		policies.AnnotationSeverity:           "Critical",
		policies.KyvernoAnnotationTitle:       "Require Labels",
		policies.KyvernoAnnotationDescription: "every pod needs an environment label",
		policies.KyvernoAnnotationCategory:    "Best Practices",
		policies.KyvernoAnnotationSeverity:    "high",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v\nwant %v", got, want)
	}
	if rep.Count(convert.LevelInfo) != 1 {
		t.Errorf("Critical -> high should record one lossy note, got %d", rep.Count(convert.LevelInfo))
	}
}

func TestBridgeAnnotationsFromKyverno(t *testing.T) {
	in := map[string]string{
		policies.KyvernoAnnotationTitle:       "Check Labels",
		policies.KyvernoAnnotationDescription: "labels are required",
		policies.KyvernoAnnotationCategory:    "Other",
		policies.KyvernoAnnotationSeverity:    "medium",
	}

	got, _ := convert.BridgeAnnotations(in, true)

	if got[policies.AnnotationDisplayName] != "Check Labels" {
		t.Errorf("title did not map to displayName: %v", got)
	}
	if got[policies.AnnotationSeverity] != string(types.SeverityModerate) {
		t.Errorf("got severity %q, want Moderate", got[policies.AnnotationSeverity])
	}
	if got[policies.KyvernoAnnotationSeverity] != "medium" {
		t.Errorf("kyverno severity not preserved: %v", got)
	}
}

func TestBridgeAnnotationsPrefersKubeaptKey(t *testing.T) {
	in := map[string]string{
		policies.AnnotationDisplayName:  "kubeapt wins",
		policies.KyvernoAnnotationTitle: "kyverno loses",
	}
	got, _ := convert.BridgeAnnotations(in, true)
	if got[policies.AnnotationDisplayName] != "kubeapt wins" || got[policies.KyvernoAnnotationTitle] != "kubeapt wins" {
		t.Errorf("kubeapt key should win on both sides: %v", got)
	}
}

// TestBridgeAnnotationsRoundTripsCritical is the case dual-emit exists to
// protect: Kyverno cannot express Critical, so deriving it back from the
// Kyverno key alone would silently downgrade the policy to High.
func TestBridgeAnnotationsRoundTripsCritical(t *testing.T) {
	in := map[string]string{policies.AnnotationSeverity: "Critical"}

	once, _ := convert.BridgeAnnotations(in, true)
	twice, _ := convert.BridgeAnnotations(once, true)

	if twice[policies.AnnotationSeverity] != "Critical" {
		t.Errorf("Critical did not survive the round trip: %v", twice)
	}
	if !reflect.DeepEqual(once, twice) {
		t.Errorf("BridgeAnnotations is not idempotent:\n once: %v\ntwice: %v", once, twice)
	}
}

func TestBridgeAnnotationsKeepsUnrecognizedSeverityVerbatim(t *testing.T) {
	in := map[string]string{policies.AnnotationSeverity: "showstopper"}
	got, _ := convert.BridgeAnnotations(in, true)

	if got[policies.AnnotationSeverity] != "showstopper" {
		t.Errorf("unrecognized severity not preserved: %v", got)
	}
	if _, ok := got[policies.KyvernoAnnotationSeverity]; ok {
		t.Errorf("unrecognized severity should not produce a kyverno value: %v", got)
	}
}

func TestBridgeAnnotationsUnmapped(t *testing.T) {
	in := map[string]string{
		"security.kubeapt.io/remediation": "add the label",
		"team.example.com/owner":          "platform",
		policies.AnnotationDisplayName:    "Kept",
		convert.AnnotationConvertSource:   "stale/provenance",
	}

	kept, _ := convert.BridgeAnnotations(in, true)
	if kept["security.kubeapt.io/remediation"] != "add the label" || kept["team.example.com/owner"] != "platform" {
		t.Errorf("unmapped keys should be copied through: %v", kept)
	}
	if _, ok := kept[convert.AnnotationConvertSource]; ok {
		t.Errorf("provenance must be authored fresh, not inherited: %v", kept)
	}

	dropped, _ := convert.BridgeAnnotations(in, false)
	if _, ok := dropped["team.example.com/owner"]; ok {
		t.Errorf("unmapped keys should be dropped: %v", dropped)
	}
	if dropped[policies.AnnotationDisplayName] != "Kept" {
		t.Errorf("bridged keys must survive keepUnmapped=false: %v", dropped)
	}
}

func TestBridgeAnnotationsEmptyIsNil(t *testing.T) {
	got, rep := convert.BridgeAnnotations(nil, true)
	if got != nil {
		t.Errorf("got %v, want nil", got)
	}
	if rep.Len() != 0 {
		t.Errorf("got %d notes, want 0", rep.Len())
	}
}
