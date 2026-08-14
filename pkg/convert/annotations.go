// Copyright by cenroq AG
// Contact: info@cenroq.com

package convert

import (
	"strings"

	"github.com/cenroq/kubeapt/v2/pkg/policies"
	"github.com/cenroq/kubeapt/v2/pkg/types"
)

// Annotations kubeapt writes to record what a converted policy came from.
// They are always authored fresh by a conversion and never inherited from the
// input, so they describe this conversion rather than an earlier one.
const (
	AnnotationConvertSource        = "convert.kubeapt.io/source"
	AnnotationConvertSourceBinding = "convert.kubeapt.io/source-binding"
	AnnotationConvertTool          = "convert.kubeapt.io/tool"
)

// bridgedKeys are the annotation keys BridgeAnnotations owns. Everything else
// is "unmapped" and subject to the keepUnmapped flag.
var bridgedKeys = map[string]struct{}{
	policies.AnnotationDisplayName:        {},
	policies.AnnotationDescription:        {},
	policies.AnnotationCategory:           {},
	policies.AnnotationSeverity:           {},
	policies.KyvernoAnnotationTitle:       {},
	policies.KyvernoAnnotationDescription: {},
	policies.KyvernoAnnotationCategory:    {},
	policies.KyvernoAnnotationSeverity:    {},
	AnnotationConvertSource:               {},
	AnnotationConvertSourceBinding:        {},
	AnnotationConvertTool:                 {},
}

// BridgeAnnotations maps policy metadata between kubeapt's
// security.kubeapt.io annotations and Kyverno's policies.kyverno.io
// equivalents, writing *both* key families.
//
// Dual-emit is deliberate and runs in both directions. Kyverno consumers read
// policies.kyverno.io/*, while keeping security.kubeapt.io/* verbatim is what
// makes a conversion reversible: the severity scales do not line up, so
// deriving one from the other alone would turn Critical into high and then back
// into High, silently downgrading the policy. Because the mapping prefers the
// kubeapt key on input and rewrites both on output, it is also idempotent.
//
// Keys outside the bridged set are copied through when keepUnmapped is true.
// Notes carry no Source or Target; use Report.Absorb to attach them.
func BridgeAnnotations(in map[string]string, keepUnmapped bool) (map[string]string, Report) {
	var rep Report
	out := map[string]string{}

	if keepUnmapped {
		for k, v := range in {
			if _, bridged := bridgedKeys[k]; bridged {
				continue
			}
			out[k] = v
		}
	}

	bridgeText(out, in, policies.AnnotationDisplayName, policies.KyvernoAnnotationTitle)
	bridgeText(out, in, policies.AnnotationDescription, policies.KyvernoAnnotationDescription)
	bridgeText(out, in, policies.AnnotationCategory, policies.KyvernoAnnotationCategory)
	bridgeSeverity(out, in, &rep)

	if len(out) == 0 {
		return nil, rep
	}
	return out, rep
}

// bridgeText copies one text annotation to both key families, preferring the
// kubeapt spelling when a document carries both.
func bridgeText(out, in map[string]string, kubeaptKey, kyvernoKey string) {
	value := policies.LookupAnnotation(in, kubeaptKey, kyvernoKey)
	if value == "" {
		return
	}
	out[kubeaptKey] = value
	out[kyvernoKey] = value
}

// bridgeSeverity copies the severity annotation to both key families,
// translating between the two scales. The kubeapt value is never rewritten:
// preserving it verbatim is what keeps Critical and Info recoverable, since
// Kyverno's scale cannot express them.
func bridgeSeverity(out, in map[string]string, rep *Report) {
	kubeaptRaw := policies.LookupAnnotation(in, policies.AnnotationSeverity)
	kyvernoRaw := policies.LookupAnnotation(in, policies.KyvernoAnnotationSeverity)

	if kubeaptRaw != "" {
		out[policies.AnnotationSeverity] = kubeaptRaw
		mapped, lossy, ok := SeverityToKyverno(kubeaptRaw)
		switch {
		case ok:
			out[policies.KyvernoAnnotationSeverity] = mapped
			if lossy {
				rep.Infof("", "", "metadata.annotations", "severity %s has no kyverno equivalent and maps to %s; the original is kept under %s",
					kubeaptRaw, mapped, policies.AnnotationSeverity)
			}
		case kyvernoRaw != "":
			out[policies.KyvernoAnnotationSeverity] = kyvernoRaw
		}
		return
	}

	if kyvernoRaw == "" {
		return
	}
	out[policies.KyvernoAnnotationSeverity] = kyvernoRaw
	if severity, ok := SeverityFromKyverno(kyvernoRaw); ok {
		out[policies.AnnotationSeverity] = string(severity)
	}
}

// SeverityToKyverno maps a raw kubeapt severity annotation onto Kyverno's
// low, medium, and high scale. lossy reports that the scales do not line up
// exactly; ok is false for Not Rated and unrecognized values, which are not
// emitted.
func SeverityToKyverno(raw string) (value string, lossy bool, ok bool) {
	switch policies.NormalizeSeverity(raw) {
	case types.SeverityCritical:
		return "high", true, true
	case types.SeverityHigh:
		return "high", false, true
	case types.SeverityModerate:
		return "medium", false, true
	case types.SeverityLow:
		return "low", false, true
	case types.SeverityInfo:
		return "low", true, true
	default:
		return "", false, false
	}
}

// SeverityFromKyverno maps a raw Kyverno severity annotation onto kubeapt's
// scale. critical is accepted even though Kyverno does not document it.
func SeverityFromKyverno(raw string) (types.Severity, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "critical":
		return types.SeverityCritical, true
	case "high":
		return types.SeverityHigh, true
	case "medium":
		return types.SeverityModerate, true
	case "low":
		return types.SeverityLow, true
	default:
		return types.SeverityNotRated, false
	}
}

// applyProvenance records what a converted object was built from. tool is the
// caller's identifier, such as "kubeapt/2.0.1"; source and binding name the
// input objects, and an empty binding is omitted.
func applyProvenance(annotations map[string]string, tool, source, binding string) map[string]string {
	if annotations == nil {
		annotations = map[string]string{}
	}
	annotations[AnnotationConvertSource] = source
	annotations[AnnotationConvertTool] = tool
	if binding != "" {
		annotations[AnnotationConvertSourceBinding] = binding
	}
	return annotations
}
