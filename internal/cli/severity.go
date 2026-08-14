// Copyright by cenroq AG
// Contact: info@cenroq.com

package cli

import (
	"github.com/fatih/color"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"

	"github.com/cenroq/kubeapt/v2/pkg/policies"
	"github.com/cenroq/kubeapt/v2/pkg/types"
)

const (
	severityCritical = string(types.SeverityCritical)
	severityHigh     = string(types.SeverityHigh)
	severityModerate = string(types.SeverityModerate)
	severityLow      = string(types.SeverityLow)
	severityInfo     = string(types.SeverityInfo)
	severityNotRated = string(types.SeverityNotRated)
)

func normalizeSeverity(raw string) string {
	return string(policies.NormalizeSeverity(raw))
}

func severityRank(s string) int {
	switch s {
	case severityCritical:
		return 0
	case severityHigh:
		return 1
	case severityModerate:
		return 2
	case severityLow:
		return 3
	case severityInfo:
		return 4
	default:
		return 5
	}
}

func severityColor(severity string) *color.Color {
	switch severity {
	case severityCritical:
		return color.New(color.FgHiRed, color.Bold)
	case severityHigh:
		return color.New(color.FgRed, color.Bold)
	case severityModerate:
		return color.New(color.FgYellow)
	case severityLow:
		return color.New(color.FgCyan)
	case severityInfo:
		return color.New(color.FgWhite)
	default:
		return color.New(color.FgHiBlack)
	}
}

func policySeverityMap(policies []admissionregistrationv1.ValidatingAdmissionPolicy) map[string]string {
	out := make(map[string]string, len(policies))
	for _, policy := range policies {
		out[policy.Name] = normalizeSeverity(policy.Annotations[policyAnnotationSeverity])
	}
	return out
}
