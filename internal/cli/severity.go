// Copyright by KolTEQ GmbH
// Contact: benjamin@kolteq.com

package cli

import (
	"strings"

	"github.com/fatih/color"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
)

const (
	severityCritical = "Critical"
	severityHigh     = "High"
	severityModerate = "Moderate"
	severityLow      = "Low"
	severityInfo     = "Info"
	severityNotRated = "Not Rated"
)

func normalizeSeverity(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "critical":
		return severityCritical
	case "high":
		return severityHigh
	case "moderate":
		return severityModerate
	case "low":
		return severityLow
	case "info":
		return severityInfo
	default:
		return severityNotRated
	}
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
