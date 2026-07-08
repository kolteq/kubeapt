// Copyright by cenroq AG
// Contact: info@cenroq.com

// Package scanaccess is an internal contract between pkg/policies (loader) and
// pkg/scanner (evaluator). It carries the typed VAP/binding/severity view that
// neither public package exposes.
//
// External consumers of kubeapt cannot import this package thanks to Go's
// internal-import rule, so the Parsed shape and Token type are effectively
// sealed: pkg/policies.Policy holds a *Parsed, and pkg/policies.Policy.Parsed
// is gated by a Token argument that only internal callers can construct.
package scanaccess

import (
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"

	"github.com/cenroq/kubeapt/v2/pkg/types"
)

// Token is a phantom credential gating internal-only access.
type Token struct{}

// Parsed is the sealed typed view of one policy.
type Parsed struct {
	VAP      *admissionregistrationv1.ValidatingAdmissionPolicy
	Bindings []*admissionregistrationv1.ValidatingAdmissionPolicyBinding
	Severity types.Severity
}
