// Copyright by KolTEQ GmbH
// Contact: benjamin@kolteq.com

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

	"github.com/kolteq/kubeapt/pkg/types"
)

// Token is a phantom credential. Holding a Token means the caller imported
// internal/scanaccess, which Go forbids for code outside the kubeapt module.
// The zero value is the only value; there are no fields to populate.
type Token struct{}

// Parsed is the sealed, typed view of one policy in a bundle.
type Parsed struct {
	VAP      *admissionregistrationv1.ValidatingAdmissionPolicy
	Bindings []*admissionregistrationv1.ValidatingAdmissionPolicyBinding
	Severity types.Severity
}
