// Copyright by KolTEQ GmbH
// Contact: benjamin@kolteq.com

// Package scanner evaluates a loaded policies.Bundle against a slice of
// in-memory Kubernetes manifests and returns structured findings.
//
// The scanner is the only public entrypoint kubeapt exposes for embedding
// the policy engine into another Go program. It does not talk to the
// Kubernetes API; callers are expected to bring their own parsed manifests.
package scanner

import (
	"context"
	"errors"
	"fmt"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kolteq/kubeapt/internal/kubernetes"
	"github.com/kolteq/kubeapt/internal/scanaccess"
	"github.com/kolteq/kubeapt/pkg/policies"
	"github.com/kolteq/kubeapt/pkg/types"
)

// Scanner evaluates a sealed policies.Bundle against caller-supplied manifests.
//
// A Scanner is safe for concurrent Scan calls: the bundle is read-only after
// load, the per-call manifest slice is deep-copied before evaluation, and the
// internal CEL environment is rebuilt per evaluation.
type Scanner struct {
	bundle          *policies.Bundle
	respectBindings bool
}

// Option configures a Scanner at construction time. It is reserved for future
// construction-time knobs; today the only concrete option is WithRespectBindings.
type Option func(*Scanner)

// WithRespectBindings configures the Scanner to evaluate each policy only
// against resources matched by the policy's own ValidatingAdmissionPolicyBinding
// documents loaded with the bundle. Policies that have no binding will not fire.
//
// Without this option (the default), the scanner synthesizes an implicit
// "match every matching resource" binding for each policy, so policies fire
// against every resource that satisfies their matchConstraints. This is the
// right default when the bundle is used as a detection ruleset rather than
// enforcement constraints.
func WithRespectBindings() Option {
	return func(s *Scanner) {
		s.respectBindings = true
	}
}

// New constructs a Scanner for the given bundle. It returns an error if bundle
// is nil.
func New(bundle *policies.Bundle, opts ...Option) (*Scanner, error) {
	if bundle == nil {
		return nil, errors.New("scanner: nil bundle")
	}
	s := &Scanner{bundle: bundle}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

// Scan evaluates every policy in the bundle against every manifest in the
// slice and returns the aggregated Findings and per-evaluation ScanErrors.
//
// The input manifests slice is deep-copied before any normalization, so the
// caller's data is never mutated.
//
// The returned error is non-nil only on catastrophic failure (e.g., context
// cancellation). Per-(policy, resource) evaluation failures land in
// Result.ScanErrors and the scan continues.
func (s *Scanner) Scan(ctx context.Context, manifests []types.Manifest) (*types.Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	working := deepCopyManifests(manifests)
	kubernetes.NormalizeResourcesForCEL(working)

	result := &types.Result{}
	for policy := range s.bundle.Iterate() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		parsed := policy.Parsed(scanaccess.Token{})
		if parsed == nil || parsed.VAP == nil {
			continue
		}

		bindings := s.effectiveBindings(parsed)
		if len(bindings) == 0 {
			continue
		}

		for _, binding := range bindings {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			for _, manifest := range working {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				s.evaluate(policy.ID, parsed, binding, manifest, result)
			}
		}
	}
	return result, nil
}

func (s *Scanner) effectiveBindings(parsed *scanaccess.Parsed) []*admissionregistrationv1.ValidatingAdmissionPolicyBinding {
	if s.respectBindings {
		return parsed.Bindings
	}
	return []*admissionregistrationv1.ValidatingAdmissionPolicyBinding{implicitBinding(parsed.VAP.Name)}
}

func implicitBinding(policyName string) *admissionregistrationv1.ValidatingAdmissionPolicyBinding {
	return &admissionregistrationv1.ValidatingAdmissionPolicyBinding{
		ObjectMeta: metav1.ObjectMeta{Name: policyName + "--implicit"},
		Spec: admissionregistrationv1.ValidatingAdmissionPolicyBindingSpec{
			PolicyName: policyName,
		},
	}
}

func (s *Scanner) evaluate(
	policyID string,
	parsed *scanaccess.Parsed,
	binding *admissionregistrationv1.ValidatingAdmissionPolicyBinding,
	manifest types.Manifest,
	result *types.Result,
) {
	ref := resourceRefFromManifest(manifest)

	if !kubernetes.MatchesPolicy(parsed.VAP, manifest, nil, false, false) {
		return
	}
	if s.respectBindings {
		if !kubernetes.MatchesBinding(binding, manifest, nil, false, false, false) {
			return
		}
	}

	eval, err := kubernetes.EvaluateValidations(parsed.VAP, binding, manifest, ref.Namespace, nil)
	if err != nil {
		result.ScanErrors = append(result.ScanErrors, types.ScanError{
			PolicyID: policyID,
			Resource: ref,
			Err:      fmt.Errorf("scanner: evaluate policy %s against %s: %w", policyID, formatRef(ref), err),
		})
		return
	}
	if eval.Compliant {
		return
	}

	for _, v := range eval.Violations {
		result.Findings = append(result.Findings, types.Finding{
			PolicyID: policyID,
			Resource: ref,
			Severity: parsed.Severity,
			Message:  v.Message,
			Path:     v.Path,
			Actions:  v.Actions,
		})
	}
}

func resourceRefFromManifest(m types.Manifest) types.ResourceRef {
	return types.ResourceRef{
		APIVersion: stringField(m, "apiVersion"),
		Kind:       stringField(m, "kind"),
		Namespace:  kubernetes.MetadataString(m, "namespace"),
		Name:       kubernetes.MetadataString(m, "name"),
		UID:        kubernetes.MetadataString(m, "uid"),
	}
}

func stringField(m types.Manifest, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func formatRef(ref types.ResourceRef) string {
	ns := ref.Namespace
	if ns == "" {
		ns = "<cluster>"
	}
	return fmt.Sprintf("%s %s/%s", ref.Kind, ns, ref.Name)
}

func deepCopyManifests(in []types.Manifest) []types.Manifest {
	out := make([]types.Manifest, len(in))
	for i, m := range in {
		out[i] = deepCopyMap(m)
	}
	return out
}

func deepCopyMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = deepCopyValue(v)
	}
	return out
}

func deepCopyValue(v any) any {
	switch x := v.(type) {
	case map[string]any:
		return deepCopyMap(x)
	case []any:
		out := make([]any, len(x))
		for i, item := range x {
			out[i] = deepCopyValue(item)
		}
		return out
	default:
		return v
	}
}
