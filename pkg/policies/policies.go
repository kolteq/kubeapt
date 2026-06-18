// Copyright by KolTEQ GmbH
// Contact: benjamin@kolteq.com

// Package policies loads kubeapt policy bundles from an fs.FS or directory,
// preserving each policy's raw YAML bytes for downstream "remediation as code"
// artifact bundling.
package policies

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"iter"
	"os"
	"path"
	"sort"
	"strings"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	sigsyaml "sigs.k8s.io/yaml"

	"github.com/kolteq/kubeapt/internal/scanaccess"
	"github.com/kolteq/kubeapt/pkg/types"
)

// ErrDuplicatePolicy is returned (wrapped) by Load when two
// ValidatingAdmissionPolicy documents in the bundle share a metadata.name.
var ErrDuplicatePolicy = errors.New("policies: duplicate policy id")

// Annotation keys read from a parsed ValidatingAdmissionPolicy's metadata.
//
// The kubeapt-namespaced keys are checked first; the Kyverno community keys
// act as a fallback so bundles authored against either convention surface
// useful metadata. Unknown or missing values cause Title to fall back to
// the policy ID and Description/Category to return the empty string.
const (
	policyAnnotationSeverity    = "security.kubeapt.io/severity"
	policyAnnotationDisplayName = "security.kubeapt.io/displayName"
	policyAnnotationDescription = "security.kubeapt.io/description"
	policyAnnotationCategory    = "security.kubeapt.io/category"

	kyvernoAnnotationTitle       = "policies.kyverno.io/title"
	kyvernoAnnotationDescription = "policies.kyverno.io/description"
	kyvernoAnnotationCategory    = "policies.kyverno.io/category"
)

// Policy is a sealed handle to one ValidatingAdmissionPolicy in a Bundle.
//
// ID is metadata.name. RawYAML is the single-document YAML for the policy,
// suitable for `kubectl apply -f`. BindingYAML carries the multi-document
// YAML for every ValidatingAdmissionPolicyBinding that targets this policy,
// concatenated with the standard "---" separator; it is empty when no binding
// references the policy.
type Policy struct {
	ID          string
	RawYAML     []byte
	BindingYAML []byte

	parsed *scanaccess.Parsed
}

// Parsed returns the sealed typed view. Calling it requires a scanaccess.Token,
// which only callers that can import internal/scanaccess (i.e., kubeapt's own
// pkg/scanner) are able to construct.
func (p *Policy) Parsed(_ scanaccess.Token) *scanaccess.Parsed {
	return p.parsed
}

// Title returns a human-readable display name for the policy, looked up in
// the parsed VAP's annotations. It prefers the kubeapt key
// (security.kubeapt.io/displayName), falls back to the Kyverno community key
// (policies.kyverno.io/title), and finally to ID so the caller always
// receives a non-empty string.
func (p *Policy) Title() string {
	if v := p.lookupAnnotation(policyAnnotationDisplayName, kyvernoAnnotationTitle); v != "" {
		return v
	}
	return p.ID
}

// Description returns the policy's human-readable description, looked up
// under security.kubeapt.io/description, then policies.kyverno.io/description.
// Returns "" if neither annotation is set.
func (p *Policy) Description() string {
	return p.lookupAnnotation(policyAnnotationDescription, kyvernoAnnotationDescription)
}

// Category returns the policy's category, useful for grouping policies in
// catalog views. Looked up under security.kubeapt.io/category, then
// policies.kyverno.io/category. Returns "" if neither annotation is set.
func (p *Policy) Category() string {
	return p.lookupAnnotation(policyAnnotationCategory, kyvernoAnnotationCategory)
}

// lookupAnnotation returns the first non-empty annotation value in keys
// order, or "" if none are set. Safe to call on a *Policy whose sealed
// parsed handle is nil (returns "").
func (p *Policy) lookupAnnotation(keys ...string) string {
	if p == nil || p.parsed == nil || p.parsed.VAP == nil {
		return ""
	}
	ann := p.parsed.VAP.Annotations
	for _, k := range keys {
		if v := strings.TrimSpace(ann[k]); v != "" {
			return v
		}
	}
	return ""
}

// Resources returns the sorted, de-duplicated resource plurals that the
// policy's matchConstraints target (for example ["deployments", "pods"]).
//
// Subresource entries are reduced to their base resource, so a rule targeting
// "pods/status" contributes "pods"; a wildcard rule contributes "*". It returns
// nil for a nil *Policy or one whose parsed VAP declares no match constraints.
func (p *Policy) Resources() []string {
	if p == nil || p.parsed == nil {
		return nil
	}
	return PolicyResources(p.parsed.VAP)
}

// TargetsResources reports whether the policy's matchConstraints target any of
// the supplied resource plurals — the plural names used in
// spec.matchConstraints.resourceRules.resources (for example "pods" or
// "deployments"), not the Kind.
//
// Matching is case-insensitive and compares on the base resource, so a policy
// that targets "pods/status" matches TargetsResources("pods"). A rule using the
// "*" (or "*/*") wildcard targets every resource. It returns false when no
// resources are supplied or the policy has no parsed match constraints.
func (p *Policy) TargetsResources(resources ...string) bool {
	if p == nil || p.parsed == nil {
		return false
	}
	return PolicyTargetsResources(p.parsed.VAP, resources)
}

// Bundle is an iterable collection of *Policy keyed by ID.
//
// Bundle-level metadata (Name, Description, Version, Labels, Sources) comes
// from an optional bundle.json at the loaded root; if no bundle.json is
// present, the string getters return "" and Labels/Sources return nil.
type Bundle struct {
	items []*Policy
	byID  map[string]*Policy

	name        string
	description string
	version     string
	labels      map[string]string
	sources     []string
}

// Iterate yields every Policy in load order.
func (b *Bundle) Iterate() iter.Seq[*Policy] {
	return func(yield func(*Policy) bool) {
		for _, p := range b.items {
			if !yield(p) {
				return
			}
		}
	}
}

// Get returns the Policy with the given ID, or (nil, false) if none exists.
func (b *Bundle) Get(id string) (*Policy, bool) {
	p, ok := b.byID[id]
	return p, ok
}

// Len returns the number of policies in the bundle.
func (b *Bundle) Len() int {
	return len(b.items)
}

// Name returns the bundle's declared name from bundle.json, or "" if no
// bundle.json was found at the bundle root.
func (b *Bundle) Name() string { return b.name }

// Description returns the bundle's declared description from bundle.json,
// or "" if no bundle.json was found at the bundle root.
func (b *Bundle) Description() string { return b.description }

// Version returns the bundle's declared version from bundle.json, or "" if
// no bundle.json was found at the bundle root.
func (b *Bundle) Version() string { return b.version }

// Labels returns the bundle's declared labels from bundle.json, or nil if
// no bundle.json was found at the bundle root or the labels field was empty.
// The returned map is a defensive copy; mutating it does not affect the
// Bundle's internal state.
func (b *Bundle) Labels() map[string]string {
	if len(b.labels) == 0 {
		return nil
	}
	out := make(map[string]string, len(b.labels))
	for k, v := range b.labels {
		out[k] = v
	}
	return out
}

// Sources returns the bundle's declared source URLs from bundle.json, or
// nil if no bundle.json was found at the bundle root or the sources field
// was empty. The returned slice is a defensive copy.
func (b *Bundle) Sources() []string {
	if len(b.sources) == 0 {
		return nil
	}
	return append([]string(nil), b.sources...)
}

// FilterByResources returns a new Bundle containing only the policies whose
// matchConstraints target one of the supplied resource plurals (for example
// "pods" or "deployments"). Load order is preserved and every kept policy keeps
// its bindings; bundle-level metadata (Name, Description, Version, Labels,
// Sources) is carried over unchanged.
//
// Matching follows (*Policy).TargetsResources: case-insensitive, base-resource
// aware ("pods/status" is kept by FilterByResources("pods")), and a policy with
// a "*"/"*/*" wildcard rule is always kept.
//
// Calling FilterByResources with no resources returns a structural copy that
// still contains every policy. The returned Bundle shares the underlying
// *Policy values with the receiver; neither bundle mutates them.
func (b *Bundle) FilterByResources(resources ...string) *Bundle {
	out := &Bundle{
		byID:        make(map[string]*Policy, len(b.items)),
		name:        b.name,
		description: b.description,
		version:     b.version,
	}
	if len(b.labels) > 0 {
		out.labels = make(map[string]string, len(b.labels))
		for k, v := range b.labels {
			out.labels[k] = v
		}
	}
	if len(b.sources) > 0 {
		out.sources = append([]string(nil), b.sources...)
	}
	for _, p := range b.items {
		if len(resources) == 0 || p.TargetsResources(resources...) {
			out.items = append(out.items, p)
			out.byID[p.ID] = p
		}
	}
	return out
}

// LoadDir is a convenience wrapper around Load that reads from the host
// filesystem rooted at path.
func LoadDir(p string) (*Bundle, error) {
	if p == "" {
		return nil, errors.New("policies: empty path")
	}
	return Load(os.DirFS(p), ".")
}

// Load walks fsys starting at root, decoding every .yaml/.yml/.json file as
// a multi-document Kubernetes manifest stream. ValidatingAdmissionPolicy
// documents become Policy entries; ValidatingAdmissionPolicyBinding documents
// are attached to the policy they reference via spec.policyName.
//
// Documents of any other Kind are ignored.
//
// Load returns an error wrapping ErrDuplicatePolicy if two policies share a
// metadata.name; check with errors.Is.
func Load(fsys fs.FS, root string) (*Bundle, error) {
	if fsys == nil {
		return nil, errors.New("policies: nil fs.FS")
	}
	if root == "" {
		root = "."
	}

	files, err := collectYAMLFiles(fsys, root)
	if err != nil {
		return nil, err
	}
	sort.Strings(files)

	type pendingPolicy struct {
		id      string
		yaml    []byte
		vap     *admissionregistrationv1.ValidatingAdmissionPolicy
	}
	type pendingBinding struct {
		yaml    []byte
		binding *admissionregistrationv1.ValidatingAdmissionPolicyBinding
	}

	var policies []pendingPolicy
	bindingsByPolicy := map[string][]pendingBinding{}

	for _, file := range files {
		docs, err := readYAMLDocuments(fsys, file)
		if err != nil {
			return nil, fmt.Errorf("policies: read %s: %w", file, err)
		}
		for i, doc := range docs {
			kind, err := documentKind(doc)
			if err != nil {
				return nil, fmt.Errorf("policies: %s doc %d: %w", file, i, err)
			}
			switch kind {
			case "ValidatingAdmissionPolicy":
				var vap admissionregistrationv1.ValidatingAdmissionPolicy
				if err := sigsyaml.Unmarshal(doc, &vap); err != nil {
					return nil, fmt.Errorf("policies: %s doc %d: %w", file, i, err)
				}
				if vap.Name == "" {
					return nil, fmt.Errorf("policies: %s doc %d: ValidatingAdmissionPolicy missing metadata.name", file, i)
				}
				policies = append(policies, pendingPolicy{
					id:   vap.Name,
					yaml: doc,
					vap:  &vap,
				})
			case "ValidatingAdmissionPolicyBinding":
				var binding admissionregistrationv1.ValidatingAdmissionPolicyBinding
				if err := sigsyaml.Unmarshal(doc, &binding); err != nil {
					return nil, fmt.Errorf("policies: %s doc %d: %w", file, i, err)
				}
				key := binding.Spec.PolicyName
				if key == "" {
					return nil, fmt.Errorf("policies: %s doc %d: ValidatingAdmissionPolicyBinding missing spec.policyName", file, i)
				}
				bindingsByPolicy[key] = append(bindingsByPolicy[key], pendingBinding{
					yaml:    doc,
					binding: &binding,
				})
			default:
				continue
			}
		}
	}

	bundle := &Bundle{
		byID: make(map[string]*Policy, len(policies)),
	}
	for _, pp := range policies {
		if _, dup := bundle.byID[pp.id]; dup {
			return nil, fmt.Errorf("policies: %s: %w", pp.id, ErrDuplicatePolicy)
		}
		pending := bindingsByPolicy[pp.id]
		var bindingYAML []byte
		bindings := make([]*admissionregistrationv1.ValidatingAdmissionPolicyBinding, 0, len(pending))
		if len(pending) > 0 {
			docs := make([][]byte, 0, len(pending))
			for _, pb := range pending {
				docs = append(docs, pb.yaml)
				bindings = append(bindings, pb.binding)
			}
			bindingYAML = joinYAMLDocuments(docs)
		}
		severity := severityFromAnnotations(pp.vap.Annotations)
		policy := &Policy{
			ID:          pp.id,
			RawYAML:     pp.yaml,
			BindingYAML: bindingYAML,
			parsed: &scanaccess.Parsed{
				VAP:      pp.vap,
				Bindings: bindings,
				Severity: severity,
			},
		}
		bundle.items = append(bundle.items, policy)
		bundle.byID[pp.id] = policy
	}

	if err := loadBundleMetadata(fsys, root, bundle); err != nil {
		return nil, err
	}

	return bundle, nil
}

// loadBundleMetadata populates Bundle.name/description/version from a
// bundle.json sitting at the bundle root. Missing file is not an error;
// malformed JSON is.
func loadBundleMetadata(fsys fs.FS, root string, bundle *Bundle) error {
	manifestPath := path.Join(root, "bundle.json")
	data, err := fs.ReadFile(fsys, manifestPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("policies: read %s: %w", manifestPath, err)
	}
	var meta struct {
		Name        string            `json:"name"`
		Description string            `json:"description"`
		Version     string            `json:"version"`
		Labels      map[string]string `json:"labels"`
		Sources     []string          `json:"sources"`
	}
	if err := json.Unmarshal(data, &meta); err != nil {
		return fmt.Errorf("policies: parse %s: %w", manifestPath, err)
	}
	bundle.name = strings.TrimSpace(meta.Name)
	bundle.description = strings.TrimSpace(meta.Description)
	bundle.version = strings.TrimSpace(meta.Version)
	if len(meta.Labels) > 0 {
		bundle.labels = make(map[string]string, len(meta.Labels))
		for k, v := range meta.Labels {
			bundle.labels[k] = v
		}
	}
	if len(meta.Sources) > 0 {
		bundle.sources = append([]string(nil), meta.Sources...)
	}
	return nil
}

func collectYAMLFiles(fsys fs.FS, root string) ([]string, error) {
	var files []string
	err := fs.WalkDir(fsys, root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		switch strings.ToLower(path.Ext(p)) {
		case ".yaml", ".yml", ".json":
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return files, nil
}

func readYAMLDocuments(fsys fs.FS, name string) ([][]byte, error) {
	f, err := fsys.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	reader := utilyaml.NewYAMLReader(bufio.NewReader(f))
	var docs [][]byte
	for {
		raw, err := reader.Read()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		if len(bytes.TrimSpace(raw)) == 0 {
			continue
		}
		docs = append(docs, append([]byte(nil), raw...))
	}
	return docs, nil
}

// documentKind extracts the Kind from a single-document YAML or JSON blob.
func documentKind(doc []byte) (string, error) {
	var meta struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
	}
	if err := sigsyaml.Unmarshal(doc, &meta); err != nil {
		return "", err
	}
	return meta.Kind, nil
}

// joinYAMLDocuments concatenates multiple single-document YAML blobs into one
// multi-document stream, separated by the standard "---\n" marker.
func joinYAMLDocuments(docs [][]byte) []byte {
	if len(docs) == 0 {
		return nil
	}
	if len(docs) == 1 {
		return append([]byte(nil), docs[0]...)
	}
	var buf bytes.Buffer
	for i, d := range docs {
		if i > 0 {
			if !bytes.HasSuffix(buf.Bytes(), []byte("\n")) {
				buf.WriteByte('\n')
			}
			buf.WriteString("---\n")
		}
		buf.Write(d)
	}
	return buf.Bytes()
}

// severityFromAnnotations mirrors the normalization done in internal/cli/severity.go,
// reproduced here so pkg/policies has no dependency on the CLI package.
func severityFromAnnotations(annotations map[string]string) types.Severity {
	raw := strings.ToLower(strings.TrimSpace(annotations[policyAnnotationSeverity]))
	switch raw {
	case "critical":
		return types.SeverityCritical
	case "high":
		return types.SeverityHigh
	case "moderate":
		return types.SeverityModerate
	case "low":
		return types.SeverityLow
	case "info":
		return types.SeverityInfo
	default:
		return types.SeverityNotRated
	}
}

// PolicyTargetsResources reports whether vap's matchConstraints target any of
// the supplied resource plurals. It is the package-level form of
// (*Policy).TargetsResources, exposed for callers that hold a parsed
// *admissionregistrationv1.ValidatingAdmissionPolicy directly.
//
// Matching is case-insensitive and compares on the base resource, so a rule
// targeting "pods/status" matches the request "pods". A "*"/"*/*" rule matches
// every request. It returns false when vap is nil, declares no match
// constraints, or resources is empty.
func PolicyTargetsResources(vap *admissionregistrationv1.ValidatingAdmissionPolicy, resources []string) bool {
	if vap == nil || vap.Spec.MatchConstraints == nil || len(resources) == 0 {
		return false
	}
	for _, rule := range vap.Spec.MatchConstraints.ResourceRules {
		for _, ruleResource := range rule.Resources {
			for _, want := range resources {
				if resourceRuleSelects(ruleResource, want) {
					return true
				}
			}
		}
	}
	return false
}

// PolicyResources returns the sorted, de-duplicated resource plurals that vap's
// matchConstraints target. Subresource entries are reduced to their base
// resource ("pods/status" -> "pods") and a wildcard rule contributes "*". It
// returns nil when vap is nil or declares no match constraints.
func PolicyResources(vap *admissionregistrationv1.ValidatingAdmissionPolicy) []string {
	if vap == nil || vap.Spec.MatchConstraints == nil {
		return nil
	}
	seen := make(map[string]struct{})
	var out []string
	for _, rule := range vap.Spec.MatchConstraints.ResourceRules {
		for _, ruleResource := range rule.Resources {
			base := baseResource(ruleResource)
			if base == "" {
				continue
			}
			if _, ok := seen[base]; ok {
				continue
			}
			seen[base] = struct{}{}
			out = append(out, base)
		}
	}
	sort.Strings(out)
	return out
}

// resourceRuleSelects reports whether a single matchConstraints resource entry
// (ruleResource) covers the requested resource plural (want). Both values are
// normalized to lowercase; ruleResource is compared on its base resource and
// the "*"/"*/*" wildcards match any request.
func resourceRuleSelects(ruleResource, want string) bool {
	ruleResource = strings.ToLower(strings.TrimSpace(ruleResource))
	want = strings.ToLower(strings.TrimSpace(want))
	if ruleResource == "" || want == "" {
		return false
	}
	if ruleResource == "*" || ruleResource == "*/*" {
		return true
	}
	if ruleResource == want {
		return true
	}
	return baseResource(ruleResource) == want
}

// baseResource normalizes a matchConstraints resource entry to its lowercase
// base resource, dropping any "/subresource" suffix ("pods/status" -> "pods").
func baseResource(resource string) string {
	resource = strings.ToLower(strings.TrimSpace(resource))
	if idx := strings.IndexByte(resource, '/'); idx != -1 {
		return resource[:idx]
	}
	return resource
}
