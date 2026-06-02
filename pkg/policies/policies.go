// Copyright by KolTEQ GmbH
// Contact: benjamin@kolteq.com

// Package policies loads kubeapt policy bundles from an fs.FS or directory,
// preserving each policy's raw YAML bytes for downstream "remediation as code"
// artifact bundling.
package policies

import (
	"bufio"
	"bytes"
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

// policyAnnotationSeverity is the annotation key kubeapt uses to declare a
// policy's severity. The value is normalized to one of the types.Severity
// constants; unknown or missing values map to types.SeverityNotRated.
const policyAnnotationSeverity = "security.kubeapt.io/severity"

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

// Bundle is an iterable collection of *Policy keyed by ID.
type Bundle struct {
	items []*Policy
	byID  map[string]*Policy
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

	return bundle, nil
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
