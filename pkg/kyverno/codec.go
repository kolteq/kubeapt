// Copyright by cenroq AG
// Contact: info@cenroq.com

package kyverno

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	sigsyaml "sigs.k8s.io/yaml"
)

// ErrLegacyPolicy reports a kyverno.io ClusterPolicy or Policy. Those use
// Kyverno's pattern, anchor, and JMESPath rule model, which has no CEL
// equivalent, so kubeapt refuses them rather than converting them badly.
var ErrLegacyPolicy = errors.New("kyverno: legacy ClusterPolicy or Policy is not supported")

// IsKnownAPIVersion reports whether apiVersion is one kubeapt has verified its
// field set against.
func IsKnownAPIVersion(apiVersion string) bool {
	return apiVersion == APIVersionV1 || apiVersion == APIVersionV1Alpha1
}

// DecodeValidatingPolicies reads a YAML or JSON stream and returns every
// policies.kyverno.io ValidatingPolicy and NamespacedValidatingPolicy in it.
//
// Documents of any other kind or group are skipped, so a stream may safely mix
// policies with unrelated manifests. A legacy kyverno.io ClusterPolicy or
// Policy returns an error wrapping ErrLegacyPolicy. An unrecognized
// policies.kyverno.io version is not an error: the document is decoded with the
// v1 field set so a future version still converts, and callers can flag it with
// IsKnownAPIVersion. TypeMeta is preserved exactly as decoded.
func DecodeValidatingPolicies(r io.Reader) ([]ValidatingPolicy, error) {
	decoder := utilyaml.NewYAMLOrJSONDecoder(r, 4096)
	var policies []ValidatingPolicy

	for {
		var raw runtime.RawExtension
		if err := decoder.Decode(&raw); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}

		if len(bytes.TrimSpace(raw.Raw)) == 0 {
			continue
		}

		var header struct {
			metav1.TypeMeta `json:",inline"`
			Metadata        struct {
				Name string `json:"name"`
			} `json:"metadata"`
		}
		if err := json.Unmarshal(raw.Raw, &header); err != nil {
			return nil, err
		}

		group := schema.FromAPIVersionAndKind(header.APIVersion, header.Kind).Group

		if group == LegacyGroupName && (header.Kind == KindClusterPolicy || header.Kind == KindPolicy) {
			return nil, fmt.Errorf("%w: found %s %s; kubeapt converts policies.kyverno.io ValidatingPolicy only",
				ErrLegacyPolicy, header.Kind, header.Metadata.Name)
		}
		if group != GroupName {
			continue
		}
		if header.Kind != KindValidatingPolicy && header.Kind != KindNamespacedValidatingPolicy {
			continue
		}

		var policy ValidatingPolicy
		if err := json.Unmarshal(raw.Raw, &policy); err != nil {
			return nil, err
		}

		policies = append(policies, policy)
	}

	return policies, nil
}

// Marshal renders one policy as a single YAML document with surrounding
// whitespace trimmed. A policy whose apiVersion is policies.kyverno.io/v1alpha1
// emits matchConditions under its v1alpha1 name, "conditions".
func Marshal(p ValidatingPolicy) ([]byte, error) {
	data, err := sigsyaml.Marshal(p)
	if err != nil {
		return nil, err
	}
	if p.APIVersion == APIVersionV1Alpha1 {
		data, err = renameMatchConditions(data)
		if err != nil {
			return nil, err
		}
	}
	return bytes.TrimSpace(data), nil
}

// renameMatchConditions rewrites spec.matchConditions to spec.conditions, the
// spelling policies.kyverno.io/v1alpha1 used.
func renameMatchConditions(data []byte) ([]byte, error) {
	var doc map[string]any
	if err := sigsyaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	spec, ok := doc["spec"].(map[string]any)
	if !ok {
		return data, nil
	}
	conditions, ok := spec["matchConditions"]
	if !ok {
		return data, nil
	}
	delete(spec, "matchConditions")
	spec["conditions"] = conditions
	return sigsyaml.Marshal(doc)
}
