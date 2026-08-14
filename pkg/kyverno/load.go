// Copyright by cenroq AG
// Contact: info@cenroq.com

package kyverno

import (
	"fmt"
	"os"

	"github.com/cenroq/kubeapt/v2/internal/kubernetes"
)

// LoadValidatingPolicies reads Kyverno validating policies from a file, or from
// the .yaml, .yml, and .json files directly inside a directory. Directories are
// not walked recursively, mirroring
// kubernetes.LoadValidatingAdmissionPolicies.
//
// It diverges from that loader in one deliberate way: the ValidatingAdmissionPolicy
// loader skips unparseable files in directory mode with a debug log, which suits
// a read-only report. Here, skipping a file means silently not converting a
// policy the caller asked for, so a decode error is returned instead.
func LoadValidatingPolicies(path string) ([]ValidatingPolicy, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if !info.IsDir() {
		return loadValidatingPoliciesFromFile(path)
	}

	files, err := kubernetes.CollectManifestFiles(path)
	if err != nil {
		return nil, err
	}

	var all []ValidatingPolicy
	for _, file := range files {
		items, err := loadValidatingPoliciesFromFile(file)
		if err != nil {
			return nil, err
		}
		all = append(all, items...)
	}
	return all, nil
}

func loadValidatingPoliciesFromFile(path string) ([]ValidatingPolicy, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	policies, err := DecodeValidatingPolicies(f)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return policies, nil
}
