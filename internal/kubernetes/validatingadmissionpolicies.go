// Copyright by KolTEQ GmbH
// Contact: benjamin@kolteq.com

package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"

	"github.com/kolteq/kubeapt/internal/logging"
)

func LoadValidatingAdmissionPolicies(path string) ([]admissionregistrationv1.ValidatingAdmissionPolicy, error) {
	return loadValidatingAdmissionPoliciesFromPath(path, nil)
}

func LoadValidatingAdmissionPoliciesWithProgress(path string, onFile func(string)) ([]admissionregistrationv1.ValidatingAdmissionPolicy, error) {
	return loadValidatingAdmissionPoliciesFromPath(path, onFile)
}

func ListValidatingAdmissionPolicies() ([]admissionregistrationv1.ValidatingAdmissionPolicy, error) {
	clientset, err := NewClientset()
	if err != nil {
		return nil, err
	}

	policyList, err := clientset.AdmissionregistrationV1().ValidatingAdmissionPolicies().List(context.TODO(), metav1.ListOptions{})

	if err != nil {
		return nil, err
	}

	// Maybe for debugging purposes
	// for _, policy := range policyList.Items {
	//  println("Policy Name:", policy.Name)
	// }

	return policyList.Items, nil
}

func ListValidatingAdmissionPolicyBindings() ([]admissionregistrationv1.ValidatingAdmissionPolicyBinding, error) {
	clientset, err := NewClientset()
	if err != nil {
		return nil, err
	}

	bindingList, err := clientset.AdmissionregistrationV1().ValidatingAdmissionPolicyBindings().List(context.TODO(), metav1.ListOptions{})

	if err != nil {
		return nil, err
	}

	// Maybe for debugging purposes
	// for _, binding := range bindingList.Items {
	//  println("Binding Name:", binding.Name)
	// }

	return bindingList.Items, nil
}

func LoadValidatingAdmissionPolicyBindings(path string) ([]admissionregistrationv1.ValidatingAdmissionPolicyBinding, error) {
	return loadValidatingAdmissionPolicyBindingsFromPath(path, nil)
}

func LoadValidatingAdmissionPolicyBindingsWithProgress(path string, onFile func(string)) ([]admissionregistrationv1.ValidatingAdmissionPolicyBinding, error) {
	return loadValidatingAdmissionPolicyBindingsFromPath(path, onFile)
}

func loadValidatingAdmissionPoliciesFromFile(path string) ([]admissionregistrationv1.ValidatingAdmissionPolicy, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return decodeValidatingAdmissionPolicies(f)
}

func decodeValidatingAdmissionPolicies(r io.Reader) ([]admissionregistrationv1.ValidatingAdmissionPolicy, error) {
	decoder := utilyaml.NewYAMLOrJSONDecoder(r, 4096)
	var policies []admissionregistrationv1.ValidatingAdmissionPolicy

	for {
		var raw runtime.RawExtension
		if err := decoder.Decode(&raw); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}

		if len(bytes.TrimSpace(raw.Raw)) == 0 {
			continue
		}

		var typeMeta metav1.TypeMeta
		if err := json.Unmarshal(raw.Raw, &typeMeta); err != nil {
			return nil, err
		}

		if typeMeta.Kind != "ValidatingAdmissionPolicy" {
			continue
		}

		var policy admissionregistrationv1.ValidatingAdmissionPolicy
		if err := json.Unmarshal(raw.Raw, &policy); err != nil {
			return nil, err
		}

		policies = append(policies, policy)
	}

	return policies, nil
}

func loadValidatingAdmissionPolicyBindingsFromFile(path string) ([]admissionregistrationv1.ValidatingAdmissionPolicyBinding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return decodeValidatingAdmissionPolicyBindings(f)
}

func decodeValidatingAdmissionPolicyBindings(r io.Reader) ([]admissionregistrationv1.ValidatingAdmissionPolicyBinding, error) {
	decoder := utilyaml.NewYAMLOrJSONDecoder(r, 4096)
	var bindings []admissionregistrationv1.ValidatingAdmissionPolicyBinding

	for {
		var raw runtime.RawExtension
		if err := decoder.Decode(&raw); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}

		if len(bytes.TrimSpace(raw.Raw)) == 0 {
			continue
		}

		var typeMeta metav1.TypeMeta
		if err := json.Unmarshal(raw.Raw, &typeMeta); err != nil {
			return nil, err
		}

		if typeMeta.Kind != "ValidatingAdmissionPolicyBinding" {
			continue
		}

		var binding admissionregistrationv1.ValidatingAdmissionPolicyBinding
		if err := json.Unmarshal(raw.Raw, &binding); err != nil {
			return nil, err
		}

		bindings = append(bindings, binding)
	}

	return bindings, nil
}

func loadValidatingAdmissionPoliciesFromPath(path string, onFile func(string)) ([]admissionregistrationv1.ValidatingAdmissionPolicy, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if info.IsDir() {
		files, err := collectManifestFiles(path)
		if err != nil {
			return nil, err
		}

		var all []admissionregistrationv1.ValidatingAdmissionPolicy
		for _, file := range files {
			if onFile != nil {
				onFile(file)
			}
			items, err := loadValidatingAdmissionPoliciesFromFile(file)
			if err != nil {
				logging.Debugf("Skipping policy file %s: %v", file, err)
				continue
			}
			all = append(all, items...)
		}
		return all, nil
	}

	if onFile != nil {
		onFile(path)
	}
	return loadValidatingAdmissionPoliciesFromFile(path)
}

func loadValidatingAdmissionPolicyBindingsFromPath(path string, onFile func(string)) ([]admissionregistrationv1.ValidatingAdmissionPolicyBinding, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if info.IsDir() {
		files, err := collectManifestFiles(path)
		if err != nil {
			return nil, err
		}

		var all []admissionregistrationv1.ValidatingAdmissionPolicyBinding
		for _, file := range files {
			if onFile != nil {
				onFile(file)
			}
			items, err := loadValidatingAdmissionPolicyBindingsFromFile(file)
			if err != nil {
				logging.Debugf("Skipping binding file %s: %v", file, err)
				continue
			}
			all = append(all, items...)
		}
		return all, nil
	}

	if onFile != nil {
		onFile(path)
	}
	return loadValidatingAdmissionPolicyBindingsFromFile(path)
}

func collectManifestFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		lower := strings.ToLower(name)
		if !strings.HasSuffix(lower, ".yaml") && !strings.HasSuffix(lower, ".yml") && !strings.HasSuffix(lower, ".json") {
			continue
		}
		files = append(files, filepath.Join(dir, name))
	}
	return files, nil
}

func CountManifestFiles(path string) (int, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	if info.IsDir() {
		files, err := collectManifestFiles(path)
		if err != nil {
			return 0, err
		}
		if len(files) == 0 {
			return 1, nil
		}
		return len(files), nil
	}
	return 1, nil
}
