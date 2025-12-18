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

func GetLocalValidatingAdmissionPolicies(path string) ([]admissionregistrationv1.ValidatingAdmissionPolicy, error) {
	return loadPoliciesFromPath(path, nil)
}

func GetLocalValidatingAdmissionPoliciesWithProgress(path string, onFile func(string)) ([]admissionregistrationv1.ValidatingAdmissionPolicy, error) {
	return loadPoliciesFromPath(path, onFile)
}

func GetRemoteValidatingAdmissionPolicies() ([]admissionregistrationv1.ValidatingAdmissionPolicy, error) {
	clientset, err := Init()
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

func GetRemoteValidatingAdmissionPolicyBindings() ([]admissionregistrationv1.ValidatingAdmissionPolicyBinding, error) {
	clientset, err := Init()
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

func GetLocalValidatingAdmissionPolicyBindings(path string) ([]admissionregistrationv1.ValidatingAdmissionPolicyBinding, error) {
	return loadBindingsFromPath(path, nil)
}

func GetLocalValidatingAdmissionPolicyBindingsWithProgress(path string, onFile func(string)) ([]admissionregistrationv1.ValidatingAdmissionPolicyBinding, error) {
	return loadBindingsFromPath(path, onFile)
}

func readValidatingAdmissionPoliciesFromFile(path string) ([]admissionregistrationv1.ValidatingAdmissionPolicy, error) {
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

func readValidatingAdmissionPolicyBindingsFromFile(path string) ([]admissionregistrationv1.ValidatingAdmissionPolicyBinding, error) {
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

func loadPoliciesFromPath(path string, onFile func(string)) ([]admissionregistrationv1.ValidatingAdmissionPolicy, error) {
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
			items, err := readValidatingAdmissionPoliciesFromFile(file)
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
	return readValidatingAdmissionPoliciesFromFile(path)
}

func loadBindingsFromPath(path string, onFile func(string)) ([]admissionregistrationv1.ValidatingAdmissionPolicyBinding, error) {
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
			items, err := readValidatingAdmissionPolicyBindingsFromFile(file)
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
	return readValidatingAdmissionPolicyBindingsFromFile(path)
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
