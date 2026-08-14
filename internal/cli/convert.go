// Copyright by cenroq AG
// Contact: info@cenroq.com

package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	sigsyaml "sigs.k8s.io/yaml"

	"github.com/cenroq/kubeapt/v2/internal/config"
	"github.com/cenroq/kubeapt/v2/internal/kubernetes"
	"github.com/cenroq/kubeapt/v2/internal/logging"
	"github.com/cenroq/kubeapt/v2/pkg/convert"
	"github.com/cenroq/kubeapt/v2/pkg/kyverno"
)

// Conversion targets accepted by --to.
const (
	convertTargetKyverno = "kyverno"
	convertTargetVAP     = "vap"
)

// File names used when --output names a directory. They match the on-disk
// bundle layout in internal/config, so the result is something the rest of the
// CLI can already read.
const (
	convertPoliciesFileName = "policies.yaml"
	convertBindingsFileName = "bindings.yaml"
)

// ConvertCmd builds the convert command.
func ConvertCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "convert --to kyverno|vap",
		Short: "Convert between ValidatingAdmissionPolicy and Kyverno ValidatingPolicy",
		Long: `Convert Kubernetes ValidatingAdmissionPolicy objects and their bindings into
Kyverno ValidatingPolicy objects, or the reverse.

Manifests are written to stdout so the output can be piped straight to kubectl.
Anything the conversion could not carry over faithfully is reported on stderr.`,
		Example: `  # Convert local policies and bindings to Kyverno
  kubeapt convert --to kyverno -p ./policies -b ./bindings

  # Convert Kyverno policies back, writing a policies.yaml and bindings.yaml pair
  kubeapt convert --to vap -p ./kyverno-policies --output ./out/

  # Migrate what is already running in the cluster, failing on any lossy conversion
  kubeapt convert --to kyverno --cluster --strict`,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			if err := logging.Init("", getLogLevel()); err != nil {
				return err
			}
			logging.SetOutputWriter(cmd.ErrOrStderr())
			logging.SetReportWriter(cmd.OutOrStdout())
			return nil
		},
		RunE: runConvert,
	}

	cmd.Flags().String("to", "", "Conversion target: kyverno or vap")
	cmd.Flags().StringP("policies", "p", "", "File or folder holding the policies to convert")
	cmd.Flags().StringP("bindings", "b", "", "File or folder holding the ValidatingAdmissionPolicyBinding manifests (only used with --to kyverno)")
	cmd.Flags().String("bundle", "", "Policy bundle name to convert")
	cmd.Flags().String("bundle-version", "", "Bundle version to use with --bundle (defaults to latest)")
	cmd.Flags().StringP("policy-name", "P", "", "Policy name to convert from downloaded policies")
	cmd.Flags().Bool("cluster", false, "Convert the ValidatingAdmissionPolicies and bindings installed in the connected cluster")
	cmd.Flags().StringP("namespace", "n", "", "Emit NamespacedValidatingPolicy in this namespace (only used with --to kyverno)")
	cmd.Flags().StringP("format", "f", "yaml", "Specify the manifest output format: yaml or json")
	cmd.Flags().String("output", "", "Write manifests to a file path, or to policies.yaml and bindings.yaml when the path is an existing directory")
	cmd.Flags().Bool("strict", false, "Exit non-zero when the conversion changes policy behaviour")
	cmd.Flags().String("validation-actions", "Deny", "Comma separated actions to use when the source declares none: Deny, Warn, or Audit")
	cmd.Flags().String("kyverno-api-version", "v1", "Kyverno API version to emit: v1 or v1alpha1 (only used with --to kyverno)")
	cmd.Flags().Bool("no-provenance", false, "Omit the convert.kubeapt.io annotations recording what each policy was converted from")

	return cmd
}

// convertRequest is the validated form of the command's flags.
type convertRequest struct {
	target            string
	policyPath        string
	bindingPath       string
	bundleName        string
	bundleVersion     string
	policyName        string
	fromCluster       bool
	namespace         string
	format            string
	outputPath        string
	strict            bool
	validationActions []admissionregistrationv1.ValidationAction
	kyvernoAPIVersion string
	noProvenance      bool
}

func runConvert(cmd *cobra.Command, _ []string) error {
	request, err := parseConvertFlags(cmd)
	if err != nil {
		return err
	}

	out, closeOut, err := convertOutputWriter(cmd, request)
	if err != nil {
		return err
	}
	defer closeOut()

	var report convert.Report
	if request.target == convertTargetKyverno {
		err = runConvertToKyverno(cmd, request, out, &report)
	} else {
		err = runConvertToVAP(cmd, request, out, &report)
	}
	if err != nil {
		return err
	}

	reportConversionNotes(report)

	if request.strict && report.Has(convert.LevelError) {
		return fmt.Errorf("conversion produced %d finding(s) that change policy behaviour; review the report above",
			report.Count(convert.LevelError))
	}
	return nil
}

func parseConvertFlags(cmd *cobra.Command) (convertRequest, error) {
	flags := cmd.Flags()
	var request convertRequest
	var err error

	if request.policyPath, err = flags.GetString("policies"); err != nil {
		return request, err
	}
	if request.bindingPath, err = flags.GetString("bindings"); err != nil {
		return request, err
	}
	if request.bundleName, err = flags.GetString("bundle"); err != nil {
		return request, err
	}
	if request.bundleVersion, err = flags.GetString("bundle-version"); err != nil {
		return request, err
	}
	if request.policyName, err = flags.GetString("policy-name"); err != nil {
		return request, err
	}
	if request.fromCluster, err = flags.GetBool("cluster"); err != nil {
		return request, err
	}
	if request.namespace, err = flags.GetString("namespace"); err != nil {
		return request, err
	}
	if request.strict, err = flags.GetBool("strict"); err != nil {
		return request, err
	}
	if request.noProvenance, err = flags.GetBool("no-provenance"); err != nil {
		return request, err
	}

	target, err := flags.GetString("to")
	if err != nil {
		return request, err
	}
	request.target = strings.ToLower(strings.TrimSpace(target))
	switch request.target {
	case "":
		return request, fmt.Errorf("--to is required; expected kyverno or vap")
	case convertTargetKyverno, convertTargetVAP:
	default:
		return request, fmt.Errorf("invalid target %s, expected kyverno or vap", request.target)
	}

	format, err := flags.GetString("format")
	if err != nil {
		return request, err
	}
	request.format = strings.ToLower(strings.TrimSpace(format))
	if request.format == "" {
		request.format = "yaml"
	}
	if request.format != "yaml" && request.format != "json" {
		return request, fmt.Errorf("invalid format %s, expected yaml or json", request.format)
	}

	apiVersion, err := flags.GetString("kyverno-api-version")
	if err != nil {
		return request, err
	}
	switch strings.ToLower(strings.TrimSpace(apiVersion)) {
	case "", "v1":
		request.kyvernoAPIVersion = kyverno.APIVersionV1
	case "v1alpha1":
		request.kyvernoAPIVersion = kyverno.APIVersionV1Alpha1
	default:
		return request, fmt.Errorf("invalid kyverno api version %s, expected v1 or v1alpha1", apiVersion)
	}

	actions, err := flags.GetString("validation-actions")
	if err != nil {
		return request, err
	}
	if request.validationActions, err = parseValidationActions(actions); err != nil {
		return request, err
	}

	outputPath, err := flags.GetString("output")
	if err != nil {
		return request, err
	}
	request.outputPath = strings.TrimSpace(outputPath)

	if err := validateConvertSources(cmd, request); err != nil {
		return request, err
	}
	return request, nil
}

// validateConvertSources rejects flag combinations that cannot be honoured.
func validateConvertSources(cmd *cobra.Command, request convertRequest) error {
	if request.bundleName != "" && (request.policyPath != "" || request.bindingPath != "" || request.policyName != "") {
		return fmt.Errorf("--bundle cannot be combined with --policies, --policy-name, or --bindings")
	}
	if request.bundleVersion != "" && request.bundleName == "" {
		return fmt.Errorf("--bundle-version requires --bundle")
	}
	if request.policyName != "" && request.policyPath != "" {
		return fmt.Errorf("--policy-name cannot be combined with --policies")
	}
	if request.policyName != "" && request.bindingPath != "" {
		return fmt.Errorf("--policy-name cannot be combined with --bindings")
	}
	if request.fromCluster && (request.policyPath != "" || request.bindingPath != "" || request.bundleName != "" || request.policyName != "") {
		return fmt.Errorf("--cluster cannot be combined with --policies, --bindings, --bundle, or --policy-name")
	}
	if request.policyPath == "" && request.bindingPath == "" && request.bundleName == "" && request.policyName == "" && !request.fromCluster {
		return fmt.Errorf("specify a source: --policies, --bundle, --policy-name, or --cluster")
	}

	if request.target == convertTargetVAP {
		if request.bindingPath != "" {
			return fmt.Errorf("--bindings is only used with --to kyverno")
		}
		if request.fromCluster {
			return fmt.Errorf("--cluster reads ValidatingAdmissionPolicies; use --to kyverno")
		}
		if request.namespace != "" {
			return fmt.Errorf("--namespace is only used with --to kyverno")
		}
		if cmd.Flags().Changed("kyverno-api-version") {
			return fmt.Errorf("--kyverno-api-version is only used with --to kyverno")
		}
	}
	return nil
}

func runConvertToKyverno(cmd *cobra.Command, request convertRequest, out io.Writer, report *convert.Report) error {
	policies, bindings, err := loadVAPSource(cmd, request)
	if err != nil {
		return err
	}

	// A policy with no binding is reported per policy by VAPSetToKyverno, which
	// names it, so there is nothing useful to say up front here.
	converted, rep, err := convert.VAPSetToKyverno(policies, bindings, convert.VAPToKyvernoOptions{
		DefaultValidationActions: request.validationActions,
		Namespace:                request.namespace,
		TargetAPIVersion:         request.kyvernoAPIVersion,
		ProvenanceTool:           provenanceTool(),
		OmitProvenance:           request.noProvenance,
	})
	*report = rep
	if err != nil {
		return err
	}

	documents := make([]any, 0, len(converted))
	for _, policy := range converted {
		documents = append(documents, policy)
	}
	return writeConvertOutput(out, request, documents, nil)
}

func runConvertToVAP(cmd *cobra.Command, request convertRequest, out io.Writer, report *convert.Report) error {
	source, err := resolveKyvernoSourcePath(cmd, request)
	if err != nil {
		return err
	}
	policies, err := kyverno.LoadValidatingPolicies(source)
	if err != nil {
		return err
	}
	if len(policies) == 0 {
		return fmt.Errorf("no Kyverno ValidatingPolicy documents found in %s", source)
	}

	vaps, bindings, rep, err := convert.KyvernoSetToVAP(policies, convert.KyvernoToVAPOptions{
		DefaultValidationActions: request.validationActions,
		ProvenanceTool:           provenanceTool(),
		OmitProvenance:           request.noProvenance,
	})
	*report = rep
	if err != nil {
		return err
	}

	policyDocs := make([]any, 0, len(vaps))
	for _, vap := range vaps {
		policyDocs = append(policyDocs, vap)
	}
	bindingDocs := make([]any, 0, len(bindings))
	for _, binding := range bindings {
		bindingDocs = append(bindingDocs, binding)
	}
	return writeConvertOutput(out, request, policyDocs, bindingDocs)
}

// loadVAPSource reads ValidatingAdmissionPolicies and bindings from whichever
// source the flags selected.
func loadVAPSource(cmd *cobra.Command, request convertRequest) (
	[]admissionregistrationv1.ValidatingAdmissionPolicy,
	[]admissionregistrationv1.ValidatingAdmissionPolicyBinding,
	error) {
	switch {
	case request.fromCluster:
		policies, err := kubernetes.ListValidatingAdmissionPolicies()
		if err != nil {
			return nil, nil, err
		}
		bindings, err := kubernetes.ListValidatingAdmissionPolicyBindings()
		if err != nil {
			return nil, nil, err
		}
		return policies, bindings, nil

	case request.bundleName != "":
		policiesPath, bindingsPath, err := locateInstalledBundle(request.bundleName, request.bundleVersion)
		if err != nil {
			return nil, nil, err
		}
		policyFiles, err := config.CollectManifestFilesRecursive(policiesPath)
		if err != nil {
			return nil, nil, err
		}
		bindingFiles, err := config.CollectManifestFilesRecursive(bindingsPath)
		if err != nil {
			return nil, nil, err
		}
		policies, err := config.LoadPoliciesFromFilesWithProgress(policyFiles, nil)
		if err != nil {
			return nil, nil, err
		}
		bindings, err := config.LoadBindingsFromFilesWithProgress(bindingFiles, nil)
		if err != nil {
			return nil, nil, err
		}
		return policies, bindings, nil

	case request.policyName != "":
		path, err := resolveDownloadedPolicyPath(cmd, request.policyName)
		if err != nil {
			return nil, nil, err
		}
		policies, err := kubernetes.LoadValidatingAdmissionPolicies(path)
		if err != nil {
			return nil, nil, err
		}
		bindings, err := kubernetes.LoadValidatingAdmissionPolicyBindings(path)
		if err != nil {
			return nil, nil, err
		}
		return policies, bindings, nil

	default:
		policyPath, bindingPath := request.policyPath, request.bindingPath
		if policyPath == "" {
			policyPath = bindingPath
			logging.Debugf("No policies path provided, reusing %s", bindingPath)
		}
		if bindingPath == "" {
			bindingPath = policyPath
			logging.Debugf("No bindings path provided, reusing %s", policyPath)
		}
		policies, err := kubernetes.LoadValidatingAdmissionPolicies(policyPath)
		if err != nil {
			return nil, nil, err
		}
		bindings, err := kubernetes.LoadValidatingAdmissionPolicyBindings(bindingPath)
		if err != nil {
			return nil, nil, err
		}
		if len(policies) == 0 {
			return nil, nil, fmt.Errorf("no ValidatingAdmissionPolicy documents found in %s", policyPath)
		}
		return policies, bindings, nil
	}
}

// resolveKyvernoSourcePath returns the path holding the Kyverno policies to
// convert.
func resolveKyvernoSourcePath(cmd *cobra.Command, request convertRequest) (string, error) {
	switch {
	case request.bundleName != "":
		policiesPath, _, err := locateInstalledBundle(request.bundleName, request.bundleVersion)
		return policiesPath, err
	case request.policyName != "":
		return resolveDownloadedPolicyPath(cmd, request.policyName)
	default:
		return request.policyPath, nil
	}
}

func resolveDownloadedPolicyPath(cmd *cobra.Command, policyName string) (string, error) {
	version, err := ensurePolicyVersionAvailable(cmd, "")
	if err != nil {
		return "", err
	}
	index, err := loadPoliciesIndex(cmd.Context())
	if err != nil {
		return "", err
	}
	return resolvePolicyFileWithIndex(index, policyName, version)
}

// convertOutputWriter returns the writer manifests go to. Notes always go to
// stderr through the logger, so stdout stays pipeable.
func convertOutputWriter(cmd *cobra.Command, request convertRequest) (io.Writer, func(), error) {
	noop := func() {}
	if request.outputPath == "" {
		return logging.Writer(), noop, nil
	}
	if info, err := os.Stat(request.outputPath); err == nil && info.IsDir() {
		// Directory output is written per document set, not through one writer.
		return nil, noop, nil
	}

	f, err := os.Create(request.outputPath)
	if err != nil {
		return nil, noop, fmt.Errorf("failed to open output file: %w", err)
	}
	logging.SetReportWriter(f)
	return f, func() {
		_ = f.Close()
		logging.SetReportWriter(cmd.OutOrStdout())
	}, nil
}

// writeConvertOutput renders the converted documents. A nil writer means
// --output named a directory, so policies and bindings go to separate files.
func writeConvertOutput(out io.Writer, request convertRequest, policyDocs, bindingDocs []any) error {
	if out != nil {
		return renderConvertDocuments(out, request.format, append(append([]any(nil), policyDocs...), bindingDocs...))
	}

	if err := writeConvertFile(filepath.Join(request.outputPath, convertPoliciesFileName), request.format, policyDocs); err != nil {
		return err
	}
	if len(bindingDocs) == 0 {
		return nil
	}
	return writeConvertFile(filepath.Join(request.outputPath, convertBindingsFileName), request.format, bindingDocs)
}

func writeConvertFile(path, format string, documents []any) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to open output file: %w", err)
	}
	defer f.Close()
	return renderConvertDocuments(f, format, documents)
}

// renderConvertDocuments writes documents as a YAML stream or a JSON array.
func renderConvertDocuments(out io.Writer, format string, documents []any) error {
	values := make([]map[string]any, 0, len(documents))
	for _, document := range documents {
		value, err := convertDocumentValue(document)
		if err != nil {
			return err
		}
		values = append(values, value)
	}

	if format == "json" {
		data, err := json.MarshalIndent(values, "", "  ")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(out, string(data))
		return err
	}

	for i, value := range values {
		data, err := sigsyaml.Marshal(value)
		if err != nil {
			return err
		}
		if i > 0 {
			if _, err := fmt.Fprintln(out, "---"); err != nil {
				return err
			}
		}
		if _, err := out.Write(bytes.TrimSpace(data)); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(out); err != nil {
			return err
		}
	}
	return nil
}

// convertDocumentValue renders one converted object into a generic map. Kyverno
// policies go through kyverno.Marshal so a v1alpha1 target gets the right field
// spelling, and every document is pruned of the placeholder fields the
// Kubernetes structs always serialize.
func convertDocumentValue(document any) (map[string]any, error) {
	var (
		data []byte
		err  error
	)
	if policy, ok := document.(kyverno.ValidatingPolicy); ok {
		data, err = kyverno.Marshal(policy)
	} else {
		data, err = sigsyaml.Marshal(document)
	}
	if err != nil {
		return nil, err
	}

	var value map[string]any
	if err := sigsyaml.Unmarshal(data, &value); err != nil {
		return nil, err
	}
	pruneGeneratedFields(value)
	return value, nil
}

// pruneGeneratedFields drops the empty status and null creationTimestamp that
// the Kubernetes structs serialize unconditionally. kubeapt authors these
// documents, so neither carries meaning, and both are noise in a manifest
// intended to be applied.
func pruneGeneratedFields(value map[string]any) {
	if status, ok := value["status"]; ok && isEmptyDocumentField(status) {
		delete(value, "status")
	}
	metadata, ok := value["metadata"].(map[string]any)
	if !ok {
		return
	}
	if timestamp, ok := metadata["creationTimestamp"]; ok && timestamp == nil {
		delete(metadata, "creationTimestamp")
	}
	if len(metadata) == 0 {
		delete(value, "metadata")
	}
}

func isEmptyDocumentField(value any) bool {
	switch typed := value.(type) {
	case nil:
		return true
	case map[string]any:
		return len(typed) == 0
	default:
		return false
	}
}

// reportConversionNotes logs everything the conversion could not carry over.
// Notes go to stderr so stdout carries only manifests; --log-level governs how
// much is shown.
func reportConversionNotes(report convert.Report) {
	for _, note := range report.Notes {
		message := formatConversionNote(note)
		switch note.Level {
		case convert.LevelError:
			logging.Errorf("%s", message)
		case convert.LevelWarn:
			logging.Warnf("%s", message)
		default:
			logging.Debugf("%s", message)
		}
	}

	errors := report.Count(convert.LevelError)
	warnings := report.Count(convert.LevelWarn)
	if errors == 0 && warnings == 0 {
		return
	}
	logging.Warnf("Conversion finished with %d warning(s) and %d finding(s) that change policy behaviour", warnings, errors)
}

func formatConversionNote(note convert.Note) string {
	location := note.Source
	if note.Field != "" {
		location += " " + note.Field
	}
	if note.Target != "" && note.Target != note.Source {
		return fmt.Sprintf("%s -> %s: %s", location, note.Target, note.Message)
	}
	return fmt.Sprintf("%s: %s", location, note.Message)
}

// parseValidationActions parses a comma separated action list, accepting any
// capitalization of the three Kubernetes actions.
func parseValidationActions(raw string) ([]admissionregistrationv1.ValidationAction, error) {
	var out []admissionregistrationv1.ValidationAction
	for _, field := range strings.Split(raw, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		switch strings.ToLower(field) {
		case "deny":
			out = append(out, admissionregistrationv1.Deny)
		case "warn":
			out = append(out, admissionregistrationv1.Warn)
		case "audit":
			out = append(out, admissionregistrationv1.Audit)
		default:
			return nil, fmt.Errorf("invalid validation action %s, expected Deny, Warn, or Audit", field)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("--validation-actions requires at least one of Deny, Warn, or Audit")
	}
	return out, nil
}

func provenanceTool() string {
	return "kubeapt/" + appVersion
}
