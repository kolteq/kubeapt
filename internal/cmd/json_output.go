// Copyright by KolTEQ GmbH
// Contact: benjamin@kolteq.com

package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/kolteq/kubeapt/internal/kubernetes"
)

type jsonEnvelope struct {
	Metadata jsonMetadata `json:"metadata"`
	Results  interface{} `json:"results"`
}

type jsonMetadata struct {
	Command    string           `json:"comand"`
	View       string           `json:"view"`
	Kubernetes jsonKubernetes    `json:"kubernetes"`
	Time       jsonTimeWindow    `json:"time"`
}

type jsonKubernetes struct {
	Name       string         `json:"name"`
	Namespaces []string       `json:"namespaces"`
	Resources  map[string]int `json:"resources"`
}

type jsonTimeWindow struct {
	Start int64 `json:"start"`
	Stop  int64 `json:"stop"`
}

func buildJSONMetadata(cmd *cobra.Command, view string, namespaces []string, resources map[string]int, start, stop time.Time) jsonMetadata {
	command := strings.Join(os.Args, " ")
	command = strings.TrimSpace(command)
	if command == "" {
		command = cmd.CommandPath()
	}

	name := strings.TrimSpace(kubernetes.ClusterName())
	if name == "" {
		name = "unknown"
	}

	metadataNamespaces := uniqueSortedStrings(namespaces)
	if metadataNamespaces == nil {
		metadataNamespaces = []string{}
	}

	if resources == nil {
		resources = map[string]int{}
	}

	return jsonMetadata{
		Command: command,
		View:    jsonViewLabel(view),
		Kubernetes: jsonKubernetes{
			Name:       name,
			Namespaces: metadataNamespaces,
			Resources:  resources,
		},
		Time: jsonTimeWindow{
			Start: start.Unix(),
			Stop:  stop.Unix(),
		},
	}
}

func writeJSONEnvelope(w io.Writer, metadata jsonMetadata, results interface{}) error {
	payload := jsonEnvelope{
		Metadata: metadata,
		Results:  results,
	}
	encoded, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, string(encoded))
	return err
}

func jsonViewLabel(view string) string {
	value := strings.ToLower(strings.TrimSpace(view))
	switch value {
	case "policy":
		return "policies"
	case "namespace":
		return "namespaces"
	case "resource":
		return "resources"
	default:
		return view
	}
}

func uniqueSortedStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		set[value] = struct{}{}
	}
	if len(set) == 0 {
		return nil
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
