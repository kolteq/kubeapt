// Copyright by cenroq AG
// Contact: info@cenroq.com

package convert

import (
	"fmt"
	"hash/fnv"
	"strings"
)

// maxNameLength is the DNS-1123 subdomain limit Kubernetes applies to
// metadata.name.
const maxNameLength = 253

// defaultProvenanceTool identifies kubeapt in provenance annotations when a
// caller supplies no version.
const defaultProvenanceTool = "kubeapt"

// derivedName joins parts with "-" and keeps the result a legal metadata.name.
// A name over the length limit is truncated and given a suffix derived from the
// full name, so distinct inputs stay distinct and the same input always
// produces the same output.
func derivedName(parts ...string) string {
	name := strings.Join(parts, "-")
	if len(name) <= maxNameLength {
		return name
	}

	hasher := fnv.New32a()
	_, _ = hasher.Write([]byte(name))
	suffix := fmt.Sprintf("-%08x", hasher.Sum32())

	prefix := strings.TrimRight(name[:maxNameLength-len(suffix)], "-.")
	return prefix + suffix
}

// objectRef names an object for a Note's Source or Target, as "Kind/name" or
// "Kind/namespace/name" when the object is namespaced.
func objectRef(kind, namespace, name string) string {
	if namespace != "" {
		return kind + "/" + namespace + "/" + name
	}
	return kind + "/" + name
}
