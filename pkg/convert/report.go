// Copyright by cenroq AG
// Contact: info@cenroq.com

// Package convert translates between the Kubernetes ValidatingAdmissionPolicy
// model, where a policy and its bindings are separate objects, and Kyverno's
// ValidatingPolicy, which folds the binding's role into the policy itself.
//
// Everything here is pure: no filesystem, no network, no cluster, no logger.
// Every function takes typed structs and returns typed structs plus a Report
// describing where the translation lost or approximated meaning. Callers decide
// how to surface a Report; the kubeapt CLI logs it to stderr.
package convert

import (
	"errors"
	"fmt"
)

// Level classifies a Note's impact on conversion fidelity.
type Level string

const (
	// LevelInfo records a lossless restatement worth mentioning.
	LevelInfo Level = "Info"
	// LevelWarn records a dropped or defaulted field that changes neither which
	// requests the policy matches nor how it decides them.
	LevelWarn Level = "Warn"
	// LevelError records output that is not semantically equivalent to the
	// input. The output is still produced so a human can review and fix it;
	// kubeapt convert --strict exits non-zero when any is present.
	LevelError Level = "Error"
)

// Note is one fidelity observation about a single converted object.
type Note struct {
	Level Level `json:"level"`
	// Source names the input object, as "Kind/name".
	Source string `json:"source"`
	// Target names the emitted object, or "" when nothing was emitted for Source.
	Target string `json:"target,omitempty"`
	// Field is the JSON path the note is about, such as "spec.paramKind" or
	// "spec.validations[0].expression".
	Field string `json:"field,omitempty"`
	// Message is lowercase with no trailing punctuation, matching kubeapt's
	// error style.
	Message string `json:"message"`
}

// Report accumulates Notes in emission order.
type Report struct {
	Notes []Note `json:"notes,omitempty"`
}

// Add appends one note.
func (r *Report) Add(level Level, source, target, field, format string, args ...any) {
	r.Notes = append(r.Notes, Note{
		Level:   level,
		Source:  source,
		Target:  target,
		Field:   field,
		Message: fmt.Sprintf(format, args...),
	})
}

// Infof appends a LevelInfo note.
func (r *Report) Infof(source, target, field, format string, args ...any) {
	r.Add(LevelInfo, source, target, field, format, args...)
}

// Warnf appends a LevelWarn note.
func (r *Report) Warnf(source, target, field, format string, args ...any) {
	r.Add(LevelWarn, source, target, field, format, args...)
}

// Errorf appends a LevelError note.
func (r *Report) Errorf(source, target, field, format string, args ...any) {
	r.Add(LevelError, source, target, field, format, args...)
}

// Absorb appends other's notes, filling any empty Source or Target with the
// values given. It lets a helper produce notes without knowing its caller's
// context.
func (r *Report) Absorb(other Report, source, target string) {
	for _, note := range other.Notes {
		if note.Source == "" {
			note.Source = source
		}
		if note.Target == "" {
			note.Target = target
		}
		r.Notes = append(r.Notes, note)
	}
}

// Count returns how many notes carry the given level.
func (r *Report) Count(level Level) int {
	n := 0
	for _, note := range r.Notes {
		if note.Level == level {
			n++
		}
	}
	return n
}

// Has reports whether any note carries the given level.
func (r *Report) Has(level Level) bool {
	return r.Count(level) > 0
}

// Len returns the number of notes.
func (r *Report) Len() int {
	return len(r.Notes)
}

// Errors a caller can test for. They are returned only when a document produces
// no output at all; anything that is emitted but imperfect becomes a LevelError
// note instead.
var (
	// ErrUnsupportedEvaluationMode reports evaluation.mode JSON or Envoy, which
	// evaluate a payload a ValidatingAdmissionPolicy cannot receive.
	ErrUnsupportedEvaluationMode = errors.New("convert: evaluation mode has no ValidatingAdmissionPolicy equivalent")
	// ErrMissingNamespace reports a NamespacedValidatingPolicy with no
	// metadata.namespace, which leaves nothing to pin the converted policy to.
	ErrMissingNamespace = errors.New("convert: NamespacedValidatingPolicy has no metadata.namespace")
	// ErrNothingConverted reports that no input document produced output.
	ErrNothingConverted = errors.New("convert: no policies converted")
)
