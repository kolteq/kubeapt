// Copyright by cenroq AG
// Contact: info@cenroq.com

package convert_test

import (
	"reflect"
	"testing"

	"github.com/cenroq/kubeapt/v2/pkg/convert"
)

func TestReportLevelsAndCounts(t *testing.T) {
	var rep convert.Report
	if rep.Len() != 0 || rep.Has(convert.LevelError) {
		t.Fatal("zero Report is not empty")
	}

	rep.Infof("VAP/a", "VP/a", "spec", "noted %d", 1)
	rep.Warnf("VAP/a", "VP/a", "spec.x", "dropped")
	rep.Errorf("VAP/a", "", "spec.paramKind", "not equivalent")
	rep.Warnf("VAP/b", "VP/b", "", "another")

	if rep.Len() != 4 {
		t.Errorf("got %d notes, want 4", rep.Len())
	}
	if got := rep.Count(convert.LevelWarn); got != 2 {
		t.Errorf("got %d warns, want 2", got)
	}
	if got := rep.Count(convert.LevelInfo); got != 1 {
		t.Errorf("got %d infos, want 1", got)
	}
	if !rep.Has(convert.LevelError) {
		t.Error("Has(LevelError) = false, want true")
	}
	if rep.Notes[0].Message != "noted 1" {
		t.Errorf("got message %q, want %q", rep.Notes[0].Message, "noted 1")
	}

	// Notes keep emission order.
	wantLevels := []convert.Level{convert.LevelInfo, convert.LevelWarn, convert.LevelError, convert.LevelWarn}
	var gotLevels []convert.Level
	for _, note := range rep.Notes {
		gotLevels = append(gotLevels, note.Level)
	}
	if !reflect.DeepEqual(gotLevels, wantLevels) {
		t.Errorf("got levels %v, want %v", gotLevels, wantLevels)
	}
}

func TestReportAbsorbFillsEmptyContext(t *testing.T) {
	var sub convert.Report
	sub.Warnf("", "", "spec.matchConstraints", "context free")
	sub.Errorf("Other/x", "Other/y", "spec.z", "already attributed")

	var rep convert.Report
	rep.Absorb(sub, "VAP/source", "VP/target")

	if rep.Len() != 2 {
		t.Fatalf("got %d notes, want 2", rep.Len())
	}
	if rep.Notes[0].Source != "VAP/source" || rep.Notes[0].Target != "VP/target" {
		t.Errorf("empty context not filled: %+v", rep.Notes[0])
	}
	if rep.Notes[1].Source != "Other/x" || rep.Notes[1].Target != "Other/y" {
		t.Errorf("populated context overwritten: %+v", rep.Notes[1])
	}

	// Absorbing must not mutate the source report.
	if sub.Notes[0].Source != "" {
		t.Errorf("Absorb mutated the absorbed report: %+v", sub.Notes[0])
	}
}
