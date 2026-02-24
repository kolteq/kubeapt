package logging

import (
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/rs/zerolog"
)

func resetLogging() {
	globalLogger = zerolog.New(io.Discard)
	fileCloser = nil
	consoleWriter = nil
	reportWriter = nil
	initOnce = sync.Once{}
}

func TestInitSetsFileCloserOnce(t *testing.T) {
	resetLogging()

	dir := t.TempDir()
	first := filepath.Join(dir, "first.log")
	second := filepath.Join(dir, "second.log")

	if err := Init(first, "debug"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fileCloser == nil {
		t.Fatalf("expected fileCloser to be set")
	}

	if err := Init(second, "error"); err != nil {
		t.Fatalf("unexpected error on second init: %v", err)
	}

	if f, ok := fileCloser.(*os.File); ok {
		if f.Name() != first {
			t.Fatalf("expected fileCloser to remain %q, got %q", first, f.Name())
		}
	}

	Close()
}

func TestSetLevel(t *testing.T) {
	resetLogging()
	globalLogger = zerolog.New(io.Discard)

	setLevel("debug")
	if globalLogger.GetLevel() != zerolog.DebugLevel {
		t.Fatalf("expected debug level, got %v", globalLogger.GetLevel())
	}

	setLevel("warn")
	if globalLogger.GetLevel() != zerolog.WarnLevel {
		t.Fatalf("expected warn level, got %v", globalLogger.GetLevel())
	}
}
