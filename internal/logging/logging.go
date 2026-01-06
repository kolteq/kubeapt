// Copyright by KolTEQ GmbH
// Contact: benjamin@kolteq.com

package logging

import (
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var (
	globalLogger zerolog.Logger
	fileCloser   io.Closer
	initOnce     sync.Once
)

func Init(logFilePath, level string) error {
	var initErr error
	initOnce.Do(func() {
		consoleWriter := zerolog.ConsoleWriter{
			Out:        os.Stdout,
			TimeFormat: time.RFC3339,
		}
		globalLogger = log.Output(consoleWriter)
		setLevel(level)

		if logFilePath != "" {
			f, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
			if err != nil {
				initErr = err
				return
			}
			fileCloser = f
			globalLogger.Info().Msgf("Writing WARN/AUDIT logs to %s", logFilePath)
		}
	})
	return initErr
}

func Close() {
	if fileCloser != nil {
		fileCloser.Close()
	}
}

func Debugf(format string, args ...interface{}) {
	globalLogger.Debug().Msgf(format, args...)
}

func setLevel(level string) {
	lvl := zerolog.InfoLevel
	switch strings.ToLower(level) {
	case "debug":
		lvl = zerolog.DebugLevel
	case "warn":
		lvl = zerolog.WarnLevel
	case "error":
		lvl = zerolog.ErrorLevel
	case "info":
		lvl = zerolog.InfoLevel
	}
	globalLogger = globalLogger.Level(lvl)
}
