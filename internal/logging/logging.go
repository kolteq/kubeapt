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
	globalLogger  zerolog.Logger
	fileCloser    io.Closer
	initOnce      sync.Once
	consoleWriter *zerolog.ConsoleWriter
	reportWriter  io.Writer
)

func Init(logFilePath, level string) error {
	var initErr error
	initOnce.Do(func() {
		if consoleWriter == nil {
			writer := zerolog.ConsoleWriter{
				Out:          os.Stdout,
				TimeFormat:   time.RFC3339,
				PartsExclude: []string{zerolog.TimestampFieldName},
			}
			consoleWriter = &writer
		}
		globalLogger = log.Output(consoleWriter)
		if reportWriter == nil {
			reportWriter = consoleWriter.Out
		}
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

func Infof(format string, args ...interface{}) {
	globalLogger.Info().Msgf(format, args...)
}

func Warnf(format string, args ...interface{}) {
	globalLogger.Warn().Msgf(format, args...)
}

func Errorf(format string, args ...interface{}) {
	globalLogger.Error().Msgf(format, args...)
}

func SetOutputWriter(w io.Writer) {
	if w == nil {
		return
	}
	if consoleWriter == nil {
		writer := zerolog.ConsoleWriter{
			Out:          w,
			TimeFormat:   time.RFC3339,
			PartsExclude: []string{zerolog.TimestampFieldName},
		}
		consoleWriter = &writer
		globalLogger = log.Output(consoleWriter)
		if reportWriter == nil {
			reportWriter = w
		}
		return
	}
	consoleWriter.Out = w
	if reportWriter == nil {
		reportWriter = w
	}
}

func SetReportWriter(w io.Writer) {
	if w == nil {
		return
	}
	reportWriter = w
}

func Writer() io.Writer {
	if reportWriter != nil {
		return reportWriter
	}
	if consoleWriter != nil && consoleWriter.Out != nil {
		return consoleWriter.Out
	}
	return os.Stdout
}

func Newline() {
	_, _ = io.WriteString(Writer(), "\n")
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
