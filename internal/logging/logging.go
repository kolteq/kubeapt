// Copyright by KolTEQ GmbH
// Contact: benjamin@kolteq.com

package logging

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"
)

type ResourceRef struct {
	Kind      string `yaml:"kind"`
	Namespace string `yaml:"namespace,omitempty"`
	Name      string `yaml:"name"`
}

type DenyReport struct {
	Policy   string      `yaml:"policy"`
	Binding  string      `yaml:"binding"`
	Resource ResourceRef `yaml:"resource"`
	Message  string      `yaml:"message"`
}

var (
	globalLogger zerolog.Logger
	fileWriter   io.Writer
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
			fileWriter = f
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

func Errorf(format string, args ...interface{}) {
	globalLogger.Error().Msgf(format, args...)
}

func WarnUser(message string) {
	globalLogger.Warn().Msg(message)
	writeToFile("WARN: " + message)
}

func AuditUser(message string) {
	globalLogger.Info().Str("channel", "AUDIT").Msg(message)
	writeToFile("AUDIT: " + message)
}

func Deny(policyName, bindingName string, resource ResourceRef, message string) {
	report := DenyReport{
		Policy:   policyName,
		Binding:  bindingName,
		Resource: resource,
		Message:  message,
	}
	body, err := yaml.Marshal(report)
	if err != nil {
		globalLogger.Error().Err(err).Msg("failed to marshal deny report")
		return
	}

	globalLogger.Error().Msg("DENY event generated")
	fmt.Println("---")
	fmt.Print(string(body))
	writeToFile("DENY:\n" + string(body))
}

func writeToFile(line string) {
	if fileWriter == nil {
		return
	}
	if _, err := fileWriter.Write([]byte(line + "\n")); err != nil {
		globalLogger.Error().Err(err).Msg("failed to write log file entry")
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
