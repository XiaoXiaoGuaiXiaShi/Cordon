package logger

import (
	"os"
	"strings"

	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

var (
	Logger *log.Entry
)

func init() {
	Logger = NewLogger()
}

func NewLogger() *log.Entry {
	return log.WithFields(log.Fields{"cordon_pid": os.Getpid()})
}

func SetLevel(level string) {
	level = strings.ToUpper(level)

	switch level {
	case "TRACE":
		log.SetLevel(log.TraceLevel)
	case "DEBUG":
		log.SetLevel(log.DebugLevel)
	case "INFO":
		log.SetLevel(log.InfoLevel)
	default:
		log.SetLevel(log.InfoLevel)
	}
}

func SetFormatter(format string) {
	switch format {
	case "json":
		log.SetFormatter(&log.JSONFormatter{})
	case "text":
		log.SetFormatter(&log.TextFormatter{})
	default:
		log.SetFormatter(&log.JSONFormatter{})
	}
}

func SetOutput(path string) {
	if path == "stdout" || path == "" {
		Logger.Logger.Out = os.Stdout
	} else {
		file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			Logger.Fatal(err)
		}
		Logger.Logger.Out = file
	}
}

func SetRotation(path string, maxSize, maxAge int) {
	if path == "stdout" || path == "" {
		return
	}

	log.SetOutput(&lumberjack.Logger{
		Filename: path,
		MaxSize:  maxSize,
		MaxAge:   maxAge,
	})
}

func SetLabel(labels map[string]string) {
	for k, v := range labels {
		Logger = Logger.WithFields(log.Fields{k: v})
	}
}

func Fatal(err error) {
	Logger.Fatal(err)
}

func Debug(message string) {
	Logger.Debug(message)
}

func Info(message string) {
	Logger.Info(message)
}

func Error(err error) {
	Logger.Error(err)
}

func WithFields(fields log.Fields) *log.Entry {
	return log.WithFields(fields)
}

type LogLabels struct {
	Labels map[string]string
}

type AuditEventLog struct {
	Action     string
	Hostname   string
	PID        uint32
	Comm       string
	ParentComm string
}

type RestrictedFileAccessLog struct {
	AuditEventLog
	Path string
}

func (l *RestrictedFileAccessLog) Info() {
	Logger.WithFields(logrus.Fields{
		"Action":     l.Action,
		"Hostname":   l.Hostname,
		"PID":        l.PID,
		"Comm":       l.Comm,
		"ParentComm": l.ParentComm,
		"Path":       l.Path,
	}).Info("File access is trapped in th filter.")
}

type RestrictedCapabilityLog struct {
	AuditEventLog
	Cap uint8
}

func (l *RestrictedCapabilityLog) Info() {
	Logger.WithFields(logrus.Fields{
		"Action":     l.Action,
		"Hostname":   l.Hostname,
		"PID":        l.PID,
		"Comm":       l.Comm,
		"ParentComm": l.ParentComm,
		"Cap":       l.Cap,
	}).Info("Capability control is trapped in th filter.")
}

type RestrictedSyscallLog struct {
	AuditEventLog
	Syscall string
}

func (l *RestrictedSyscallLog) Info() {
	Logger.WithFields(logrus.Fields{
		"Action":     l.Action,
		"Hostname":   l.Hostname,
		"PID":        l.PID,
		"Comm":       l.Comm,
		"ParentComm": l.ParentComm,
		"Syscall":       l.Syscall,
	}).Info("Syscall control is trapped in th filter.")
}