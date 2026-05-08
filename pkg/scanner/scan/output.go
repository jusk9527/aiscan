package scan

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/chainreactors/parsers"
)

const (
	ansiReset  = "\x1b[0m"
	ansiDim    = "\x1b[2m"
	ansiCyan   = "\x1b[36m"
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
	ansiRed    = "\x1b[31m"
	ansiBold   = "\x1b[1m"
)

type outputOptions struct {
	Color bool
}

var ansiPattern = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

func stripANSI(value string) string {
	return ansiPattern.ReplaceAllString(value, "")
}

func colorize(enabled bool, code, value string) string {
	if !enabled || value == "" {
		return value
	}
	return code + value + ansiReset
}

func colorForPriority(priority priority) string {
	switch priority {
	case priorityLow:
		return ansiCyan
	case priorityMedium:
		return ansiYellow
	case priorityHigh:
		return ansiRed
	case priorityCritical:
		return ansiBold + ansiRed
	default:
		return ansiDim
	}
}

func formatEventLine(event event, opts outputOptions) string {
	source := event.Source
	if source == "" || source == "input" {
		source = "scan"
	}
	prefix := colorize(opts.Color, ansiDim, "["+source+"]")

	switch event.Kind {
	case eventTarget:
		switch target := event.Target.(type) {
		case serviceTarget:
			if target.Result == nil {
				return ""
			}
			return sanitizeOutputLine(fmt.Sprintf("%s %s", prefix, strings.TrimSpace(target.Result.String())), opts)
		case webTarget:
			if target.URL == "" {
				return ""
			}
			line := fmt.Sprintf("%s %s %s", prefix, colorize(opts.Color, ansiGreen, "web"), target.URL)
			if target.HostHeader != "" {
				line += " " + colorize(opts.Color, ansiDim, "host="+target.HostHeader)
			}
			return sanitizeOutputLine(line, opts)
		case webProbeTarget:
			if !reportableSprayResult(target.Result) {
				return ""
			}
			return sanitizeOutputLine(fmt.Sprintf("%s %s", prefix, strings.TrimSpace(target.Result.String())), opts)
		}
	case eventFinding:
		switch finding := event.Finding.(type) {
		case fingerprintFinding:
			names := parsers.NormalizeNames(finding.Fingers)
			if len(names) == 0 {
				return ""
			}
			return formatPriorityLine(prefix, finding.Priority(), "finger", fmt.Sprintf("%s %s", finding.Target, strings.Join(names, ",")), opts)
		case weakpassFinding:
			if finding.Result == nil {
				return ""
			}
			return formatPriorityLine(prefix, finding.Priority(), "weakpass", strings.TrimSpace(finding.Result.Format(parsers.ZombieFormatWeakpassFinding)), opts)
		case vulnFinding:
			if finding.Message == "" {
				return ""
			}
			return formatPriorityLine(prefix, finding.Priority(), "vuln", finding.Message, opts)
		case verificationFinding:
			return formatPriorityLine(prefix, finding.Priority(), "verify", formatVerificationFinding(finding), opts)
		}
	case eventError:
		if event.Error.Message == "" {
			return ""
		}
		return sanitizeOutputLine(fmt.Sprintf("%s %s %s", prefix, colorize(opts.Color, ansiRed, "error"), event.Error.Message), opts)
	}
	return ""
}

func formatPriorityLine(prefix string, priority priority, label, body string, opts outputOptions) string {
	if body == "" {
		return ""
	}
	priorityText := strings.ToUpper(string(priority))
	if priorityText == "" {
		priorityText = "INFO"
	}
	tag := colorize(opts.Color, colorForPriority(priority), priorityText)
	name := colorize(opts.Color, colorForPriority(priority), label)
	return sanitizeOutputLine(fmt.Sprintf("%s %s %s %s", prefix, tag, name, body), opts)
}

func sanitizeOutputLine(line string, opts outputOptions) string {
	line = strings.TrimSpace(line)
	if !opts.Color {
		line = stripANSI(line)
	}
	return line
}

func formatVerificationFinding(finding verificationFinding) string {
	parts := []string{string(finding.Status)}
	if finding.OriginalPriority != "" {
		parts = append(parts, "priority="+string(finding.OriginalPriority))
	}
	if finding.Target != "" {
		parts = append(parts, finding.Target)
	}
	if finding.Summary != "" {
		parts = append(parts, finding.Summary)
	}
	if finding.Evidence != "" {
		parts = append(parts, "evidence="+finding.Evidence)
	}
	return strings.Join(parts, " ")
}
