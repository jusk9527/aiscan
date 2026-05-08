package scan

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/chainreactors/parsers"
	"github.com/chainreactors/utils"
)

type webEndpoint struct {
	URL        string
	HostHeader string
	Source     string
}

type fingerprint struct {
	Target string
	Name   string
	Source string
}

type sprayObservation struct {
	Result     *parsers.SprayResult
	Capability string
}

type verificationResult struct {
	Finding verificationFinding
	Source  string
}

type projector struct {
	mu             sync.Mutex
	inputs         []string
	debug          bool
	stream         io.Writer
	streamOptions  outputOptions
	fileLines      []string
	stats          *statsCollector
	webEndpoints   []webEndpoint
	gogoResults    []*parsers.GOGOResult
	sprayResults   []sprayObservation
	fingerprints   []fingerprint
	zombieResults  []*parsers.ZombieResult
	neutronMatches []string
	verifications  []verificationResult
	errors         []string
	trace          []string
	seenWeb        map[string]struct{}
	seenFinger     map[string]struct{}
}

type projectorOptions struct {
	Debug       bool
	Stream      io.Writer
	StreamColor bool
}

func newProjector(inputs []string, opts projectorOptions) *projector {
	return &projector{
		inputs:        append([]string(nil), inputs...),
		debug:         opts.Debug,
		stream:        opts.Stream,
		streamOptions: outputOptions{Color: opts.StreamColor},
		fileLines:     make([]string, 0),
		stats:         newStatsCollector(len(inputs)),
		seenWeb:       make(map[string]struct{}),
		seenFinger:    make(map[string]struct{}),
	}
}

func (p *projector) Observe(pipelineEvent pipelineEvent) {
	var streamEvent event
	var streamLine string

	p.mu.Lock()

	if p.debug {
		p.trace = append(p.trace, formatTraceEvent(pipelineEvent))
	}
	if p.stats != nil {
		p.stats.Observe(pipelineEvent)
	}
	if pipelineEvent.Action != pipelineEventAccept {
		p.mu.Unlock()
		return
	}

	p.recordAcceptedEvent(pipelineEvent.Event)
	plain := formatEventLine(pipelineEvent.Event, outputOptions{})
	if plain != "" {
		p.fileLines = append(p.fileLines, plain)
		streamEvent = pipelineEvent.Event
		streamLine = plain
	}
	stream := p.stream
	streamOptions := p.streamOptions
	p.mu.Unlock()

	if streamLine == "" || stream == nil {
		return
	}
	line := formatEventLine(streamEvent, streamOptions)
	if line != "" {
		fmt.Fprintln(stream, line)
	}
}

func (p *projector) recordAcceptedEvent(event event) {
	switch event.Kind {
	case eventTarget:
		p.recordTargetEvent(event)
	case eventFinding:
		p.recordFindingEvent(event)
	case eventError:
		if event.Error.Message != "" {
			p.errors = append(p.errors, event.Error.Message)
		}
	}
}

func (p *projector) recordTargetEvent(event event) {
	switch target := event.Target.(type) {
	case webTarget:
		key := utils.NormalizeURL(target.URL) + "|host=" + strings.ToLower(target.HostHeader)
		if _, ok := p.seenWeb[key]; !ok {
			p.seenWeb[key] = struct{}{}
			p.webEndpoints = append(p.webEndpoints, webEndpoint{
				URL:        target.URL,
				HostHeader: target.HostHeader,
				Source:     event.Source,
			})
		}
	case serviceTarget:
		if target.Result != nil {
			p.gogoResults = append(p.gogoResults, target.Result)
		}
	case webProbeTarget:
		if reportableSprayResult(target.Result) {
			source := target.Capability
			if source == "" {
				source = event.Source
			}
			p.sprayResults = append(p.sprayResults, sprayObservation{
				Result:     target.Result,
				Capability: source,
			})
		}
	}
}

func (p *projector) recordFindingEvent(event event) {
	switch finding := event.Finding.(type) {
	case fingerprintFinding:
		for _, name := range parsers.NormalizeNames(finding.Fingers) {
			key := strings.ToLower(finding.Target) + "|" + strings.ToLower(name)
			if _, ok := p.seenFinger[key]; ok {
				continue
			}
			p.seenFinger[key] = struct{}{}
			p.fingerprints = append(p.fingerprints, fingerprint{
				Target: finding.Target,
				Name:   name,
				Source: event.Source,
			})
		}
	case weakpassFinding:
		if finding.Result != nil {
			p.zombieResults = append(p.zombieResults, finding.Result)
		}
	case vulnFinding:
		if finding.Message != "" {
			p.neutronMatches = append(p.neutronMatches, finding.Message)
		}
	case verificationFinding:
		if finding.Status != "" || finding.Summary != "" {
			p.verifications = append(p.verifications, verificationResult{
				Finding: finding,
				Source:  event.Source,
			})
		}
	}
}

func (p *projector) Finish() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.stats != nil {
		p.stats.Finish()
	}
}

func (p *projector) JSONLines() (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	var sb strings.Builder
	for _, result := range p.gogoResults {
		line, err := json.Marshal(result)
		if err != nil {
			return "", err
		}
		sb.Write(line)
		sb.WriteByte('\n')
	}
	for _, item := range p.sprayResults {
		line, err := json.Marshal(item.Result)
		if err != nil {
			return "", err
		}
		sb.Write(line)
		sb.WriteByte('\n')
	}
	return sb.String(), nil
}

func (p *projector) String() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	stats := p.statsSnapshotLocked()

	var sb strings.Builder
	sb.WriteString(p.summaryLineLocked(stats))

	if len(stats.CapabilityRuns) > 0 {
		sb.WriteString("\n")
		sb.WriteString(metricLine("runs", stats.CapabilityRuns))
	}
	if len(stats.SprayByCapability) > 0 {
		sb.WriteString("\n")
		sb.WriteString(metricLine("spray", stats.SprayByCapability))
	}
	if len(stats.ErrorsBySource) > 0 {
		sb.WriteString("\n")
		sb.WriteString(metricLine("errors", stats.ErrorsBySource))
	}

	if len(p.trace) > 0 {
		sb.WriteString("\n## Pipeline Trace\n")
		for _, line := range p.trace {
			sb.WriteString("- ")
			sb.WriteString(line)
			sb.WriteString("\n")
		}
	}

	return sb.String()
}

func (p *projector) ReportMarkdown() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	stats := p.statsSnapshotLocked()

	var sb strings.Builder
	sb.WriteString("# Scan Report\n\n")
	sb.WriteString(p.summaryLineLocked(stats))
	sb.WriteString("\n\n")

	sb.WriteString("## Metrics\n\n")
	sb.WriteString("| Metric | Value |\n")
	sb.WriteString("| --- | ---: |\n")
	sb.WriteString(fmt.Sprintf("| Inputs | %d |\n", stats.Inputs))
	sb.WriteString(fmt.Sprintf("| Open services | %d |\n", len(p.gogoResults)))
	sb.WriteString(fmt.Sprintf("| Web endpoints | %d |\n", len(p.webEndpoints)))
	sb.WriteString(fmt.Sprintf("| Web probes | %d |\n", len(p.sprayResults)))
	sb.WriteString(fmt.Sprintf("| Fingerprints | %d |\n", len(p.fingerprints)))
	sb.WriteString(fmt.Sprintf("| Weakpass findings | %d |\n", len(p.zombieResults)))
	sb.WriteString(fmt.Sprintf("| Vulnerability findings | %d |\n", len(p.neutronMatches)))
	sb.WriteString(fmt.Sprintf("| AI verifications | %d |\n", len(p.verifications)))
	sb.WriteString(fmt.Sprintf("| Errors | %d |\n", len(p.errors)))
	sb.WriteString(fmt.Sprintf("| Duration | %s |\n", stats.Duration().Round(time.Millisecond)))

	if len(stats.CapabilityRuns) > 0 {
		sb.WriteString("\n## Capability Runs\n\n")
		writeCountTable(&sb, "Capability", stats.CapabilityRuns)
	}

	if len(p.gogoResults) > 0 {
		sb.WriteString("\n## Open Services\n\n")
		for _, result := range sortedGogoResults(p.gogoResults) {
			sb.WriteString("- ")
			sb.WriteString(stripANSI(strings.TrimSpace(result.String())))
			sb.WriteString("\n")
		}
	}

	if len(p.webEndpoints) > 0 {
		sb.WriteString("\n## Web Endpoints\n\n")
		for _, endpoint := range sortedWebEndpoints(p.webEndpoints) {
			sb.WriteString("- ")
			sb.WriteString(endpoint.URL)
			if endpoint.HostHeader != "" {
				sb.WriteString(" host=")
				sb.WriteString(endpoint.HostHeader)
			}
			if endpoint.Source != "" {
				sb.WriteString(" source=")
				sb.WriteString(endpoint.Source)
			}
			sb.WriteString("\n")
		}
	}

	if len(p.sprayResults) > 0 {
		sb.WriteString("\n## Web Probe Results\n\n")
		for _, item := range sortedSprayResults(p.sprayResults) {
			if item.Result == nil {
				continue
			}
			sb.WriteString("- ")
			sb.WriteString(item.Capability)
			sb.WriteString(" ")
			sb.WriteString(stripANSI(strings.TrimSpace(item.Result.String())))
			sb.WriteString("\n")
		}
	}

	if len(p.fingerprints) > 0 {
		sb.WriteString("\n## Fingerprints\n\n")
		for _, finger := range sortedFingerprints(p.fingerprints) {
			sb.WriteString(fmt.Sprintf("- %s %s", finger.Target, finger.Name))
			if finger.Source != "" {
				sb.WriteString(" source=")
				sb.WriteString(finger.Source)
			}
			sb.WriteString("\n")
		}
	}

	if len(p.zombieResults) > 0 {
		sb.WriteString("\n## Weakpass Findings\n\n")
		for _, result := range p.zombieResults {
			sb.WriteString("- ")
			sb.WriteString(stripANSI(strings.TrimSpace(result.Format(parsers.ZombieFormatWeakpassFinding))))
			sb.WriteString("\n")
		}
	}

	if len(p.neutronMatches) > 0 {
		sb.WriteString("\n## Vulnerability Findings\n\n")
		for _, line := range sortedStrings(p.neutronMatches) {
			sb.WriteString("- ")
			sb.WriteString(line)
			sb.WriteString("\n")
		}
	}

	if len(p.verifications) > 0 {
		sb.WriteString("\n## AI Verification Results\n\n")
		for _, item := range sortedVerificationResults(p.verifications) {
			finding := item.Finding
			sb.WriteString("- ")
			sb.WriteString(string(finding.Status))
			sb.WriteString(" priority=")
			sb.WriteString(string(finding.OriginalPriority))
			if finding.Target != "" {
				sb.WriteString(" target=")
				sb.WriteString(finding.Target)
			}
			if finding.OriginalKind != "" {
				sb.WriteString(" finding=")
				sb.WriteString(string(finding.OriginalKind))
			}
			if finding.Summary != "" {
				sb.WriteString(" summary=")
				sb.WriteString(finding.Summary)
			}
			if finding.Evidence != "" {
				sb.WriteString(" evidence=")
				sb.WriteString(finding.Evidence)
			}
			if item.Source != "" {
				sb.WriteString(" source=")
				sb.WriteString(item.Source)
			}
			sb.WriteString("\n")
		}
	}

	if len(p.errors) > 0 {
		sb.WriteString("\n## Errors\n\n")
		for _, line := range sortedStrings(p.errors) {
			sb.WriteString("- ")
			sb.WriteString(line)
			sb.WriteString("\n")
		}
	}

	return sb.String()
}

func (p *projector) summaryLineLocked(stats statsSnapshot) string {
	return fmt.Sprintf("[scan] completed inputs=%d open=%d web=%d probes=%d fingerprints=%d weakpass=%d vulns=%d verified=%d errors=%d duration=%s\n",
		stats.Inputs,
		len(p.gogoResults),
		len(p.webEndpoints),
		len(p.sprayResults),
		len(p.fingerprints),
		len(p.zombieResults),
		len(p.neutronMatches),
		len(p.verifications),
		len(p.errors),
		stats.Duration().Round(time.Millisecond))
}

func (p *projector) PlainText() string {
	p.mu.Lock()
	defer p.mu.Unlock()

	var sb strings.Builder
	for _, line := range p.fileLines {
		sb.WriteString(line)
		sb.WriteByte('\n')
	}
	sb.WriteString(p.summaryLineLocked(p.statsSnapshotLocked()))
	return sb.String()
}

func (p *projector) statsSnapshotLocked() statsSnapshot {
	if p.stats != nil {
		return p.stats.Snapshot()
	}
	stats := newStatsCollector(len(p.inputs))
	stats.Finish()
	return stats.Snapshot()
}

func sprayResultSortKey(item sprayObservation) string {
	if item.Result == nil {
		return item.Capability
	}
	return item.Result.UrlString + "|" + item.Capability + "|" + item.Result.Source.Name()
}

func sortedGogoResults(results []*parsers.GOGOResult) []*parsers.GOGOResult {
	out := append([]*parsers.GOGOResult(nil), results...)
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].GetTarget() < out[j].GetTarget()
	})
	return out
}

func sortedVerificationResults(results []verificationResult) []verificationResult {
	out := append([]verificationResult(nil), results...)
	sort.SliceStable(out, func(i, j int) bool {
		left := out[i].Finding
		right := out[j].Finding
		return string(left.Status)+"|"+left.Target+"|"+left.OriginalKey < string(right.Status)+"|"+right.Target+"|"+right.OriginalKey
	})
	return out
}

func sortedWebEndpoints(endpoints []webEndpoint) []webEndpoint {
	out := append([]webEndpoint(nil), endpoints...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].URL == out[j].URL {
			return out[i].HostHeader < out[j].HostHeader
		}
		return out[i].URL < out[j].URL
	})
	return out
}

func sortedSprayResults(results []sprayObservation) []sprayObservation {
	out := append([]sprayObservation(nil), results...)
	sort.SliceStable(out, func(i, j int) bool {
		return sprayResultSortKey(out[i]) < sprayResultSortKey(out[j])
	})
	return out
}

func sortedFingerprints(fingers []fingerprint) []fingerprint {
	out := append([]fingerprint(nil), fingers...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Target == out[j].Target {
			return out[i].Name < out[j].Name
		}
		return out[i].Target < out[j].Target
	})
	return out
}

func sortedStrings(values []string) []string {
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}

func formatTraceEvent(event pipelineEvent) string {
	line := fmt.Sprintf("[scan:debug] action=%s", event.Action)
	if event.Capability != "" {
		line += " capability=" + event.Capability
	}
	line += fmt.Sprintf(" kind=%s key=%q source=%s", event.Event.label(), event.Event.key(), event.Event.Source)
	switch target := event.Event.Target.(type) {
	case scanTarget:
		if target.Target != "" {
			line += " target=" + target.Target
		}
	case serviceTarget:
		if target.Result != nil {
			line += " target=" + target.Result.GetTarget()
		}
	case webTarget:
		if target.URL != "" {
			line += " url=" + target.URL
		}
		if target.HostHeader != "" {
			line += " host=" + target.HostHeader
		}
	case webProbeTarget:
		if target.Result != nil && target.Result.UrlString != "" {
			line += " url=" + target.Result.UrlString
		}
		if target.HostHeader != "" {
			line += " host=" + target.HostHeader
		}
	case hostCandidateTarget:
		if target.Host != "" {
			line += " host=" + target.Host
		}
	case pocTarget:
		if target.Target != "" {
			line += " target=" + target.Target
		}
	case weakpassTarget:
		if target.Target.Address() != ":" {
			line += " target=" + target.Target.Address()
		}
	}
	if event.Event.Kind == eventError && event.Event.Error.Message != "" {
		line += " message=" + event.Event.Error.Message
	}
	return line
}
