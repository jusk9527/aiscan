package scan

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/chainreactors/utils"
)

func buildSeedEvents(rawInputs []string, sink eventSink) []event {
	var seeds []event
	for _, raw := range rawInputs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		events := seedEventsFromInput(raw)
		if len(events) == 0 {
			if sink != nil {
				sink.Observe(pipelineEvent{Action: pipelineEventAccept, Event: errorEventOf("", fmt.Sprintf("skip invalid input: %s", raw))})
			}
			continue
		}
		seeds = append(seeds, events...)
	}
	return seeds
}

func seedEventsFromInput(raw string) []event {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}

	if strings.Contains(raw, "://") {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Hostname() == "" {
			return nil
		}
		var seeds []event
		if utils.IsWebScheme(parsed.Scheme) {
			seeds = append(seeds, targetEvent("input", raw, newWebTarget(raw, raw, "")))
		}
		if host := parsed.Hostname(); utils.IsDomainHost(host) {
			seeds = append(seeds, targetEvent("input", raw, newHostCandidateTarget(raw, host)))
		}
		if target, ok := parseZombieTarget(raw, ""); ok {
			seeds = append(seeds, targetEvent("input", raw, newWeakpassTarget(raw, target)))
		}
		return seeds
	}

	if strings.Contains(raw, "/") {
		return []event{targetEvent("input", raw, newScanTarget(raw, raw, ""))}
	}

	if host, port, ok := utils.SplitHostPort(raw); ok {
		return seedEventsFromHostPort(host, port, raw)
	}

	seeds := []event{targetEvent("input", raw, newScanTarget(raw, raw, ""))}
	if utils.IsDomainHost(raw) {
		seeds = append(seeds, targetEvent("input", raw, newHostCandidateTarget(raw, raw)))
	}
	return seeds
}

func seedEventsFromHostPort(host, port, raw string) []event {
	seeds := []event{targetEvent("input", raw, newScanTarget(raw, host, port))}
	if utils.IsDomainHost(host) {
		seeds = append(seeds, targetEvent("input", raw, newHostCandidateTarget(raw, host)))
	}
	if utils.IsWebPort(port) {
		seeds = append(seeds, targetEvent("input", raw, newWebTarget(raw, webURLFromHostPort(host, port), "")))
	}
	if target, ok := parseZombieTarget(raw, ""); ok {
		seeds = append(seeds, targetEvent("input", raw, newWeakpassTarget(raw, target)))
	}
	return seeds
}
