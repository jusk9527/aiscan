package scan

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/chainreactors/parsers"
	sdkzombie "github.com/chainreactors/sdk/zombie"
)

func (c *Command) runPortDiscoveryCapability(ctx context.Context, discovery discoveryOptions, input target, emit emitFunc) {
	target, ok := input.(scanTarget)
	if !ok {
		return
	}
	ports := discovery.Ports
	if target.Ports != "" {
		ports = target.Ports
	}
	c.logger.Infof("[scan:%s] scanning %s ports=%s", capGogoPortscan, target.Target, ports)
	resultCh, err := gogoScanStream(ctx, c.engines.Gogo, gogoScanOptions{
		Target:  target.Target,
		Ports:   ports,
		Threads: discovery.Threads,
		Timeout: discovery.Timeout,
	})
	if err != nil {
		emit(errorEventOf(capGogoPortscan, fmt.Sprintf("gogo %s: %v", target.Target, err)))
		return
	}
	for result := range resultCh {
		if ctx.Err() != nil {
			return
		}
		if result == nil {
			continue
		}
		emit(targetEvent(capGogoPortscan, target.Raw, newServiceTarget(target.Raw, result)))
	}
}

func runServiceAnalysisCapability(_ context.Context, profile profile, input target, emit emitFunc) {
	target, ok := input.(serviceTarget)
	if !ok || target.Result == nil {
		return
	}
	deriveServiceResult(profile, serviceResult{Result: target.Result}, emit)
}

func (c *Command) runSprayCapability(ctx context.Context, flags flags, web webOptions, input target, source string, opts sprayCheckOptions, emit emitFunc) {
	target, ok := input.(webTarget)
	if !ok || target.URL == "" {
		return
	}
	opts.URLs = []string{target.URL}
	opts.Host = target.HostHeader
	opts.Dictionaries = web.Dictionaries
	opts.Rules = web.Rules
	opts.Word = web.Word
	opts.DefaultDict = web.DefaultDict
	opts.Advance = web.Advance
	opts.Threads = flags.SprayThreads
	opts.Timeout = flags.Timeout

	resultCh, err := sprayCheckStream(ctx, c.engines.Spray, opts)
	if err != nil {
		emit(errorEventOf(source, fmt.Sprintf("spray %s: %v", target.URL, err)))
		return
	}
	for result := range resultCh {
		if ctx.Err() != nil {
			return
		}
		if !reportableSprayResult(result) {
			continue
		}
		emit(targetEvent(source, target.Raw, newWebProbeTarget(target.Raw, source, target.HostHeader, result)))
	}
}

func runWebResultAnalysisCapability(_ context.Context, profile profile, input target, emit emitFunc) {
	target, ok := input.(webProbeTarget)
	if !ok || !reportableSprayResult(target.Result) {
		return
	}
	deriveWebProbeResult(profile, webProbeResult{Source: target.Capability, Result: target.Result, HostHeader: target.HostHeader}, emit)
}

func (c *Command) runHostCollisionCapability(ctx context.Context, flags flags, web webOptions, state *pipelineState, input target, emit emitFunc) {
	switch target := input.(type) {
	case webTarget:
		c.runHostCollisionForEndpoint(ctx, flags, web, state, target, state.hostCandidateList(), emit)
	case hostCandidateTarget:
		host := strings.ToLower(strings.TrimSpace(target.Host))
		if host == "" {
			return
		}
		for _, endpoint := range state.webEndpointList() {
			c.runHostCollisionForEndpoint(ctx, flags, web, state, endpoint, []string{host}, emit)
		}
	}
}

func (c *Command) runHostCollisionForEndpoint(ctx context.Context, flags flags, web webOptions, state *pipelineState, target webTarget, hosts []string, emit emitFunc) {
	if target.URL == "" || target.HostHeader != "" {
		return
	}
	parsed, err := url.Parse(target.URL)
	if err != nil || parsed.Hostname() == "" || net.ParseIP(parsed.Hostname()) == nil {
		return
	}
	for _, host := range hosts {
		if strings.EqualFold(host, parsed.Hostname()) {
			continue
		}
		if !state.markHostCollision(target.URL, host) {
			continue
		}
		c.runSprayCapability(ctx, flags, web, newWebTarget(target.Raw, target.URL, host), capSprayHost, sprayCheckOptions{
			Finger: true,
		}, emit)
	}
}

func (c *Command) runWeakpassCapability(ctx context.Context, flags flags, credentials credentialOptions, input target, emit emitFunc) {
	target, ok := input.(weakpassTarget)
	if !ok || target.Target.Service == "" || target.Target.Address() == ":" {
		return
	}

	resultCh, err := zombieWeakpassStream(ctx, c.engines.Zombie, zombieWeakpassOptions{
		Targets:   []sdkzombie.Target{target.Target},
		Threads:   flags.ZombieThreads,
		Timeout:   flags.Timeout,
		Top:       flags.ZombieTop,
		Users:     credentials.Users,
		Passwords: credentials.Passwords,
	})
	if err != nil {
		emit(errorEventOf(capZombieWeakpass, fmt.Sprintf("zombie %s: %v", target.Target.Address(), err)))
		return
	}
	for result := range resultCh {
		if ctx.Err() != nil {
			return
		}
		if result == nil {
			continue
		}
		deriveWeakpassResult(weakpassResult{Source: capZombieWeakpass, Result: result}, emit)
	}
}

func (c *Command) runPOCCapability(ctx context.Context, flags flags, input target, emit emitFunc) {
	target, ok := input.(pocTarget)
	if !ok || target.Target == "" {
		return
	}
	resultCh, err := neutronExecuteStream(ctx, c.engines.Neutron, c.engines.Index, neutronExecuteOptions{
		Target:       target.Target,
		Fingers:      parsers.NormalizeNames(target.Fingers),
		MaxPerFinger: flags.MaxNeutronPerFP,
	})
	if err == errNoNeutronTemplates {
		emit(errorEventOf(capNeutronPOC, fmt.Sprintf("neutron %s: skipped, no templates selected", target.Target)))
		return
	}
	if err != nil {
		emit(errorEventOf(capNeutronPOC, fmt.Sprintf("neutron %s: %v", target.Target, err)))
		return
	}
	for result := range resultCh {
		if ctx.Err() != nil {
			return
		}
		if result == nil || !result.Matched() {
			continue
		}
		tmpl := result.Template()
		templateID := ""
		severity := ""
		name := ""
		if tmpl != nil {
			templateID = tmpl.Id
			severity = tmpl.Info.Severity
			name = tmpl.Info.Name
		}
		emit(findingEvent(capNeutronPOC, vulnFinding{
			Message: fmt.Sprintf("[vuln] %s template=%s severity=%s name=%q", target.Target, templateID, severity, name),
		}))
	}
}
