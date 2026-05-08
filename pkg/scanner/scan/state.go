package scan

import (
	"sort"
	"strings"
	"sync"

	"github.com/chainreactors/utils"
)

type pipelineState struct {
	mu                sync.Mutex
	hostCandidates    map[string]struct{}
	webEndpoints      map[string]webTarget
	hostCollisionSeen map[string]struct{}
}

func newPipelineState() *pipelineState {
	return &pipelineState{
		hostCandidates:    make(map[string]struct{}),
		webEndpoints:      make(map[string]webTarget),
		hostCollisionSeen: make(map[string]struct{}),
	}
}

func (s *pipelineState) record(event event) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if event.Kind != eventTarget {
		return
	}
	switch target := event.Target.(type) {
	case hostCandidateTarget:
		host := strings.ToLower(strings.TrimSpace(target.Host))
		if host != "" {
			s.hostCandidates[host] = struct{}{}
		}
	case webTarget:
		key := utils.NormalizeURL(target.URL) + "|host=" + strings.ToLower(target.HostHeader)
		s.webEndpoints[key] = target
	}
}

func (s *pipelineState) hostCandidateList() []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	hosts := make([]string, 0, len(s.hostCandidates))
	for host := range s.hostCandidates {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	return hosts
}

func (s *pipelineState) webEndpointList() []webTarget {
	s.mu.Lock()
	defer s.mu.Unlock()

	endpoints := make([]webTarget, 0, len(s.webEndpoints))
	for _, endpoint := range s.webEndpoints {
		endpoints = append(endpoints, endpoint)
	}
	sort.SliceStable(endpoints, func(i, j int) bool {
		if endpoints[i].URL == endpoints[j].URL {
			return endpoints[i].HostHeader < endpoints[j].HostHeader
		}
		return endpoints[i].URL < endpoints[j].URL
	})
	return endpoints
}

func (s *pipelineState) markHostCollision(rawURL, host string) bool {
	key := utils.NormalizeURL(rawURL) + "|host=" + strings.ToLower(strings.TrimSpace(host))

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.hostCollisionSeen[key]; ok {
		return false
	}
	s.hostCollisionSeen[key] = struct{}{}
	return true
}
