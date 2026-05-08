package scan

import "context"

const (
	capGogoPortscan   = "gogo_portscan"
	capSprayCheck     = "spray_check"
	capSprayFinger    = "spray_finger"
	capCoreWeb        = "core_web"
	capSprayCommon    = "spray_common"
	capSprayBackup    = "spray_backup"
	capSprayActive    = "spray_active"
	capSprayCrawl     = "spray_crawl"
	capSprayBrute     = "spray_brute"
	capZombieWeakpass = "zombie_weakpass"
	capNeutronPOC     = "neutron_poc"
	capAgentVerify    = "agent_verify"
)

type emitFunc func(event)

type capability struct {
	Name         string
	Accepts      map[targetKind]struct{}
	AcceptEvents func(event) bool
	Worker       int
	RunKey       func(target) string
	RunEventKey  func(event) string
	Run          func(context.Context, target, emitFunc)
	RunEvent     func(context.Context, event, emitFunc)
}

func (c capability) accepts(target target) bool {
	if target == nil {
		return false
	}
	_, ok := c.Accepts[target.Kind()]
	return ok
}

func (c capability) acceptsEvent(event event) bool {
	if c.AcceptEvents == nil {
		return false
	}
	return c.AcceptEvents(event)
}

func (c capability) keyFor(target target) string {
	if target == nil {
		return ""
	}
	if c.RunKey != nil {
		return c.RunKey(target)
	}
	return c.Name + "|" + string(target.Kind()) + "|" + target.Key()
}

func (c capability) eventKeyFor(event event) string {
	if c.RunEventKey != nil {
		return c.RunEventKey(event)
	}
	return c.Name + "|" + event.key()
}

func targetInputs(kinds ...targetKind) map[targetKind]struct{} {
	out := make(map[targetKind]struct{}, len(kinds))
	for _, kind := range kinds {
		out[kind] = struct{}{}
	}
	return out
}
