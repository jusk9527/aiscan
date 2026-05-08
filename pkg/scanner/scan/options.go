package scan

import (
	"github.com/chainreactors/aiscan/pkg/provider"
	"github.com/chainreactors/aiscan/pkg/telemetry"
)

type Option func(*Command)

type VerificationConfig struct {
	Provider     provider.Provider
	Model        string
	Enable       bool
	MinPriority  string
	SystemPrompt string
	MaxTurns     int
	Timeout      int
}

func WithVerificationConfig(config VerificationConfig) Option {
	return func(c *Command) {
		c.verification = config
	}
}

func WithLogger(logger telemetry.Logger) Option {
	return func(c *Command) {
		if logger != nil {
			c.logger = logger
		}
	}
}

func (c *Command) Configure(opts ...Option) {
	for _, opt := range opts {
		if opt != nil {
			opt(c)
		}
	}
}
