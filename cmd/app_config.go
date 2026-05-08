package cmd

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/chainreactors/aiscan/pkg/app"
	"github.com/chainreactors/aiscan/pkg/provider"
	"github.com/chainreactors/aiscan/pkg/telemetry"
)

type runtimeFeatures struct {
	ProviderEnabled     bool
	ProviderOptional    bool
	ToolsEnabled        bool
	VerificationEnabled bool
	VerifyMinPriority   string
}

func appConfig(option *Option, features runtimeFeatures) app.Config {
	return app.Config{
		Provider: app.ProviderConfig{
			Enabled:  features.ProviderEnabled,
			Config:   providerConfig(option),
			Optional: features.ProviderOptional,
		},
		Scanner: app.ScannerConfig{
			CyberhubURL:         resolvedCyberhubURL(option),
			CyberhubKey:         resolvedCyberhubKey(option),
			CyberhubMode:        resolvedCyberhubMode(option),
			VerificationEnabled: features.VerificationEnabled,
			VerifyMinPriority:   resolvedVerifyMinPriority(features.VerifyMinPriority),
			VerifyMaxTurns:      resolvedDefaultInt(DefaultVerifyTurns, 3),
			VerifyTimeout:       resolvedDefaultInt(DefaultVerifyTimeout, 120),
		},
		Tools: app.ToolConfig{
			Enabled:     features.ToolsEnabled,
			BashTimeout: 300,
		},
		Logger: telemetry.NewLogger(telemetry.LogConfig{
			Debug:  option.Debug,
			Quiet:  option.Quiet,
			Output: os.Stderr,
		}),
	}
}

func providerConfig(option *Option) provider.ProviderConfig {
	cfg := defaultProviderConfig()
	if option.Provider != "" {
		cfg.Provider = option.Provider
	}
	if baseURL := resolvedBaseURL(option); baseURL != "" {
		cfg.BaseURL = baseURL
	}
	if option.APIKey != "" {
		cfg.APIKey = option.APIKey
	}
	if option.Model != "" {
		cfg.Model = option.Model
	}
	if option.Proxy != "" {
		cfg.Proxy = option.Proxy
	}
	cfg.Timeout = 120
	return cfg
}

func applyResolvedProviderOptions(option *Option, cfg provider.ProviderConfig) {
	option.Provider = cfg.Provider
	option.BaseURL = cfg.BaseURL
	option.APIKey = cfg.APIKey
	option.Model = cfg.Model
	option.Proxy = cfg.Proxy
}

func resolvedBaseURL(option *Option) string {
	return option.BaseURL
}

func resolvedModel(option *Option) string {
	if option.Model != "" {
		return option.Model
	}
	if DefaultModel != "" {
		return DefaultModel
	}
	return "gpt-4o"
}

func resolvedCyberhubURL(option *Option) string {
	if option.CyberhubURL != "" {
		return option.CyberhubURL
	}
	return DefaultCyberhubURL
}

func resolvedCyberhubKey(option *Option) string {
	if option.CyberhubKey != "" {
		return option.CyberhubKey
	}
	return DefaultCyberhubKey
}

func resolvedCyberhubMode(option *Option) string {
	if option.CyberhubMode != "" {
		return option.CyberhubMode
	}
	if DefaultCyberhubMode != "" {
		return DefaultCyberhubMode
	}
	return "merge"
}

func resolvedDefaultVerify() string {
	value := strings.ToLower(strings.TrimSpace(DefaultVerify))
	if value == "" {
		return "auto"
	}
	return value
}

func resolvedVerifyMinPriority(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "high"
	}
	return value
}

func resolvedDefaultInt(value string, fallback int) int {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func resolvedACPURL(option *Option) string {
	if option.ACPURL != "" {
		return option.ACPURL
	}
	return DefaultACPURL
}

func resolvedACPNodeID(option *Option) string {
	if option.ACPNodeID != "" {
		return option.ACPNodeID
	}
	return DefaultACPNodeID
}

func resolvedACPNodeName(option *Option) string {
	if option.ACPNodeName != "" {
		return option.ACPNodeName
	}
	return DefaultACPNodeName
}

func resolvedSpace(option *Option) string {
	if option.Space != "" && option.Space != "default" {
		return option.Space
	}
	if DefaultSpace != "" {
		return DefaultSpace
	}
	if option.Space != "" {
		return option.Space
	}
	return "default"
}

func defaultACPNodeName(option *Option) string {
	if nodeName := resolvedACPNodeName(option); nodeName != "" {
		return nodeName
	}
	var b [4]byte
	if _, err := rand.Read(b[:]); err == nil {
		return "aiscan-" + hex.EncodeToString(b[:])
	}
	return "aiscan-" + strconv.FormatInt(time.Now().UnixNano(), 36)
}
