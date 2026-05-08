package scan

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/chainreactors/parsers"
	sdkzombie "github.com/chainreactors/sdk/zombie"
	"github.com/chainreactors/utils"
	zombiepkg "github.com/chainreactors/zombie/pkg"
)

func readInputs(inputs []string, listFile string) ([]string, error) {
	var out []string
	for _, input := range inputs {
		input = strings.TrimSpace(input)
		if input != "" {
			out = append(out, input)
		}
	}
	if listFile == "" {
		return out, nil
	}

	f, err := os.Open(listFile)
	if err != nil {
		return nil, fmt.Errorf("open input list: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, scanner.Err()
}

func parseZombieTarget(raw, serviceOverride string) (sdkzombie.Target, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return sdkzombie.Target{}, false
	}

	var target sdkzombie.Target
	if strings.Contains(raw, "://") {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Hostname() == "" {
			return sdkzombie.Target{}, false
		}
		target.IP = parsed.Hostname()
		target.Port = parsed.Port()
		target.Scheme = parsed.Scheme
		target.Service = parsed.Scheme
		if service, ok := parsers.ZombieServiceFromName(parsed.Scheme); ok {
			target.Service = service
		}
		if parsed.User != nil {
			target.Username = parsed.User.Username()
			target.Password, _ = parsed.User.Password()
		}
	} else if host, port, ok := utils.SplitHostPort(raw); ok {
		target.IP = host
		target.Port = port
		target.Service = zombiepkg.GetDefault(port)
		target.Scheme = target.Service
	} else {
		target.IP = raw
	}

	if serviceOverride != "" {
		service := strings.ToLower(serviceOverride)
		if mapped, ok := parsers.ZombieServiceFromName(service); ok {
			service = mapped
		}
		target.Service = service
		target.Scheme = target.Service
	}
	if target.Port == "" && target.Service != "" {
		target.Port = zombiepkg.Services.DefaultPort(target.Service)
	}
	if target.Service == "" || target.Service == "unknown" {
		return sdkzombie.Target{}, false
	}
	return target, true
}
