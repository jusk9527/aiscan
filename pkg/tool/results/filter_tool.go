package results

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/chainreactors/aiscan/pkg/provider"
	"github.com/chainreactors/parsers"
)

type FilterResultsTool struct{}

func (t *FilterResultsTool) Name() string        { return "filter_results" }
func (t *FilterResultsTool) Description() string {
	return "Filter JSON-lines scanner output by field criteria. Run a scanner with -j flag first to get JSON, then pass the output here with filter conditions."
}

func (t *FilterResultsTool) Definition() provider.ToolDefinition {
	return provider.ToolDefinition{
		Type: "function",
		Function: provider.FunctionDefinition{
			Name:        "filter_results",
			Description: t.Description(),
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"scanner": map[string]any{
						"type":        "string",
						"enum":        []string{"gogo", "spray", "zombie"},
						"description": "Which scanner produced the output",
					},
					"data": map[string]any{
						"type":        "string",
						"description": "JSON-lines output from the scanner",
					},
					"filter": map[string]any{
						"type":        "object",
						"description": "Key-value pairs for filtering. Keys are field names (ip, port, protocol, status, url, host, title, framework, service, etc.), values are match strings.",
						"additionalProperties": map[string]any{
							"type": "string",
						},
					},
					"operator": map[string]any{
						"type":        "string",
						"enum":        []string{"contains", "equals", "not_contains", "not_equals"},
						"description": "Match operator for all filter values. Default: contains",
					},
					"limit": map[string]any{
						"type":        "integer",
						"description": "Maximum results to return. Default: 50",
					},
				},
				"required": []string{"scanner", "data", "filter"},
			},
		},
	}
}

func (t *FilterResultsTool) Execute(_ context.Context, arguments string) (string, error) {
	var args struct {
		Scanner  string            `json:"scanner"`
		Data     string            `json:"data"`
		Filter   map[string]string `json:"filter"`
		Operator string            `json:"operator"`
		Limit    int               `json:"limit"`
	}
	if err := json.Unmarshal([]byte(arguments), &args); err != nil {
		return "", fmt.Errorf("invalid arguments: %w", err)
	}
	if args.Operator == "" {
		args.Operator = "contains"
	}
	if args.Limit <= 0 {
		args.Limit = 50
	}

	lines := splitJSONLines(args.Data)
	if len(lines) == 0 {
		return "No results to filter.", nil
	}

	switch args.Scanner {
	case "gogo":
		return filterGogoResults(lines, args.Filter, args.Operator, args.Limit)
	case "spray":
		return filterSprayResults(lines, args.Filter, args.Operator, args.Limit)
	case "zombie":
		return filterZombieResults(lines, args.Filter, args.Operator, args.Limit)
	default:
		return "", fmt.Errorf("unsupported scanner: %s", args.Scanner)
	}
}

func filterGogoResults(lines []string, filter map[string]string, operator string, limit int) (string, error) {
	gogoOp := toGogoOperator(operator)
	var sb strings.Builder
	matched := 0
	total := 0

	for _, line := range lines {
		var r parsers.GOGOResult
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			continue
		}
		total++
		if !matchGogoResult(&r, filter, gogoOp) {
			continue
		}
		matched++
		sb.WriteString(r.FullOutput())
		sb.WriteByte('\n')
		if matched >= limit {
			break
		}
	}

	header := fmt.Sprintf("Matched %d/%d results (showing %d):\n\n", matched, total, min(matched, limit))
	return truncateOutput(header + sb.String()), nil
}

func filterSprayResults(lines []string, filter map[string]string, operator string, limit int) (string, error) {
	var sb strings.Builder
	matched := 0
	total := 0

	for _, line := range lines {
		var r parsers.SprayResult
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			continue
		}
		if r.ErrString != "" {
			continue
		}
		total++
		if !matchSprayResult(&r, filter, operator) {
			continue
		}
		matched++
		sb.WriteString(r.String())
		sb.WriteByte('\n')
		if matched >= limit {
			break
		}
	}

	header := fmt.Sprintf("Matched %d/%d results (showing %d):\n\n", matched, total, min(matched, limit))
	return truncateOutput(header + sb.String()), nil
}

func filterZombieResults(lines []string, filter map[string]string, operator string, limit int) (string, error) {
	var sb strings.Builder
	matched := 0
	total := 0

	for _, line := range lines {
		var r parsers.ZombieResult
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			continue
		}
		total++
		if !matchZombieResult(&r, filter, operator) {
			continue
		}
		matched++
		sb.WriteString(r.Full())
		sb.WriteByte('\n')
		if matched >= limit {
			break
		}
	}

	header := fmt.Sprintf("Matched %d/%d results (showing %d):\n\n", matched, total, min(matched, limit))
	return truncateOutput(header + sb.String()), nil
}

func matchGogoResult(r *parsers.GOGOResult, filter map[string]string, gogoOp string) bool {
	for k, v := range filter {
		if !r.Filter(k, v, gogoOp) {
			return false
		}
	}
	return true
}

func matchSprayResult(r *parsers.SprayResult, filter map[string]string, operator string) bool {
	for k, v := range filter {
		fieldVal := r.Get(k)
		if !matchValue(fieldVal, v, operator) {
			return false
		}
	}
	return true
}

func matchZombieResult(r *parsers.ZombieResult, filter map[string]string, operator string) bool {
	for k, v := range filter {
		fieldVal := zombieFieldValue(r, k)
		if !matchValue(fieldVal, v, operator) {
			return false
		}
	}
	return true
}

func zombieFieldValue(r *parsers.ZombieResult, key string) string {
	switch strings.ToLower(key) {
	case "ip":
		return r.IP
	case "port":
		return r.Port
	case "service":
		return r.Service
	case "username", "user":
		return r.Username
	case "password", "pass":
		return r.Password
	case "scheme":
		return r.Scheme
	case "mod":
		return r.Mod.String()
	case "address", "addr":
		return r.Address()
	default:
		return ""
	}
}

func matchValue(fieldVal, matchVal, operator string) bool {
	fieldLower := strings.ToLower(fieldVal)
	matchLower := strings.ToLower(matchVal)
	switch operator {
	case "contains":
		return strings.Contains(fieldLower, matchLower)
	case "equals":
		return fieldLower == matchLower
	case "not_contains":
		return !strings.Contains(fieldLower, matchLower)
	case "not_equals":
		return fieldLower != matchLower
	default:
		return strings.Contains(fieldLower, matchLower)
	}
}

func toGogoOperator(operator string) string {
	switch operator {
	case "contains":
		return "::"
	case "equals":
		return "=="
	case "not_contains":
		return "!:"
	case "not_equals":
		return "!="
	default:
		return "::"
	}
}
