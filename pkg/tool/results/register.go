package results

import "github.com/chainreactors/aiscan/pkg/tool"

func NewTools() []tool.Tool {
	return []tool.Tool{
		&ParseResultsTool{},
		&FilterResultsTool{},
	}
}
