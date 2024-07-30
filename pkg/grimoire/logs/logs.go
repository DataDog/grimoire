package logs

import (
	"github.com/datadog/grimoire/pkg/grimoire/detonators"
)

type Searcher interface {
	FindLogs(info *detonators.DetonationInfo) ([]map[string]interface{}, error)
}
