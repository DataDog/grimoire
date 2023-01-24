package logs

import "github.com/datadog/grimoire/pkg/grimoire/common"

type Searcher interface {
	FindLogs(uuid grimoire.DetonationID) ([]map[string]interface{}, error)
}
