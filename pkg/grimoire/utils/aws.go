package utils

import (
	"fmt"
	"strings"
)

// GetCloudTrailEventFullName returns the full name of a CloudTrail event, e.g. sts:GetCallerIdentity
func GetCloudTrailEventFullName(event *map[string]interface{}) string {
	eventName := (*event)["eventName"].(string)
	eventSourceShort := strings.TrimSuffix((*event)["eventSource"].(string), ".amazonaws.com")
	return fmt.Sprintf("%s:%s", eventSourceShort, eventName) // e.g. "sts:GetCallerIdentity"
}
