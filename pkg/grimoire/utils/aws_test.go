package utils

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGetCloudTrailEventFullName(t *testing.T) {
	event := map[string]interface{}{
		"eventName":   "SendCommand",
		"eventSource": "ssm.amazonaws.com",
	}
	result := GetCloudTrailEventFullName(&event)
	assert.Equal(t, "ssm:SendCommand", result)
}
