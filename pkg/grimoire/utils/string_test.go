package utils

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestStringMatches(t *testing.T) {
	assert.True(t, StringMatches("sts:GetCallerIdentity", "sts:GetCallerIdentity"))
	assert.True(t, StringMatches("sts:GetCallerIdentity", "sts:getcalleridentity"))
	assert.True(t, StringMatches("sts:GetCallerIdentity", "sts:*"))
	assert.True(t, StringMatches("sts:GetCallerIdentity", "*Identity"))
	assert.True(t, StringMatches("sts:GetCallerIdentity", "sts:Get*Identity"))

	assert.True(t, StringMatches("sts:GetCallerIdentity", "*"))
	assert.True(t, StringMatches("sts:GetCallerIdentity", "*:*"))

	assert.False(t, StringMatches("sts:GetCallerIdentity", "iam:*"))
	assert.False(t, StringMatches("sts:GetCallerIdentity", "*User"))
}
