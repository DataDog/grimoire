package utils

import (
	"strings"
)

type Redactor func(input string) string

func StaticRedactor(output string) Redactor {
	return func(input string) string {
		return output
	}
}

const (
	RedactedAccountId = "123456789012"
	RedactedIpAddress = "1.2.3.4"
)

func ArnRedactor(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) < 6 {
		return arn
	}
	parts[4] = RedactedAccountId
	return strings.Join(parts, ":")
}

var (
	AccountIdRedactor = StaticRedactor(RedactedAccountId)
	IpAddressRedactor = StaticRedactor(RedactedIpAddress)
)
var FieldsToRedact = map[string]Redactor{
	"recipientAccountId": AccountIdRedactor,
	"sourceIPAddress":    IpAddressRedactor,
	"userIdentity.accessKeyId": func(accessKeyId string) string {
		if strings.HasPrefix(accessKeyId, "ASIA") {
			return "ASIAEXAMPLE"
		} else if strings.HasPrefix(accessKeyId, "AKIA") {
			return "AKIAEXAMPLE"
		} else {
			return "<access-key-id>"
		}
	},
	"userIdentity.accountId":                              AccountIdRedactor,
	"userIdentity.sessionContext.sessionIssuer.accountId": AccountIdRedactor,
	"userIdentity.sessionContext.sessionIssuer.arn":       ArnRedactor,
}

func RedactCloudTrailEvents(events *[]map[string]interface{}) {
	for i := range *events {
		(*events)[i]["eventjson"] = "REDACTED"
	}
}

func mapDeepGet(m *map[string]interface{}, key string) (interface{}, bool) {
	keys := strings.Split(key, ".")
	current := *m
	for i, k := range keys {
		if i == len(keys)-1 {
			v, ok := current[k]
			return v, ok
		}
		if current[k] == nil {
			return nil, false
		}
		current = current[k].(map[string]interface{})
	}
	return nil, false
}
