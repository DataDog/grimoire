package utils

import (
	"regexp"
	"strings"
)

// StringMatches returns true if the candidate string matches a pattern.
// Supports wildcards. Case-insensitive
func StringMatches(candidate string, pattern string) bool {
	var regex strings.Builder
	regex.WriteString("(?i)") // case-insensitive
	for i, literal := range strings.Split(pattern, "*") {

		// Replace * with .*
		if i > 0 {
			regex.WriteString(".*")
		}

		// Quote any regular expression meta characters in the
		// literal text.
		regex.WriteString(regexp.QuoteMeta(literal))
	}

	matches, _ := regexp.MatchString(regex.String(), candidate)
	return matches
}
