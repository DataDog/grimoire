package main

import (
	"github.com/spf13/cobra"
	"time"
)

var timeout time.Duration
var lookupInterval time.Duration
var maxEvents int
var includeEvents []string
var excludeEvents []string
var writeEventsOnly bool
var extendSearchWindow time.Duration

// CLI flags shared between 'shell' and 'stratus-red-team' commands
func initLookupFlags(cmd *cobra.Command) {
	cmd.Flags().DurationVarP(&timeout, "timeout", "", 15*time.Minute, "Maximum time to wait for events to appear in CloudTrail logs")
	cmd.Flags().DurationVarP(&lookupInterval, "interval", "", 5*time.Second, "Interval to check for new events. You might need to increase this if you're hitting AWS API rate limits")
	cmd.Flags().DurationVarP(&extendSearchWindow, "extend-search-window", "", 0, "Extend the end of the search window by this amount of time")
	cmd.Flags().IntVarP(&maxEvents, "max-events", "", 0, "Maximum number of events to retrieve before exiting")
	cmd.Flags().BoolVarP(&writeEventsOnly, "only-write-events", "", false, "Only consider write events and ignore read-only ones")

	cmd.Flags().StringSliceVarP(&includeEvents, "include-events", "", []string{}, "Only consider specific CloudTrail events. Comma-separated and using the format 'service:Operation' (e.g. 's3:PutObject')")
	cmd.Flags().StringSliceVarP(&excludeEvents, "exclude-events", "", []string{}, "Exclude specific CloudTrail events. Comma-separated and using the format 'service:Operation' (e.g. 's3:PutObject')")
}
