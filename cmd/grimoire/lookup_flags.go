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
	cmd.Flags().DurationVarP(&timeout, "timeout", "", 15*time.Minute, "TODO")
	cmd.Flags().DurationVarP(&lookupInterval, "interval", "", 5*time.Second, "TODO")
	cmd.Flags().DurationVarP(&extendSearchWindow, "extend-search-window", "", 0, "TODO")
	cmd.Flags().IntVarP(&maxEvents, "max-events", "", 0, "TODO")
	cmd.Flags().BoolVarP(&writeEventsOnly, "only-write-events", "", false, "TODO")

	cmd.Flags().StringSliceVarP(&includeEvents, "include-events", "", []string{}, "TODO")
	cmd.Flags().StringSliceVarP(&excludeEvents, "exclude-events", "", []string{}, "TODO")
}