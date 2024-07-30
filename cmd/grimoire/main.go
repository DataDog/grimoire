package main

import (
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"os"
)

var enableVerboseLogging = false

var rootCmd = &cobra.Command{
	Use: "grimoire",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if enableVerboseLogging {
			log.SetLevel(log.DebugLevel)
		}
	},
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&enableVerboseLogging, "debug", "v", false, "Enable debug logging")

	rootCmd.AddCommand(NewRunCommand())
	rootCmd.AddCommand(NewShellCommand())
	// Disable creation of the "completion" command
	rootCmd.CompletionOptions.DisableDefaultCmd = true
}

func main() {

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
