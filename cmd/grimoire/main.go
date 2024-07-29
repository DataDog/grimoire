package main

import (
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"os"
)

var rootCmd = &cobra.Command{
	Use: "grimoire",
}

var enableVerboseLogging = false

func init() {
	rootCmd.AddCommand(NewRunCommand())
	rootCmd.AddCommand(NewShellCommand())
	rootCmd.PersistentFlags().BoolVarP(&enableVerboseLogging, "debug", "v", true, "Enable debug logging")

	// Disable creation of the "completion" command
	rootCmd.CompletionOptions.DisableDefaultCmd = true

	if enableVerboseLogging {
		log.SetLevel(log.DebugLevel)
	}
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
