package main

import (
	"fmt"
	"github.com/common-nighthawk/go-figure"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"os"
)

var enableVerboseLogging = false
var disableBanner = false

var rootCmd = &cobra.Command{
	Use: "grimoire",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if enableVerboseLogging {
			log.SetLevel(log.DebugLevel)
		}
		if !disableBanner {
			figure.NewColorFigure("Grimoire", "", "purple", true).Print()
			fmt.Println()
		}
	},
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&enableVerboseLogging, "debug", "v", false, "Enable debug logging")
	rootCmd.PersistentFlags().BoolVarP(&enableVerboseLogging, "disable-banner", "", false, "Disable Grimoire ASCII-art banner")

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
