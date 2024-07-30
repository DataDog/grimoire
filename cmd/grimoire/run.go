package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/datadog/grimoire/pkg/grimoire/detonators"
	"github.com/datadog/grimoire/pkg/grimoire/logs"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"os"
	"time"
)

type RunCommand struct {
	stratusRedTeamAttackTechnique string
	outputFile                    string
}

func NewRunCommand() *cobra.Command {
	var stratusRedTeamAttackTechnique string
	var outputFile string

	runCmd := &cobra.Command{
		Use:          "run",
		Short:        "TODO",
		SilenceUsage: true,
		Example:      "TODO",
		RunE: func(cmd *cobra.Command, args []string) error {
			command := RunCommand{
				stratusRedTeamAttackTechnique: stratusRedTeamAttackTechnique,
				outputFile:                    outputFile,
			}
			return command.Do()
		},
	}

	runCmd.Flags().StringVarP(&stratusRedTeamAttackTechnique, "stratus-red-team-attack-technique", "", "", "TODO")
	runCmd.Flags().StringVarP(&outputFile, "output-file", "o", "", "TODO")

	return runCmd
}

func (m *RunCommand) Validate() error {
	if m.stratusRedTeamAttackTechnique == "" {
		return errors.New("missing Stratus Red Team attack technique")
	}
	return nil
}

func (m *RunCommand) Do() error {
	if err := m.Validate(); err != nil {
		return err
	}
	detonator, err := detonators.NewStratusRedTeamDetonator(m.stratusRedTeamAttackTechnique)
	if err != nil {
		return err
	}
	awsConfig, _ := config.LoadDefaultConfig(context.Background())
	cloudtrailLogs := &logs.CloudTrailEventsFinder{
		CloudtrailClient: cloudtrail.NewFromConfig(awsConfig),
		Options: &logs.CloudTrailEventLookupOptions{
			//WaitAtLeast:         30 * time.Second,
			WaitAtMost:                  10 * time.Minute,
			SearchInterval:              5 * time.Second,
			DebounceTimeAfterFirstEvent: 120 * time.Second,
		},
	}

	log.Infof("Detonating %s", detonator)
	detonation, err := detonator.Detonate()
	if err != nil {
		return err
	}

	//TODO critical: catch ctrl+c and cleanup if appropriate
	defer detonator.CleanUp() // Note: cleanup needs to be done after we're done searching for logs

	log.Info("Stratus Red Team attack technique successfully detonated")
	var allEvents []map[string]interface{}

	log.Info("Searching for CloudTrail logs...")
	results, err := cloudtrailLogs.FindLogs(detonation)
	if err != nil {
		return err
	}

	for evt := range results {
		if evt.Error != nil {
			//TODO: should we write the events we have so far to the output file before exiting?
			return evt.Error
		}
		log.Infof("%s: %s", (*evt.CloudTrailEvent)["eventTime"], (*evt.CloudTrailEvent)["eventName"])
		allEvents = append(allEvents, *evt.CloudTrailEvent)
	}

	if err := m.writeToFile(allEvents); err != nil {
		return fmt.Errorf("unable to write events to file: %w", err)
	}
	return nil
}

func (m *RunCommand) writeToFile(events []map[string]interface{}) error {
	if m.outputFile == "" {
		return nil // nothing to do
	}
	outputBytes, err := json.MarshalIndent(events, "", "   ")
	if err != nil {
		return err
	}

	if m.outputFile == "-" {
		fmt.Println(string(outputBytes))
	} else if err := os.WriteFile(m.outputFile, outputBytes, 0600); err != nil {
		return err
	}
	return nil
}
