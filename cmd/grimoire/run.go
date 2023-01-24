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

// TODO: rename 'run'

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
	detonator := detonators.NewStratusRedTeamDetonator(m.stratusRedTeamAttackTechnique)
	awsConfig, _ := config.LoadDefaultConfig(context.Background())
	cloudtrailLogs := &logs.CloudTrailDataStore{
		CloudtrailClient: cloudtrail.NewFromConfig(awsConfig),
		DataStoreId:      "4cee9f76-991a-46fc-9c49-7ab50d19d83d", // TODO
		Options: &logs.CloudTrailEventLookupOptions{
			//WaitAtLeast:         30 * time.Second,
			WaitAtMost:                  5 * time.Minute,
			SearchInterval:              1 * time.Second,
			DebounceTimeAfterFirstEvent: 10 * time.Second,
		},
	}

	log.Infof("Detonating %s", detonator)
	detonationID, err := detonator.Detonate()
	if err != nil {
		return err
	}
	defer detonator.CleanUp() // Note: cleanup needs to be done after we're done searching for logs

	events, err := cloudtrailLogs.FindLogs(detonationID)
	if err != nil {
		return err
	}

	for _, evt := range events {
		log.Infof("%s: %s", evt["eventTime"], evt["eventName"])
	}

	if err := m.writeToFile(events); err != nil {
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

	if err := os.WriteFile(m.outputFile, outputBytes, 0600); err != nil {
		return err
	}
	return nil
}
