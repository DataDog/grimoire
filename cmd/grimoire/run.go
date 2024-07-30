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
	"os/signal"
	"syscall"
	"time"
)

type RunCommand struct {
	StratusRedTeamDetonator *detonators.StratusRedTeamDetonator
	OutputFile              string
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
			if stratusRedTeamAttackTechnique == "" {
				return errors.New("missing Stratus Red Team attack technique")
			}
			detonator, err := detonators.NewStratusRedTeamDetonator(stratusRedTeamAttackTechnique)
			if err != nil {
				return err
			}
			command := RunCommand{
				StratusRedTeamDetonator: detonator,
				OutputFile:              outputFile,
			}
			return command.Do()
		},
	}

	runCmd.Flags().StringVarP(&stratusRedTeamAttackTechnique, "stratus-red-team-attack-technique", "", "", "TODO")
	runCmd.Flags().StringVarP(&outputFile, "output-file", "o", "", "TODO")

	return runCmd
}

func (m *RunCommand) Do() error {
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

	log.Infof("Detonating %s", m.StratusRedTeamDetonator.AttackTechnique)
	detonation, err := m.StratusRedTeamDetonator.Detonate()
	if err != nil {
		return err
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Info("Exiting Grimoire cleanly, don't press Ctrl+C again")
		time.Sleep(1 * time.Minute)
		if err := m.Exit(); err != nil {
			log.Errorf("unable to exit Grimoire cleanly: %v", err)
			os.Exit(1)
		}
		os.Exit(0)
	}()

	defer m.Exit()

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

		//TODO stream events to file
	}

	if err := m.writeToFile(allEvents); err != nil {
		return fmt.Errorf("unable to write events to file: %w", err)
	}
	return nil
}

func (m *RunCommand) writeToFile(events []map[string]interface{}) error {
	if m.OutputFile == "" {
		return nil // nothing to do
	}
	outputBytes, err := json.MarshalIndent(events, "", "   ")
	if err != nil {
		return err
	}

	if m.OutputFile == "-" {
		fmt.Println(string(outputBytes))
	} else if err := os.WriteFile(m.OutputFile, outputBytes, 0600); err != nil {
		return err
	}
	return nil
}

// Exits Grimoire cleanly
// It's expected that running Ctrl+C is a pretty common use-case with Grimoire
func (m *RunCommand) Exit() error {
	if err := m.StratusRedTeamDetonator.CleanUp(); err != nil {
		log.Warnf("unable to cleanup Stratus Red Team attack technique %s: %v", m.StratusRedTeamDetonator.AttackTechnique, err)
		log.Warnf("You might want to manually clean it up by running 'stratus cleanup %s'", m.StratusRedTeamDetonator.AttackTechnique)
	}
	return nil
}
