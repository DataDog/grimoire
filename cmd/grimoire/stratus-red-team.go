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
	utils "github.com/datadog/grimoire/pkg/grimoire/utils"
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
		Use:          "stratus-red-team",
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

	runCmd.Flags().StringVarP(&stratusRedTeamAttackTechnique, "attack-technique", "", "", "TODO")
	runCmd.Flags().StringVarP(&outputFile, "output", "o", "", "TODO")

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
			UserAgentMatchType:          logs.UserAgentMatchTypeExact,
		},
	}

	if err := utils.CreateOrTruncateJSONFile(m.OutputFile); err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Info("Exiting Grimoire cleanly, don't press Ctrl+C again")
		cancel()
		time.Sleep(1 * time.Minute)
		if err := m.Exit(); err != nil {
			log.Errorf("unable to exit Grimoire cleanly: %v", err)
			os.Exit(1)
		}
		os.Exit(0)
	}()

	detonation, err := m.StratusRedTeamDetonator.Detonate()
	if err != nil {
		return err
	}

	defer m.Exit()
	//TODO: should we cleanup the attack technique as soon as it's been detonated, in parallel to searching for logs?
	// if yes, we should make sure the program doesn't exit before cleanup is complete

	log.Info("Stratus Red Team attack technique successfully detonated")
	var allEvents []map[string]interface{}

	log.Info("Searching for CloudTrail events...")
	results, err := cloudtrailLogs.FindLogs(ctx, detonation)
	if err != nil {
		return err
	}

	go func() {
		for {
			select {
			case evt, ok := <-results:
				if !ok {
					return // Channel closed, exit the goroutine
				}
				if evt.Error != nil {
					log.Printf("Error processing event: %v", evt.Error)
					cancel() //TODO: is this the right thing to do?
					return
				}

				allEvents = append(allEvents, *evt.CloudTrailEvent)
				if err := m.handleNewEvent(evt.CloudTrailEvent); err != nil {
					log.Errorf(err.Error())
					cancel() //TODO: is this the right thing to do?
					return
				}

			case <-ctx.Done():
				log.Debug("Stopping event processing due to context cancellation")
				return
			}
		}
	}()

	<-ctx.Done()

	if err := m.writeToFile(allEvents); err != nil {
		return fmt.Errorf("unable to write events to file: %w", err)
	}

	return nil
}

func (m *RunCommand) handleNewEvent(event *map[string]interface{}) error {
	log.Printf("Found new CloudTrail event generated on %s UTC: %s", (*event)["eventTime"], (*event)["eventName"])
	err := utils.AppendToJsonFileArray(m.OutputFile, *event)
	if err != nil {
		return fmt.Errorf("unable to write CloudTrail event to %s: %v", m.OutputFile, err)
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
