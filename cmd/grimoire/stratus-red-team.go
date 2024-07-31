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
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type RunCommand struct {
	StratusRedTeamDetonator *detonators.StratusRedTeamDetonator
	OutputFile              string
	cleanupWg               sync.WaitGroup
	cleanupMutex            sync.Mutex
	cleanupRunning          atomic.Bool
	cleanupSucceeded        atomic.Bool
	wasCtrlCPressed         atomic.Bool
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

	detonation, err := m.StratusRedTeamDetonator.Detonate()
	if err != nil {
		return err
	}

	// The attack has been detonated successfully
	// We can already start cleaning up, in parallel of looking for the logs
	// A mutex makes sure the main program doesn't exit while we're cleaning up
	go func() {
		log.Info("Cleaning up Stratus Red Team detonation in the background")
		if err := m.CleanupDetonation(); err != nil {
			// Note: Stratus Red Team Cleanup function calls the Terraform Go Wrapper, which unfortunately
			// catches Ctrl+C signals. This means that if the user presses Ctrl+C at "the wrong time", the cleanup
			// will fail because the Terraform Wrapper will panic and exit

			// Consequently, we have some logic baked in later in this function to retry the cleanup at the end if
			// the asynchronous cleanup failed for this specific reason
			log.Debug("Asynchronous cleanup failed, will retry at the end of the program")
			if strings.Contains(err.Error(), "interrupts received") {
				log.Debug("The failure was caused by the Go terraform wrapper catching signals and panicking")
			}
			return
		}
	}()

	log.Info("Stratus Red Team attack technique successfully detonated")
	var allEvents []map[string]interface{}

	log.Info("Searching for CloudTrail events...")
	results, err := cloudtrailLogs.FindLogs(ctx, detonation)
	if err != nil {
		return err
	}

	errorChan := make(chan error)

	go func() {
		for {
			select {

			// Case 1: New CloudTrail result found
			case evt, ok := <-results:
				if !ok {
					log.Debugf("channel closed")
					errorChan <- nil
					return // Channel closed, exit the processing loop
				}

				// If it's an error, we exit the processing loop and ultimately exit
				if evt.Error != nil {
					log.Printf("Error processing event: %v", evt.Error)
					cancel()
					errorChan <- evt.Error
					return
				}

				// Otherwise, we call handleNewEvent which will stream the newly-found event appropriately
				allEvents = append(allEvents, *evt.CloudTrailEvent)
				if err := m.handleNewEvent(evt.CloudTrailEvent); err != nil {
					// If processing of this event fails, we abort execution
					log.Errorf(err.Error())
					cancel()
					errorChan <- err
					return
				}

				// We don't return here, this is the happy path where the processing loop continues

			// Case 2: The user pressed Ctrl+C, we clean up and exit the program
			/*case <-sigChan:
			m.wasCtrlCPressed.Store(true)
			log.Info("Exiting Grimoire cleanly, don't press Ctrl+C again")
			cancel()
			// NOTE: We don't clean up here again, because the cleanup starts asynchronously after the attack is detonated
			// and the program waits for it to be completed before exiting in any case.
			// In the future, if we have generic, non-Stratus Red Team related clean-up tasks, we should add them here.
			errorChan <- nil
			return*/

			case <-ctx.Done():
				log.Debug("Stopping event processing due to context cancellation")
				errorChan <- nil
				return
			}
		}
	}()

	// The code below is to handle the case where the user presses Ctrl+C several times
	// In which case it will just print an error message
	// In the future, we could force the exit to be faster
	go func() {
		for range sigChan {
			if m.wasCtrlCPressed.CompareAndSwap(false, true) {
				//signal.Ignore(os.Interrupt, syscall.SIGTERM)

				log.Info("Exiting Grimoire cleanly, don't press Ctrl+C again")
				cancel()
				// NOTE: We don't clean up here again, because the cleanup starts asynchronously after the attack is detonated
				// and the program waits for it to be completed before exiting in any case.
				// In the future, if we have generic, non-Stratus Red Team related clean-up tasks, we should add them here.

				// NOTE: We don't need to send a nil error to errorChan, because cancelling the context will reach the earlier select statement
				// "case <-ctx.Done()" that will take care of it
			} else {
				log.Info("You already pressed Ctrl+C, please wait for Grimoire to exit")
			}
		}
	}()

	// Wait for event processing to be done, either due to a Ctrl+C either due to normal exit conditions
	log.Debugf("Waiting for event processing to be done")
	err = <-errorChan
	log.Debugf("Event processing done, received a result from the error channel")
	if err != nil {
		return err
	}

	if err := m.writeToFile(allEvents); err != nil {
		return fmt.Errorf("unable to write events to file: %w", err)
	}

	// Make sure we wait until cleanup is finished before exiting
	if m.cleanupRunning.Load() == true {
		log.Info("Waiting for Stratus Red Team attack technique clean-up to complete...")
	}
	m.cleanupWg.Wait()
	if m.cleanupSucceeded.Load() == false {
		log.Debug("First try of the detonation clean-up did not work, trying again now")
		if err := m.CleanupDetonation(); err != nil {
			log.Warnf("unable to cleanup Stratus Red Team attack technique %s: %v", m.StratusRedTeamDetonator.AttackTechnique, err)
			log.Warnf("You might want to manually clean it up by running 'stratus cleanup %s'", m.StratusRedTeamDetonator.AttackTechnique)
		}
	}
	log.Debug("Async cleanup finished, exiting")

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

func (m *RunCommand) CleanupDetonation() error {
	m.cleanupMutex.Lock()
	defer m.cleanupMutex.Unlock()
	m.cleanupWg.Add(1)
	defer m.cleanupWg.Done()
	m.cleanupRunning.Store(true)
	defer m.cleanupRunning.Store(false)

	err := m.StratusRedTeamDetonator.CleanUp()
	if err == nil {
		m.cleanupSucceeded.Store(true)
	}

	log.Debug("Clean-up routing completed")
	return err
}
