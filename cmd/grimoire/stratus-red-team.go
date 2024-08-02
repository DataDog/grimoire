package main

import (
	"context"
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
)

type StratusRedTeamCommand struct {
	StratusRedTeamDetonator *detonators.StratusRedTeamDetonator
	OutputFile              string
	cleanupWg               sync.WaitGroup
	cleanupMutex            sync.Mutex
	cleanupRunning          atomic.Bool
	cleanupSucceeded        atomic.Bool
	wasCtrlCPressed         atomic.Bool
	ctx                     context.Context
	cancel                  func()
	sigChan                 chan os.Signal
}

func NewStratusRedTeamCommand() *cobra.Command {
	var stratusRedTeamAttackTechnique string
	var outputFile string

	stratusRedTeamCommand := &cobra.Command{
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
			command := StratusRedTeamCommand{
				StratusRedTeamDetonator: detonator,
				OutputFile:              outputFile,
			}
			return command.Do()
		},
	}

	stratusRedTeamCommand.Flags().StringVarP(&stratusRedTeamAttackTechnique, "attack-technique", "", "", "TODO")
	stratusRedTeamCommand.Flags().StringVarP(&outputFile, "output", "o", "", "TODO")
	initLookupFlags(stratusRedTeamCommand)

	return stratusRedTeamCommand
}

func (m *StratusRedTeamCommand) Do() error {
	awsConfig, _ := config.LoadDefaultConfig(context.Background())
	cloudtrailLogs := &logs.CloudTrailEventsFinder{
		CloudtrailClient: cloudtrail.NewFromConfig(awsConfig),
		Options: &logs.CloudTrailEventLookupOptions{
			Timeout:            timeout,
			LookupInterval:     lookupInterval,
			IncludeEvents:      includeEvents,
			ExcludeEvents:      excludeEvents,
			MaxEvents:          maxEvents,
			UserAgentMatchType: logs.UserAgentMatchTypeExact,
		},
	}

	if err := utils.CreateOrTruncateJSONFile(m.OutputFile); err != nil {
		return err
	}

	m.ctx, m.cancel = context.WithCancel(context.Background())
	defer m.cancel()

	m.handleCtrlC()

	detonation, detonationErr := m.detonateStratusRedTeam()

	// The attack has been detonated (whether successfully or not)
	// We can already start cleaning up, in parallel of looking for the logs
	// A mutex makes sure the main program doesn't exit while we're cleaning up
	// NOTE: we intentionally start this routine before checking for detonation errors, because
	// the Stratus Red Team detonate doesn't clean up failed detonations (by design)
	go m.cleanupRoutineAsync()
	defer m.shutDown()

	if detonationErr != nil {
		return fmt.Errorf("unable to detonate Stratus Red Team attack technique %s: %w", m.StratusRedTeamDetonator.AttackTechnique, detonationErr)
	}

	log.Info("Stratus Red Team attack technique successfully detonated")

	log.Info("Searching for CloudTrail events...")
	results, detonationErr := cloudtrailLogs.FindLogs(m.ctx, detonation)
	if detonationErr != nil {
		return detonationErr
	}

	errorChan := make(chan error)

	// Main processing loop that consumes events and streams them out
	go m.processingLoop(results, errorChan)

	// Wait for event processing to be done, either due to a Ctrl+C either due to normal exit conditions
	log.Debugf("Waiting for event processing to be done")
	err := <-errorChan
	log.Debugf("Event processing done, received a result from the error channel")
	if err != nil {
		return err
	}

	return nil
}

func (m *StratusRedTeamCommand) handleNewEvent(event *map[string]interface{}) error {
	log.Printf("Found new CloudTrail event generated on %s UTC: %s", (*event)["eventTime"], (*event)["eventName"])
	err := utils.AppendToJsonFileArray(m.OutputFile, *event)
	if err != nil {
		return fmt.Errorf("unable to write CloudTrail event to %s: %v", m.OutputFile, err)
	}
	return nil
}

func (m *StratusRedTeamCommand) CleanupDetonation() error {
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

	log.Debug("Clean-up routine completed")
	return err
}

func (m *StratusRedTeamCommand) handleCtrlC() {
	m.sigChan = make(chan os.Signal, 1)
	signal.Notify(m.sigChan, os.Interrupt, syscall.SIGTERM)
	// Handle CTRL+C gracefully
	go func() {
		for range m.sigChan {
			if m.wasCtrlCPressed.CompareAndSwap(false, true) {
				log.Info("Exiting Grimoire cleanly, don't press Ctrl+C again")
				m.cancel()
				// NOTE: We don't clean up here again, because the cleanup starts asynchronously after the attack is detonated
				// and the program waits for it to be completed before exiting in any case.
				// In the future, if we have generic, non-Stratus Red Team related clean-up tasks, we should add them here.
			} else {
				log.Info("You already pressed Ctrl+C, please wait for Grimoire to exit")
			}
		}
	}()
}

func (m *StratusRedTeamCommand) detonateStratusRedTeam() (*detonators.DetonationInfo, error) {
	// Detonate Stratus Red Team attack technique, honoring context cancellation
	type StratusRedTeamDetonation struct {
		detonation *detonators.DetonationInfo
		err        error
	}
	detonationChan := make(chan *StratusRedTeamDetonation)
	go func() {
		detonation, err := m.StratusRedTeamDetonator.Detonate()
		detonationChan <- &StratusRedTeamDetonation{detonation, err}
	}()
	select {
	case <-m.ctx.Done():
		log.Infof("You pressed Ctrl+C during the Stratus Red Team detonation, which could leave some cloud resources in your account. Attempting to clean it up...")
		if err := m.CleanupDetonation(); err != nil {
			log.Debugf("Unable to clean-up Stratus Red Team attack technique %s: %v", m.StratusRedTeamDetonator.AttackTechnique, err)
			log.Debugf("Attack technique status is %s", m.StratusRedTeamDetonator.GetAttackTechniqueState())
			log.Warnf("Unable to clean-up Stratus Red Team attack technique. You might want to manually clean it up by running 'stratus cleanup %s' to avoid leaving resources in your account", m.StratusRedTeamDetonator.AttackTechnique)
		}
		return nil, context.Canceled
	case result := <-detonationChan:
		return result.detonation, result.err
	}
}

func (m *StratusRedTeamCommand) cleanupRoutineAsync() {
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
	}
}

func (m *StratusRedTeamCommand) processingLoop(results <-chan *logs.CloudTrailResult, errorChan chan error) {
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
				m.cancel()
				errorChan <- evt.Error
				return
			}

			// Otherwise, we call handleNewEvent which will stream the newly-found event appropriately
			if err := m.handleNewEvent(evt.CloudTrailEvent); err != nil {
				// If processing of this event fails, we abort execution
				log.Errorf(err.Error())
				m.cancel()
				errorChan <- err
				return
			}

			// We don't return here, this is the happy path where the processing loop continues

		case <-m.ctx.Done():
			log.Debug("Stopping event processing due to context cancellation")
			errorChan <- nil
			return
		}
	}
}

func (m *StratusRedTeamCommand) shutDown() {
	// Make sure we wait until cleanup is finished before exiting
	if m.cleanupRunning.Load() {
		log.Info("Waiting for Stratus Red Team attack technique clean-up to complete...")
	}
	m.cleanupWg.Wait()
	if !m.cleanupSucceeded.Load() {
		// Note: Stratus Red Team Cleanup function calls the Terraform Go Wrapper, which unfortunately
		// catches Ctrl+C signals. This means that if the user presses Ctrl+C at "the wrong time", the cleanup
		// will fail because the Terraform Wrapper will panic and exit

		// Consequently, we have some logic baked in later in this function to retry the cleanup at the end if
		// the asynchronous cleanup failed for this specific reason
		log.Info("Asynchronous cleanup of the Stratus Red Team detonation failed, retrying one last time... don't press Ctrl+C")
		if err := m.CleanupDetonation(); err != nil {
			log.Warnf("unable to cleanup Stratus Red Team attack technique %s: %v", m.StratusRedTeamDetonator.AttackTechnique, err)
			log.Warnf("You might want to manually clean it up by running 'stratus cleanup %s'", m.StratusRedTeamDetonator.AttackTechnique)
		} else {
			log.Info("Cleanup of the Stratus Red Team attack technique succeeded")
		}
	}
	log.Debug("Cleanup finished, exiting")
}
