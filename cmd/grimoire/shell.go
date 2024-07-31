package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/datadog/grimoire/pkg/grimoire/detonators"
	"github.com/datadog/grimoire/pkg/grimoire/logs"
	utils "github.com/datadog/grimoire/pkg/grimoire/utils"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"
)

type ShellCommand struct {
	OutputFile   string
	CommandToRun string
	ScriptToRun  string
}

func NewShellCommand() *cobra.Command {
	var outputFile string
	var commandToRun string
	var scriptToRun string

	shellCmd := &cobra.Command{
		Use:          "shell",
		SilenceUsage: true,
		Example:      "TODO",
		RunE: func(cmd *cobra.Command, args []string) error {
			command := ShellCommand{
				OutputFile:   outputFile,
				CommandToRun: commandToRun,
				ScriptToRun:  scriptToRun,
			}
			if err := command.Validate(); err != nil {
				return err
			}
			return command.Do()
		},
	}

	shellCmd.Flags().StringVarP(&outputFile, "output", "o", "", "TODO")
	shellCmd.Flags().StringVarP(&commandToRun, "command", "c", "", "TODO")
	shellCmd.Flags().StringVarP(&scriptToRun, "script", "", "", "TODO")

	return shellCmd
}

func (m *ShellCommand) Validate() error {
	if m.CommandToRun != "" && m.ScriptToRun != "" {
		return fmt.Errorf("only one of 'command' or 'script' can be specified")
	}
	return nil
}
func (m *ShellCommand) Do() error {
	ctx, cancel := context.WithCancel(context.Background())
	sigChan := make(chan os.Signal)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case <-sigChan:
			cancel()
			close(sigChan)
			log.Info("Exiting Grimoire.")
			os.Exit(0)
		case <-ctx.Done():
		}
	}()

	if err := utils.CreateOrTruncateJSONFile(m.OutputFile); err != nil {
		return err
	}

	detonationUuid := utils.NewDetonationID()
	awsConfig, _ := config.LoadDefaultConfig(context.Background())

	// Ensure that the user is already authenticated to AWS
	m.ensureAuthenticatedToAws(awsConfig)

	if m.isInteractiveMode() {
		log.Info("Grimoire will now run your shell and automatically inject a unique identifier to your HTTP user agent when using the AWS CLI")
		log.Info("You can use the AWS CLI as usual. Press Ctrl+D or type 'exit' to return to Grimoire.")
		log.Info("When you exit the shell, Grimoire will look for the CloudTrail events that your commands have generated.")
		log.Info("Press ENTER to continue")
		if _, err := fmt.Scanln(); err != nil {
			return err
		}
	} else if m.CommandToRun != "" {
		log.Infof("Running detonation command: %s", m.CommandToRun)
	} else if m.ScriptToRun != "" {
		log.Infof("Running detonation script: %s", m.ScriptToRun)
	}

	startTime := time.Now()
	grimoireUserAgent := fmt.Sprintf("grimoire_%s", detonationUuid)
	commandToRun, args := m.getCommandToRun()
	log.Debugf("Running command: %s %v", commandToRun, args)
	cmd := exec.CommandContext(ctx, commandToRun, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(
		os.Environ(),
		fmt.Sprintf("AWS_EXECUTION_ENV=%s", grimoireUserAgent),
		fmt.Sprintf("GRIMOIRE_DETONATION_ID=%s", detonationUuid), // generic environment variable to allow the user to pass it further if needed
	)
	if err := cmd.Run(); err != nil && m.isExecutionError(err) {
		return fmt.Errorf("unable to run shell: %v", err)
	}
	endTime := time.Now()

	if m.isInteractiveMode() {
		log.Infof("Welcome back to Grimoire!")
	}

	cloudtrailLogs := &logs.CloudTrailEventsFinder{
		CloudtrailClient: cloudtrail.NewFromConfig(awsConfig),
		Options: &logs.CloudTrailEventLookupOptions{
			WaitAtMost:                  10 * time.Minute,
			SearchInterval:              15 * time.Second,
			DebounceTimeAfterFirstEvent: 120 * time.Second,
			UserAgentMatchType:          logs.UserAgentMatchTypePartial,
		},
	}

	detonationInfo := &detonators.DetonationInfo{
		DetonationID: detonationUuid,
		StartTime:    startTime,
		EndTime:      endTime,
	}

	log.Info("Searching for CloudTrail events...")
	eventsChannel, err := cloudtrailLogs.FindLogs(context.Background(), detonationInfo)
	if err != nil {
		return fmt.Errorf("unable to search for CloudTrail events: %v", err)
	}

	for evt := range eventsChannel {
		if evt.Error != nil {
			log.Errorf("Error while searching for CloudTrail events: %v", evt.Error)
			os.Exit(1)
		}

		log.Infof("Found event: %s", (*evt.CloudTrailEvent)["eventName"])
		if err := utils.AppendToJsonFileArray(m.OutputFile, *evt.CloudTrailEvent); err != nil {
			log.Errorf("unable to append CloudTrail event to output file: %v", err)
		}
	}

	return nil
}

func (m *ShellCommand) ensureAuthenticatedToAws(awsConfig aws.Config) {
	log.Debug("Checking AWS authentication using sts:GetCallerIdentity")
	stsClient := sts.NewFromConfig(awsConfig)
	_, err := stsClient.GetCallerIdentity(context.Background(), &sts.GetCallerIdentityInput{})
	if err != nil {
		log.Errorf("It looks like you are not authenticated to AWS. Please authenticate before running Grimoire.")
		os.Exit(1)
	}
}

func (m *ShellCommand) isExecutionError(err error) bool {
	// Ignore errors due to exit code 130 ("cancelled by ctrl+c")
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		if status, ok := exitError.Sys().(syscall.WaitStatus); ok {
			if status.ExitStatus() == 130 {
				// Ignore the error if the exit status is 130
				return false
			}
		}
	}

	return true
}

func (m *ShellCommand) getCommandToRun() (string, []string) {
	shell := os.Getenv("SHELL")
	if m.CommandToRun != "" {
		return shell, []string{"-c", m.CommandToRun}
	} else if m.ScriptToRun != "" {
		return shell, []string{"-x", m.ScriptToRun}
	} else {
		return shell, []string{}
	}
}

func (m *ShellCommand) isInteractiveMode() bool {
	return m.CommandToRun == "" && m.ScriptToRun == ""
}
