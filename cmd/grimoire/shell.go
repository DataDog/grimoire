package main

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/datadog/grimoire/pkg/grimoire/detonators"
	"github.com/datadog/grimoire/pkg/grimoire/logs"
	utils "github.com/datadog/grimoire/pkg/grimoire/utils"
	"github.com/inancgumus/screen"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"
)

type ShellCommand struct {
	outputFile string
}

func NewShellCommand() *cobra.Command {
	var outputFile string

	shellCmd := &cobra.Command{
		Use:          "shell",
		Short:        "TODO",
		SilenceUsage: true,
		Example:      "TODO",
		RunE: func(cmd *cobra.Command, args []string) error {
			command := ShellCommand{
				outputFile: outputFile,
			}
			return command.Do()
		},
	}

	shellCmd.Flags().StringVarP(&outputFile, "output-file", "o", "", "TODO")

	return shellCmd
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

	if err := utils.CreateOrTruncateJSONFile(m.outputFile); err != nil {
		return err
	}

	detonationUuid := utils.NewDetonationID()
	awsConfig, _ := config.LoadDefaultConfig(context.Background())

	// Ensure that the user is already authenticated to AWS
	m.ensureAuthenticatedToAws(awsConfig)

	log.Info("Grimoire will now run your shell and automatically inject a unique identifier to your HTTP user agent when using the AWS CLI")
	log.Info("You can use the AWS CLI as usual. Press Ctrl+D or type 'exit' to return to Grimoire.")
	log.Info("When you exit the shell, Grimoire will look for the CloudTrail logs that your commands have generated.")
	log.Info("Press ENTER to continue")
	if _, err := fmt.Scanln(); err != nil {
		return err
	}
	screen.Clear()

	startTime := time.Now()
	cmd := exec.CommandContext(ctx, os.Getenv("SHELL"))
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(
		os.Environ(),
		fmt.Sprintf("AWS_EXECUTION_ENV=grimoire_%s", detonationUuid),
	)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("unable to run shell: %v", err)
	}
	endTime := time.Now()
	screen.Clear()
	screen.MoveTopLeft()
	log.Infof("Welcome back to Grimoire!")

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

	log.Info("Searching for CloudTrail logs...")
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
		if err := utils.AppendToJsonFileArray(m.outputFile, *evt.CloudTrailEvent); err != nil {
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
