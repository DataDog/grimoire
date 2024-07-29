package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	grimoire "github.com/datadog/grimoire/pkg/grimoire/common"
	"github.com/datadog/grimoire/pkg/grimoire/logs"
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
			fmt.Println("Cancelling!")
			//TODO: Cancel in-progress CloudTrail SQL Lake queries
			os.Exit(0)
		case <-ctx.Done():
		}
	}()

	if m.outputFile != "" {
		if err := os.WriteFile(m.outputFile, []byte("[]"), 0600); err != nil {
			return fmt.Errorf("unable to create output file %s: %v", m.outputFile, err)
		}
	}

	detonationUuid := grimoire.NewDetonationID()
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
	screen.Clear()
	screen.MoveTopLeft()
	log.Infof("Welcome back to Grimoire!")

	cloudtrailLogs := &logs.CloudTrailDataStore{
		CloudtrailClient: cloudtrail.NewFromConfig(awsConfig),
		DataStoreId:      "4cee9f76-991a-46fc-9c49-7ab50d19d83d", // TODO
		Options: &logs.CloudTrailEventLookupOptions{
			WaitAtMost:                  10 * time.Minute,
			SearchInterval:              15 * time.Second,
			DebounceTimeAfterFirstEvent: 120 * time.Second,
			UserAgentMatchType:          logs.UserAgentMatchTypePartial,
		},
	}

	eventsChannel, err := cloudtrailLogs.FindLogs(detonationUuid)
	if err != nil {
		return fmt.Errorf("unable to search for CloudTrail events: %v", err)
	}

	for evt := range eventsChannel {
		if evt.Error != nil {
			log.Errorf("Error while searching for CloudTrail events: %v", evt.Error)
			os.Exit(1)
		}

		log.Infof("Found event: %s", (*evt.CloudTrailEvent)["eventName"])
		if err := m.appendToFile(*evt.CloudTrailEvent); err != nil {
			log.Errorf("unable to append CloudTrail event to output file: %v", err)
		}
	}

	return nil
}

func (m *ShellCommand) appendToFile(event map[string]interface{}) error {
	if m.outputFile == "" {
		return nil // nothing to do
	}
	if m.outputFile == "-" {
		outputBytes, err := json.MarshalIndent(event, "", "   ")
		if err != nil {
			return err
		}
		fmt.Println(string(outputBytes))
		return nil
	}

	inputBytes, err := os.ReadFile(m.outputFile)
	if err != nil {
		return err
	}
	var events []map[string]interface{}
	err = json.Unmarshal(inputBytes, &events)
	if err != nil {
		return err
	}
	events = append(events, event)

	outputBytes, err := json.MarshalIndent(events, "", "   ")
	if err != nil {
		return err
	}

	file, err := os.OpenFile(m.outputFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.Write(outputBytes)
	if err != nil {
		return err
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
