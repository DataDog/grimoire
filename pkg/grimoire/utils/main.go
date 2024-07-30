package grimoire

import (
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"os"
	"time"
)

func NewDetonationID() string {
	return uuid.New().String()
}

// Latest returns the time.Time which is the further away
func Latest(first time.Time, second time.Time) time.Time {
	if first.After(second) {
		return first
	}
	return second
}

// AppendToJsonFileArray assumes that 'outputFile' is a JSON file containing an array of JSON objects, and appends 'payload' to it
func AppendToJsonFileArray(outputFile string, payload map[string]interface{}) error {
	//TODO: create if not exists, don't assume the input file has a JSON empty array

	if outputFile == "" {
		return nil // nothing to do
	}
	if outputFile == "-" {
		outputBytes, err := json.MarshalIndent(payload, "", "   ")
		if err != nil {
			return err
		}
		fmt.Println(string(outputBytes))
		return nil
	}

	inputBytes, err := os.ReadFile(outputFile)
	if err != nil {
		return fmt.Errorf("unable to read JSON file %s: %v", outputFile, err)
	}
	var events []map[string]interface{}
	err = json.Unmarshal(inputBytes, &events)
	if err != nil {
		return fmt.Errorf("unable to unmarshal JSON file %s: %v", outputFile, err)
	}
	events = append(events, payload)

	outputBytes, err := json.MarshalIndent(events, "", "   ")
	if err != nil {
		return fmt.Errorf("unable to marshal JSON file %s: %v", outputFile, err)
	}

	file, err := os.OpenFile(outputFile, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return fmt.Errorf("unable to open JSON file %s for writing: %v", outputFile, err)
	}
	defer file.Close()
	log.Debugf("Output file currently contains: %s", string(inputBytes))
	log.Debugf("Writing the following to output file: %s", string(outputBytes))

	_, err = file.Write(outputBytes)
	if err != nil {
		return fmt.Errorf("unable to write JSON file %s: %v", outputFile, err)
	}

	return nil
}
