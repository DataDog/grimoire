package grimoire

import (
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
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

func CreateOrTruncateJSONFile(outputFile string) error {
	if outputFile == "" || outputFile == "-" {
		return nil // nothing to do
	}
	return os.WriteFile(outputFile, []byte("[]"), 0600)
}

// AppendToJsonFileArray assumes that 'outputFile' is an existing JSON file containing an array of JSON objects, and appends 'payload' to it
func AppendToJsonFileArray(outputFile string, payload map[string]interface{}) error {
	if outputFile == "" {
		return nil // nothing to do
	}

	// print to stdout, nothing else to do
	if outputFile == "-" {
		outputBytes, err := json.MarshalIndent(payload, "", "   ")
		if err != nil {
			return err
		}
		fmt.Println(string(outputBytes))
		return nil
	}

	// Read file contents and parse the JSON
	var events []map[string]interface{}
	inputBytes, err := os.ReadFile(outputFile)
	if err != nil {
		return fmt.Errorf("unable to read output file %s: %v", outputFile, err)
	}
	if err := json.Unmarshal(inputBytes, &events); err != nil {
		return fmt.Errorf("unable to unmarshal output file contents %s: %v", outputFile, err)
	}

	// Append our payload
	events = append(events, payload)

	// Re-convert it back to JSON
	outputBytes, err := json.MarshalIndent(events, "", "   ")
	if err != nil {
		return fmt.Errorf("unable to marshal JSON to output file %s: %v", outputFile, err)
	}

	// Write back ot the output file
	if err := os.WriteFile(outputFile, outputBytes, 0600); err != nil {
		return fmt.Errorf("unable to write to output file %s for writing: %v", outputFile, err)
	}

	return nil
}
