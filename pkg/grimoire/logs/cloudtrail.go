package logs

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/datadog/grimoire/pkg/grimoire/common"
	log "github.com/sirupsen/logrus"
	"strings"
	"time"
)

type CloudTrailDataStore struct {
	CloudtrailClient *cloudtrail.Client
	DataStoreId      string
	Options          *CloudTrailEventLookupOptions
}

type UserAgentMatchType int

const (
	UserAgentMatchTypeExact UserAgentMatchType = iota
	UserAgentMatchTypePartial
)

type CloudTrailEventLookupOptions struct {
	// Timeout to find the *first* CloudTrail event
	WaitAtMost time.Duration

	// Lower bound on the time to wait for events
	// Can be useful if for instance specific events are logged much faster than others
	WaitAtLeast time.Duration

	// Issue a new CloudTrail Lake search query every SearchInterval
	SearchInterval time.Duration

	// Once the first event is found, how much time to wait until there is no new event
	DebounceTimeAfterFirstEvent time.Duration

	// Exclude specific CloudTrail events from the search
	ExcludeEvents []string

	// UserAgentMatchType is the type of match to use when filtering by UserAgent
	UserAgentMatchType UserAgentMatchType
}

func (m *CloudTrailDataStore) FindLogs(detonationId grimoire.DetonationID, logsChan *chan *map[string]interface{}) ([]map[string]interface{}, error) {
	exclusion := ""
	if len(m.Options.ExcludeEvents) > 0 {
		exclusion = fmt.Sprintf("AND eventName NOT IN (%s)", strings.Join(m.Options.ExcludeEvents, ","))
	}

	var userAgentQuery = ""
	switch m.Options.UserAgentMatchType {
	case UserAgentMatchTypeExact:
		userAgentQuery = fmt.Sprintf("userAgent = '%s'", detonationId)
	case UserAgentMatchTypePartial:
		userAgentQuery = fmt.Sprintf("userAgent LIKE '%%%s%%'", detonationId)
	}

	query := fmt.Sprintf(
		`SELECT eventjson FROM %s WHERE %s %s ORDER BY eventTime ASC`,
		m.DataStoreId,
		userAgentQuery,
		exclusion,
	)
	log.Info(query)

	return m.findEvents(query, logsChan)
}

/*
	func mytest() {
		ctx, cancel := context.WithCancel()
		timer := time.AfterFunc(10*time.Second, func() {
			cancel()
		})
		timer.Stop()
	}
*/
func (m *CloudTrailDataStore) findEvents(query string, logsChan *chan *map[string]interface{}) ([]map[string]interface{}, error) {
	if m.Options.WaitAtLeast.Seconds() > m.Options.WaitAtMost.Seconds() {
		return nil, fmt.Errorf("invalid Options ('wait at least' should be lower or equal to 'wait at most')")
	}
	var allEvents = []map[string]interface{}{}
	now := time.Now()
	waitAtLeastUntil := now.Add(m.Options.WaitAtLeast)
	deadline := now.Add(m.Options.WaitAtMost)

	// We look for events as long as we didn't reach the deadline
	for time.Now().Before(deadline) {
		events, err := m.runQuery(query)
		if err != nil {
			return nil, err
		}
		if len(events) > 0 {
			// Add the events we found to our current set of events, removing any duplicates
			var newEventsFound []*map[string]interface{}
			allEvents, newEventsFound = dedupeAndAppend(allEvents, events)

			if len(newEventsFound) > 0 {
				log.Infof("Found %d new CloudTrail events", len(newEventsFound))
				// At this point, we found at least CloudTrail event
				// We now want to set a new "deadline", i.e. when we'll stop searching for further events
				// Set this new deadline, honoring both "wait at least X" and "wait for Y seconds after new events" constraints
				//
				// Note: The loop will continue as long as we keep finding new CloudTrail events
				newDeadline := time.Now().Add(m.Options.DebounceTimeAfterFirstEvent)
				deadline = latest(newDeadline, waitAtLeastUntil)
				if logsChan != nil {
					for _, newEvent := range newEventsFound {
						*logsChan <- newEvent
					}
				}
			}
		}
		time.Sleep(m.Options.SearchInterval)
	}

	if len(allEvents) == 0 {
		return nil, fmt.Errorf("timed out after %f seconds waiting for CloudTrail logs", m.Options.WaitAtMost.Seconds())
	}

	return allEvents, nil
}

// runQuery runs a specific CloudTrail Lake query, waits for the resultsand returns it
func (m *CloudTrailDataStore) runQuery(query string) ([]map[string]interface{}, error) {
	result, err := m.CloudtrailClient.StartQuery(context.Background(), &cloudtrail.StartQueryInput{
		QueryStatement: aws.String(query),
	})
	if err != nil {
		return nil, fmt.Errorf("unable to run CloudTrail Lake query '%s': %w", query, err)
	}

	// Note: We assume that any CloudTrail Lake query eventually finishes
	// TODO: use contexts with the proper deadline
	for {
		queryResults, err := m.CloudtrailClient.GetQueryResults(context.Background(), &cloudtrail.GetQueryResultsInput{
			QueryId: result.QueryId,
		})
		if err != nil {
			return nil, fmt.Errorf("unable to retrieve CloudTrail Lake query results: %w", err)
		}

		queryStatus := queryResults.QueryStatus
		if queryStatus == types.QueryStatusQueued || queryStatus == types.QueryStatusRunning {
			// The query is still running
			time.Sleep(1 * time.Second)
			continue
		} else if queryStatus == types.QueryStatusFailed || queryStatus == types.QueryStatusCancelled {
			// The query failed or was cancelled for some reason
			return nil, fmt.Errorf("failed running CloudTrail Lake query: status %s", queryStatus)
		} else if queryStatus == types.QueryStatusFinished {
			// The query is done!
			return flatten(queryResults.QueryResultRows), nil
		} else {
			return nil, fmt.Errorf("unexpected CloudTrail Lake query status: %s", queryStatus)
		}
	}
}

// Utility methods
func flatten(events [][]map[string]string) []map[string]interface{} {
	flattened := []map[string]interface{}{}
	for i := range events {
		for j := range events[i] {
			var parsed map[string]interface{}
			json.Unmarshal([]byte(events[i][j]["eventjson"]), &parsed)
			flattened = append(flattened, parsed)
		}
	}

	return flattened
}

func dedupeAndAppend(allEvents []map[string]interface{}, newEvents []map[string]interface{}) ([]map[string]interface{}, []*map[string]interface{}) {
	// Build a set of event IDs
	//TODO don't rebuild every time
	eventIDs := map[string]bool{}
	const EventIDKey = "eventID"
	for _, event := range allEvents {
		eventID := event[EventIDKey].(string)
		eventIDs[eventID] = true
	}

	// Add events we don't have yet
	actualNewEvents := []*map[string]interface{}{}
	for _, newEvent := range newEvents {
		eventID := newEvent[EventIDKey].(string)
		if _, eventExists := eventIDs[eventID]; !eventExists {
			allEvents = append(allEvents, newEvent)
			actualNewEvents = append(actualNewEvents, &newEvent)
		}
	}

	return allEvents, actualNewEvents
}

// latest returns the time.Time which is the further away
func latest(first time.Time, second time.Time) time.Time {
	if first.After(second) {
		return first
	}
	return second
}
