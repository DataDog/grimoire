package logs

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/datadog/grimoire/pkg/grimoire/detonators"
	utils "github.com/datadog/grimoire/pkg/grimoire/utils"
	log "github.com/sirupsen/logrus"
	"strings"
	"time"
)

type UserAgentMatchType int

const (
	UserAgentMatchTypeExact UserAgentMatchType = iota
	UserAgentMatchTypePartial
)

type CloudTrailEventsFinder struct {
	CloudtrailClient *cloudtrail.Client
	Options          *CloudTrailEventLookupOptions
}

type CloudTrailEventLookupOptions struct {
	// Timeout to find the *first* CloudTrail event
	WaitAtMost time.Duration

	// Lower bound on the time to wait for events
	// Can be useful if for instance specific events are logged much faster than others
	WaitAtLeast time.Duration

	// Wait for at most this number of events to be found
	WaitAtMostNumberOfEvents int

	// Issue a new CloudTrail Lake search query every SearchInterval
	SearchInterval time.Duration

	// Once the first event is found, how much time to wait until there is no new event
	DebounceTimeAfterFirstEvent time.Duration

	// Exclude specific CloudTrail events from the search
	ExcludeEvents []string

	// UserAgentMatchType is the type of match to use when filtering by UserAgent
	UserAgentMatchType UserAgentMatchType
}

type CloudTrailResult struct {
	CloudTrailEvent *map[string]interface{}
	Error           error
}

func (m *CloudTrailEventsFinder) FindLogs(ctx context.Context, detonation *detonators.DetonationInfo) (chan *CloudTrailResult, error) {
	if m.Options.WaitAtLeast.Seconds() > m.Options.WaitAtMost.Seconds() {
		return nil, fmt.Errorf("invalid Options ('wait at least' should be lower or equal to 'wait at most')")
	}

	return m.findEventsWithCloudTrail(ctx, detonation)
}

func (m *CloudTrailEventsFinder) findEventsWithCloudTrail(ctx context.Context, detonation *detonators.DetonationInfo) (chan *CloudTrailResult, error) {
	results := make(chan *CloudTrailResult) //TODO split result and error channels?
	go m.findEventsWithCloudTrailAsync(ctx, detonation, results)
	return results, nil
}

func (m *CloudTrailEventsFinder) findEventsWithCloudTrailAsync(ctx context.Context, detonation *detonators.DetonationInfo, results chan *CloudTrailResult) {
	defer close(results)

	var allEvents = []map[string]interface{}{}
	now := time.Now()
	waitAtLeastUntil := now.Add(m.Options.WaitAtLeast)
	deadline := now.Add(m.Options.WaitAtMost)

	// We look for events as long as we didn't reach the deadline
	for time.Now().Before(deadline) {
		events, err := m.lookupEvents(ctx, detonation)
		if err != nil {
			results <- &CloudTrailResult{Error: fmt.Errorf("unable to run CloudTrail LookupEvents: %w", err)}
			return
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
				deadline = utils.Latest(newDeadline, waitAtLeastUntil)
				for _, newEvent := range newEventsFound {
					log.Debug("Publishing new event to asynchronous channel")
					results <- &CloudTrailResult{CloudTrailEvent: newEvent}
				}

				// If we reached the max number of events to wait for, return as soon as possible
				if m.Options.WaitAtMostNumberOfEvents > 0 && len(allEvents) >= m.Options.WaitAtMostNumberOfEvents {
					return
				}
			} else {
				log.Debug("Some CloudTrail events were returned, but no previously-unseen events were found")
			}
		}
		log.Debugf("Sleeping for SearchInterval=%f seconds", m.Options.SearchInterval.Seconds())
		time.Sleep(m.Options.SearchInterval)
	}

	if len(allEvents) == 0 {
		results <- &CloudTrailResult{Error: fmt.Errorf("timed out after %f seconds waiting for CloudTrail logs", m.Options.WaitAtMost.Seconds())}
		return
	}
}

func (m *CloudTrailEventsFinder) lookupEvents(ctx context.Context, detonation *detonators.DetonationInfo) ([]map[string]interface{}, error) {
	paginator := cloudtrail.NewLookupEventsPaginator(m.CloudtrailClient, &cloudtrail.LookupEventsInput{
		StartTime: &detonation.StartTime,
		EndTime:   &detonation.EndTime,
	})

	log.WithField("start_time", detonation.StartTime).
		WithField("end_time", detonation.EndTime).
		Debugf("Looking for CloudTrail events with using LookupEvents and detonation ID %s", detonation.DetonationID)

	events := []map[string]interface{}{}

	for paginator.HasMorePages() {
		logs, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("unable to retrieve CloudTrail events: %w", err)
		}
		if len(logs.Events) > 0 {
			log.Debugf("Found %d CloudTrail events", len(logs.Events))
			for i := range logs.Events {
				event := logs.Events[i].CloudTrailEvent
				var parsed map[string]interface{}
				json.Unmarshal([]byte(*event), &parsed)
				eventName := parsed["eventName"].(string)
				if m.eventsMatchesDetonation(parsed, detonation) {
					if !m.isEventNameExcluded(eventName) {
						log.Debugf("Found CloudTrail event %s matching detonation UID", eventName)
						events = append(events, parsed)
					} else {
						log.Debugf("Found CloudTrail event %s matching detonation UID, but ignoring as it's on the exclude list", eventName)
					}
				} else {
					log.Debugf("Found CloudTrail event %s but it does not match detonation UID", eventName)
				}
			}
		}
	}
	return events, nil
}

func (m *CloudTrailEventsFinder) isEventNameExcluded(name string) bool {
	for i := range m.Options.ExcludeEvents {
		if m.Options.ExcludeEvents[i] == name {
			return true
		}
	}
	return false
}

func (m *CloudTrailEventsFinder) eventsMatchesDetonation(event map[string]interface{}, detonation *detonators.DetonationInfo) bool {
	userAgent := event["userAgent"].(string)

	switch m.Options.UserAgentMatchType {
	case UserAgentMatchTypeExact:
		return strings.ToLower(userAgent) == strings.ToLower(detonation.DetonationID)
	case UserAgentMatchTypePartial:
		return strings.Contains(userAgent, detonation.DetonationID)
	default:
		return false
	}
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
