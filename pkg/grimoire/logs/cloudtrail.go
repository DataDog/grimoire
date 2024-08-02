package logs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/datadog/grimoire/pkg/grimoire/detonators"
	grimoire "github.com/datadog/grimoire/pkg/grimoire/utils"
	log "github.com/sirupsen/logrus"
	"strings"
	"time"
)

type UserAgentMatchType int

const (
	UserAgentMatchTypeExact UserAgentMatchType = iota
	UserAgentMatchTypePartial
)

const CloudtrailExtendWindowEndDuration = 10 * time.Second

type CloudTrailEventsFinder struct {
	CloudtrailClient *cloudtrail.Client
	Options          *CloudTrailEventLookupOptions
}

type CloudTrailEventLookupOptions struct {
	// Timeout to find the *first* CloudTrail event
	Timeout time.Duration

	// Wait for at most this number of events to be found
	MaxEvents int

	// Issue a new CloudTrail lookup query every LookupInterval
	LookupInterval time.Duration

	// Exclude specific CloudTrail events from the search
	// NOTE: Only one of IncludeEvents and ExcludeEvents can be used simultaneously, not both
	// Event names should be in the format "[service]:[eventName]", e.g. "sts:GetCallerIdentity" and are case-insensitive
	ExcludeEvents []string

	// Only include specific CloudTrail events from the search
	// NOTE: Only one of IncludeEvents and ExcludeEvents can be used simultaneously, not both
	// Event names should be in the format "[service]:[eventName]", e.g. "sts:GetCallerIdentity" and are case-insensitive
	IncludeEvents []string

	// Only keep write events (i.e., non-read-only events)
	// see https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-management-events-with-cloudtrail.html#read-write-events-mgmt
	// this condition is evaluated in addition (and honoring) the IncludeEvents/ExcludeEvents lists
	WriteEventsOnly bool

	// UserAgentMatchType is the type of match to use when filtering by UserAgent
	UserAgentMatchType UserAgentMatchType
}

type CloudTrailResult struct {
	CloudTrailEvent *map[string]interface{}
	Error           error
}

func (m *CloudTrailEventsFinder) FindLogs(ctx context.Context, detonation *detonators.DetonationInfo) (chan *CloudTrailResult, error) {
	if len(m.Options.IncludeEvents) > 0 && len(m.Options.ExcludeEvents) > 0 {
		return nil, errors.New("only zero or one of IncludeEvents and ExcludeEvents can be specified")
	}
	return m.findEventsWithCloudTrail(ctx, detonation)
}

func (m *CloudTrailEventsFinder) findEventsWithCloudTrail(ctx context.Context, detonation *detonators.DetonationInfo) (chan *CloudTrailResult, error) {
	results := make(chan *CloudTrailResult)
	resultsInternal := make(chan *CloudTrailResult)

	// findEventsWithCloudTrailAsync has a long-running for loop that will be stopped when the context is cancelled
	// To achieve this, we "proxy" the results through another channel, and close it when the context is cancelled
	// This allows to quickly abort whenever the parent context is cancelled (for instance on a Ctrl+C)
	// Otherwise we'd have to check inside the loop and there could be a delay of several seconds

	go m.findEventsWithCloudTrailAsync(ctx, detonation, resultsInternal)

	go func() {
		defer close(results)
		for {
			select {
			case <-ctx.Done():
				// Parent context cancelled
				log.Debug("CloudTrailEventFinder identified that the parent context was cancelled, returning")
				results <- &CloudTrailResult{Error: fmt.Errorf("parent context was cancelled: %w", ctx.Err())}
				return

			case result, ok := <-resultsInternal:
				// We got a result, forward it to the parent channel
				if !ok {
					return // no more results
				}
				results <- result
			}
		}
	}()

	return results, nil
}

func (m *CloudTrailEventsFinder) findEventsWithCloudTrailAsync(ctx context.Context, detonation *detonators.DetonationInfo, results chan *CloudTrailResult) {
	defer close(results)

	var allEvents = []map[string]interface{}{}
	now := time.Now()
	deadline := now.Add(m.Options.Timeout)

	log.Debugf("Deadline for finding CloudTrail events is %s", deadline)

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
				log.Debugf("Found %d new CloudTrail events", len(newEventsFound))
				for _, newEvent := range newEventsFound {
					log.Debug("Publishing new event to asynchronous channel")
					results <- &CloudTrailResult{CloudTrailEvent: newEvent}
				}

				// If we reached the max number of events to wait for, return as soon as possible
				if m.Options.MaxEvents > 0 && len(allEvents) >= m.Options.MaxEvents {
					log.Debugf("Reached %d events, stopping search", m.Options.MaxEvents)
					return
				}
			} else {
				log.Debug("Some CloudTrail events were returned, but no previously-unseen events were found")
			}
		}
		log.Debugf("Sleeping for LookupInterval=%f seconds", m.Options.LookupInterval.Seconds())
		time.Sleep(m.Options.LookupInterval)
	}

	if len(allEvents) == 0 {
		results <- &CloudTrailResult{Error: fmt.Errorf("timed out after %f seconds waiting for CloudTrail events", m.Options.Timeout.Seconds())}
		return
	}
}

func (m *CloudTrailEventsFinder) lookupEvents(ctx context.Context, detonation *detonators.DetonationInfo) ([]map[string]interface{}, error) {
	// Check if the parent context was cancelled to avoid awkwardly continuing the search when the program is exiting
	if err := ctx.Err(); err != nil && errors.Is(err, context.Canceled) {
		return nil, context.Canceled
	}
	// in some cases, the time logged in the CloudTrail event is a few seconds "late" in comparison
	// to when the detonation happens
	endTime := detonation.EndTime.Add(CloudtrailExtendWindowEndDuration)
	paginator := cloudtrail.NewLookupEventsPaginator(m.CloudtrailClient, &cloudtrail.LookupEventsInput{
		StartTime: &detonation.StartTime,
		EndTime:   &endTime,
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
					if m.shouldKeepEvent(&parsed) {
						log.Debugf("Found CloudTrail event %s matching detonation UID", eventName)
						events = append(events, parsed)
					} else {
						log.Debugf("Found CloudTrail event %s matching detonation UID, but ignoring as it's on the exclude list", eventName)
					}
				}
			}
		}
	}
	return events, nil
}

func (m *CloudTrailEventsFinder) shouldKeepEvent(event *map[string]interface{}) bool {
	// note: we know (precondition) that zero or one of IncludeEvents and ExcludeEvents is set, not both

	eventName := (*event)["eventName"].(string)
	eventSourceShort := strings.TrimSuffix((*event)["eventSource"].(string), ".amazonaws.com")
	fullEventName := fmt.Sprintf("%s:%s", eventSourceShort, eventName) // e.g. "sts:GetCallerIdentity"
	isReadOnly := (*event)["readOnly"].(bool)

	if m.Options.WriteEventsOnly && isReadOnly {
		log.Debugf("Ignoring event %s as it's read-only and we only want write events", fullEventName)
		return false
	}

	// If an exclusion list is set, we exclude events that are in the list
	if len(m.Options.ExcludeEvents) > 0 {
		for i := range m.Options.ExcludeEvents {
			if grimoire.StringMatches(fullEventName, m.Options.ExcludeEvents[i]) {
				log.Debug("Excluding event %s as it's on the exclude list", fullEventName)
				return false
			}
		}
		return true
	}

	// If an inclusion list is set, we only include events that are in the list
	if len(m.Options.IncludeEvents) == 0 {
		for i := range m.Options.IncludeEvents {
			if grimoire.StringMatches(fullEventName, m.Options.IncludeEvents[i]) {
				log.Debug("Including event %s as it's on the include list", fullEventName)
				return true
			}
		}
		return false
	}

	return true // no exclude nor include list, we keep everything
}

func (m *CloudTrailEventsFinder) eventsMatchesDetonation(event map[string]interface{}, detonation *detonators.DetonationInfo) bool {
	userAgent := event["userAgent"].(string)

	switch m.Options.UserAgentMatchType {
	case UserAgentMatchTypeExact:
		return strings.EqualFold(userAgent, detonation.DetonationID)
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
