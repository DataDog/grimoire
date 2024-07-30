package grimoire

import (
	"github.com/google/uuid"
	"time"
)

func NewDetonationID() string {
	return uuid.New().String()
}

// latest returns the time.Time which is the further away
func Latest(first time.Time, second time.Time) time.Time {
	if first.After(second) {
		return first
	}
	return second
}
