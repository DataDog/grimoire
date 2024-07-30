package detonators

import (
	"time"
)

type DetonationInfo struct {
	DetonationID string
	StartTime    time.Time
	EndTime      time.Time
}

type Detonator interface {
	String() string
	Detonate() (*DetonationInfo, error)
	CleanUp() error
}
