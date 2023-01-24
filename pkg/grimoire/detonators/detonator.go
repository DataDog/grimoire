package detonators

import "github.com/datadog/grimoire/pkg/grimoire/common"

type Detonator interface {
	String() string
	Detonate() (grimoire.DetonationID, error)
	CleanUp() error
}
