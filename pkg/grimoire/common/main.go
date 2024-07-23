package grimoire

import "github.com/google/uuid"

type DetonationID string

func NewDetonationID() DetonationID {
	return DetonationID(uuid.New().String())
}
