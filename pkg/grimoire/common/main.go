package grimoire

import "github.com/google/uuid"

func NewDetonationID() string {
	return uuid.New().String()
}
