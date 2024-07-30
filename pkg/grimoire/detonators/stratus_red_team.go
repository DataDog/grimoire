package detonators

import (
	"fmt"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	_ "github.com/datadog/stratus-red-team/v2/pkg/stratus/loader"
	stratusrunner "github.com/datadog/stratus-red-team/v2/pkg/stratus/runner"
	log "github.com/sirupsen/logrus"
	"math"
	"time"
)

const StratusRedTeamUserAgentPrefix = "stratus-red-team_"

type StratusRedTeamDetonator struct {
	AttackTechnique *stratus.AttackTechnique
	StratusRunner   stratusrunner.Runner
}

func NewStratusRedTeamDetonator(attackTechniqueID string) (*StratusRedTeamDetonator, error) {
	ttp := stratus.GetRegistry().GetAttackTechniqueByName(attackTechniqueID)
	if ttp == nil {
		return nil, fmt.Errorf("Stratus Red Team attack technique %s not found", attackTechniqueID)
	}
	return &StratusRedTeamDetonator{AttackTechnique: ttp}, nil
}

func (m *StratusRedTeamDetonator) Detonate() (*DetonationInfo, error) {
	ttp := m.AttackTechnique

	m.StratusRunner = stratusrunner.NewRunner(ttp, stratusrunner.StratusRunnerNoForce)

	log.Debugf("Warming up Stratus Red Team attack technique %s", ttp)
	if _, err := m.StratusRunner.WarmUp(); err != nil {
		return nil, fmt.Errorf("error warming up Stratus Red Team attack technique %s: %w", ttp, err)
	}

	startTime := time.Now()
	log.Debugf("Detonating Stratus Red Team attack technique %s", ttp)
	if err := m.StratusRunner.Detonate(); err != nil {
		return nil, fmt.Errorf("error detonating Stratus Red Team attack technique %s: %w", ttp, err)
	}
	endTime := time.Now()
	log.Debugf("Detonation done in %d seconds", int(math.Round(endTime.Sub(startTime).Seconds())))

	return &DetonationInfo{
		DetonationID: StratusRedTeamUserAgentPrefix + m.StratusRunner.GetUniqueExecutionId(),
		StartTime:    startTime,
		EndTime:      endTime,
	}, nil
}

func (m *StratusRedTeamDetonator) CleanUp() error {
	return m.StratusRunner.CleanUp()
}

func (m *StratusRedTeamDetonator) String() string {
	return fmt.Sprintf("Stratus Red Team attack technique %s", m.AttackTechnique.ID)
}
