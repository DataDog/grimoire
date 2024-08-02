package detonators

import (
	"fmt"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	_ "github.com/datadog/stratus-red-team/v2/pkg/stratus/loader"
	stratusrunner "github.com/datadog/stratus-red-team/v2/pkg/stratus/runner"
	log "github.com/sirupsen/logrus"
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
		//lint:ignore ST1005 "Stratus Red Team" is a proper noun
		return nil, fmt.Errorf("Stratus Red Team attack technique %s not found", attackTechniqueID)
	}
	return &StratusRedTeamDetonator{
		AttackTechnique: ttp,
		StratusRunner:   stratusrunner.NewRunner(ttp, stratusrunner.StratusRunnerForce),
	}, nil
}

func (m *StratusRedTeamDetonator) Detonate() (*DetonationInfo, error) {
	ttp := m.AttackTechnique

	log.Infof("Warming up Stratus Red Team attack technique %s", ttp)
	if _, err := m.StratusRunner.WarmUp(); err != nil {
		return nil, fmt.Errorf("error warming up Stratus Red Team attack technique %s: %w", ttp, err)
	}

	startTime := time.Now()
	log.Infof("Detonating Stratus Red Team attack technique %s", ttp)
	if err := m.StratusRunner.Detonate(); err != nil {
		return nil, fmt.Errorf("error detonating Stratus Red Team attack technique %s: %w", ttp, err)
	}
	endTime := time.Now()

	return &DetonationInfo{
		DetonationID: StratusRedTeamUserAgentPrefix + m.StratusRunner.GetUniqueExecutionId(),
		StartTime:    startTime,
		EndTime:      endTime,
	}, nil
}

func (m *StratusRedTeamDetonator) CleanUp() error {
	return m.StratusRunner.CleanUp()
}

func (m *StratusRedTeamDetonator) GetAttackTechniqueState() stratus.AttackTechniqueState {
	return m.StratusRunner.GetState()
}

func (m *StratusRedTeamDetonator) String() string {
	return fmt.Sprintf("Stratus Red Team attack technique %s", m.AttackTechnique.ID)
}
