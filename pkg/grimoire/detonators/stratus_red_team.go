package detonators

import (
	"fmt"
	"github.com/datadog/grimoire/pkg/grimoire/common"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	_ "github.com/datadog/stratus-red-team/v2/pkg/stratus/loader"
	stratusrunner "github.com/datadog/stratus-red-team/v2/pkg/stratus/runner"
)

type StratusRedTeamDetonator struct {
	AttackTechnique *stratus.AttackTechnique
	StratusRunner   stratusrunner.Runner
}

func NewStratusRedTeamDetonator(ttp string) *StratusRedTeamDetonator {
	return &StratusRedTeamDetonator{
		AttackTechnique: stratus.GetRegistry().GetAttackTechniqueByName(ttp),
	}
}

func (m *StratusRedTeamDetonator) Detonate() (grimoire.DetonationID, error) {
	ttp := m.AttackTechnique
	m.StratusRunner = stratusrunner.NewRunner(ttp, stratusrunner.StratusRunnerNoForce)

	if _, err := m.StratusRunner.WarmUp(); err != nil {
		return "", fmt.Errorf("error warming up Stratus Red Team attack technique %s: %w", ttp, err)
	}
	if err := m.StratusRunner.Detonate(); err != nil {
		return "", fmt.Errorf("error detonating Stratus Red Team attack technique %s: %w", ttp, err)
	}

	detonationId := fmt.Sprintf("stratus-red-team_%s", m.StratusRunner.GetUniqueExecutionId())
	return grimoire.DetonationID(detonationId), nil
}

func (m *StratusRedTeamDetonator) CleanUp() error {
	return m.StratusRunner.CleanUp()
}

func (m *StratusRedTeamDetonator) String() string {
	return fmt.Sprintf("Stratus Red Team attack technique %s", m.AttackTechnique.ID)
}
