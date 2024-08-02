package detonators

import (
	"errors"
	"github.com/datadog/grimoire/pkg/grimoire/detonators/mocks"
	"github.com/datadog/stratus-red-team/v2/pkg/stratus"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestStratusRedTeamDetonate(t *testing.T) {

	type DetonateTestScenario struct {
		Name              string
		WarmUpErrors      bool
		DetonateErrors    bool
		UniqueExecutionID string
		CheckExpectations func(t *testing.T, runner *mocks.StratusRedTeamRunner, detonation *DetonationInfo, err error)
	}

	var scenario = []DetonateTestScenario{
		{
			Name:              "No warmup or detonation error",
			WarmUpErrors:      false,
			DetonateErrors:    false,
			UniqueExecutionID: "unique",
			CheckExpectations: func(t *testing.T, runner *mocks.StratusRedTeamRunner, detonation *DetonationInfo, err error) {
				runner.AssertCalled(t, "WarmUp")
				runner.AssertCalled(t, "Detonate")
				assert.Nil(t, err)
				assert.Contains(t, detonation.DetonationID, "unique")
			},
		},
		{
			Name:              "Warmup error",
			WarmUpErrors:      true,
			DetonateErrors:    false,
			UniqueExecutionID: "unique",
			CheckExpectations: func(t *testing.T, runner *mocks.StratusRedTeamRunner, detonation *DetonationInfo, err error) {
				runner.AssertCalled(t, "WarmUp")
				runner.AssertNotCalled(t, "Detonate")
				assert.NotNil(t, err)
			},
		},
		{
			Name:              "Detonate error",
			WarmUpErrors:      false,
			DetonateErrors:    true,
			UniqueExecutionID: "unique",
			CheckExpectations: func(t *testing.T, runner *mocks.StratusRedTeamRunner, detonation *DetonationInfo, err error) {
				runner.AssertCalled(t, "WarmUp")
				runner.AssertCalled(t, "Detonate")
				assert.NotNil(t, err)

				// For now, this doesn't result in an automated cleanup
				runner.AssertNotCalled(t, "CleanUp")
			},
		},
	}

	for i := range scenario {
		t.Run(scenario[i].Name, func(t *testing.T) {
			runner := new(mocks.StratusRedTeamRunner)
			detonator := StratusRedTeamDetonator{
				AttackTechnique: &stratus.AttackTechnique{ID: "foo"},
				StratusRunner:   runner,
			}

			var warmupErr error
			if scenario[i].WarmUpErrors {
				warmupErr = errors.New("warmup")
			}
			runner.On("WarmUp").Return(map[string]string{}, warmupErr)

			var detonateErr error
			if scenario[i].DetonateErrors {
				detonateErr = errors.New("detonate")
			}
			runner.On("Detonate").Return(detonateErr)

			runner.On("GetUniqueExecutionId").Return(scenario[i].UniqueExecutionID)

			detonation, err := detonator.Detonate()
			scenario[i].CheckExpectations(t, runner, detonation, err)
		})
	}
}
