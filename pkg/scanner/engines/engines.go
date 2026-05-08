package engines

import (
	"context"

	"github.com/chainreactors/aiscan/pkg/scanner/resources"
	"github.com/chainreactors/aiscan/pkg/telemetry"
	sdkfingers "github.com/chainreactors/sdk/fingers"
	"github.com/chainreactors/sdk/gogo"
	"github.com/chainreactors/sdk/neutron"
	"github.com/chainreactors/sdk/pkg/association"
	"github.com/chainreactors/sdk/spray"
	sdkzombie "github.com/chainreactors/sdk/zombie"
)

type Set struct {
	Fingers   *sdkfingers.Engine
	Gogo      *gogo.GogoEngine
	Spray     *spray.SprayEngine
	Neutron   *neutron.Engine
	Zombie    *sdkzombie.Engine
	Index     *association.FingerPOCIndex
	Resources *resources.Set
}

// CapacityConfig holds per-engine capacity limits. Zero means unlimited.
type CapacityConfig struct {
	Gogo    int // total concurrent scan threads (default: 5000)
	Spray   int // total concurrent HTTP threads (default: 200)
	Zombie  int // total concurrent auth threads (default: 500)
	Neutron int // total concurrent template executions (default: 10)
}

// DefaultCapacity returns sensible capacity defaults.
func DefaultCapacity() CapacityConfig {
	return CapacityConfig{
		Gogo:    5000,
		Spray:   200,
		Zombie:  500,
		Neutron: 10,
	}
}

func (e *Set) Close() {
	if e.Fingers != nil {
		e.Fingers.Close()
	}
	if e.Gogo != nil {
		e.Gogo.Close()
	}
	if e.Spray != nil {
		e.Spray.Close()
	}
	if e.Neutron != nil {
		e.Neutron.Close()
	}
	if e.Zombie != nil {
		e.Zombie.Close()
	}
}

func Init(ctx context.Context, cyberhubURL, apiKey string) (*Set, error) {
	return InitWithLogger(ctx, cyberhubURL, apiKey, telemetry.NopLogger())
}

func InitWithLogger(ctx context.Context, cyberhubURL, apiKey string, logger telemetry.Logger) (*Set, error) {
	return InitWithOptions(ctx, resources.Options{
		CyberhubURL: cyberhubURL,
		APIKey:      apiKey,
		Mode:        resources.ModeMerge,
	}, logger)
}

func InitWithOptions(ctx context.Context, opts resources.Options, logger telemetry.Logger) (*Set, error) {
	return InitWithCapacity(ctx, opts, DefaultCapacity(), logger)
}

func InitWithCapacity(ctx context.Context, opts resources.Options, caps CapacityConfig, logger telemetry.Logger) (*Set, error) {
	if logger == nil {
		logger = telemetry.NopLogger()
	}
	set := &Set{}

	resourceSet, err := resources.Init(ctx, opts)
	if err != nil {
		return nil, err
	}
	set.Resources = resourceSet
	if resourceSet.RemoteEnabled {
		logger.Infof("cyberhub resources loaded mode=%s fingers=%d neutron=%d", resourceSet.Mode, resourceSet.RemoteFingers, resourceSet.RemoteNeutron)
		if resourceSet.RemoteFingersErr != nil {
			logger.Warnf("load cyberhub fingers failed: %v, using local resources", resourceSet.RemoteFingersErr)
		} else if resourceSet.RemoteFingers == 0 {
			logger.Warnf("cyberhub returned no fingers, using local resources")
		}
		if resourceSet.RemoteNeutronErr != nil {
			logger.Warnf("load cyberhub neutron templates failed: %v, using local resources", resourceSet.RemoteNeutronErr)
		} else if resourceSet.RemoteNeutron == 0 {
			logger.Warnf("cyberhub returned no neutron templates, using local resources")
		}
	}

	fEngine := resourceSet.Fingers
	if fEngine == nil {
		logger.Warnf("fingers engine has no templates, continuing without fingers")
	} else if fEngine.Count() > 0 {
		set.Fingers = fEngine
		logger.Infof("fingers engine initialized with %d templates", fEngine.Count())
	} else {
		logger.Warnf("fingers engine has no templates, continuing without fingers")
		_ = fEngine.Close()
	}

	nEngine := resourceSet.Neutron
	if nEngine != nil && nEngine.Count() > 0 {
		set.Neutron = nEngine
		logger.Infof("neutron engine initialized with %d templates", nEngine.Count())
	} else {
		logger.Warnf("neutron engine has no templates, continuing without neutron")
		if nEngine != nil {
			_ = nEngine.Close()
		}
	}

	if set.Neutron != nil {
		set.Index = association.NewFingerPOCIndex()
		set.Index.BuildFromTemplates(set.Neutron.Get())
		fingerCount, pocCount := set.Index.Count()
		logger.Infof("finger-poc index built: %d fingers, %d pocs", fingerCount, pocCount)
	}

	gogoConfig := gogo.NewConfig()
	gogoConfig.WithResourceProvider(resourceSet.GogoConfig)
	if set.Fingers != nil {
		gogoConfig.WithFingersEngine(set.Fingers)
	}
	if set.Neutron != nil {
		gogoConfig.WithNeutronEngine(set.Neutron)
	}
	if caps.Gogo > 0 {
		gogoConfig.WithCapacity(caps.Gogo)
	}
	set.Gogo = gogo.NewEngine(gogoConfig)
	logger.Infof("gogo engine initialized")

	sprayConfig := spray.NewConfig()
	sprayConfig.WithResourceProvider(resourceSet.SprayConfig)
	if set.Fingers != nil {
		sprayConfig.WithFingersEngine(set.Fingers)
	}
	if caps.Spray > 0 {
		sprayConfig.WithCapacity(caps.Spray)
	}
	set.Spray = spray.NewEngine(sprayConfig)
	logger.Infof("spray engine initialized")

	zombieConfig := sdkzombie.NewConfig()
	if caps.Zombie > 0 {
		zombieConfig.WithCapacity(caps.Zombie)
	}
	set.Zombie = sdkzombie.NewEngine(zombieConfig)
	if err := set.Zombie.Init(); err != nil {
		logger.Warnf("init zombie engine failed: %v, continuing without zombie", err)
		set.Zombie = nil
	} else {
		logger.Infof("zombie engine initialized")
	}

	if set.Neutron != nil && caps.Neutron > 0 {
		set.Neutron.SetCapacity(caps.Neutron)
	}

	return set, nil
}
