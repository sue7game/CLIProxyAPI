package cliproxy

import (
	"github.com/router-for-me/CLIProxyAPI/v8/internal/watcher/synthesizer"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

func synthesizeGroupingConfigInventory(ctx *synthesizer.SynthesisContext) ([]*coreauth.Auth, error) {
	if ctx == nil || ctx.Config == nil {
		return synthesizer.NewConfigSynthesizer().Synthesize(ctx)
	}
	local := *ctx
	if local.IDGenerator == nil {
		local.IDGenerator = synthesizer.NewStableIDGenerator()
	}
	synth := synthesizer.NewConfigSynthesizer()
	auths, err := synth.Synthesize(&local)
	if err != nil {
		return nil, err
	}
	disabledConfig := disabledGroupingInventoryConfig(local.Config)
	if disabledConfig == nil {
		return auths, nil
	}
	// Append disabled sources using the same generator so duplicate records cannot
	// shift enabled runtime IDs or reuse another inventory entry's runtime ID.
	local.Config = disabledConfig
	disabled, err := synth.Synthesize(&local)
	if err != nil {
		return nil, err
	}
	for _, auth := range disabled {
		auth.Disabled = true
		auth.Status = coreauth.StatusDisabled
	}
	return append(auths, disabled...), nil
}

func disabledGroupingInventoryConfig(cfg *config.Config) *config.Config {
	compat := append([]config.OpenAICompatibility(nil), cfg.OpenAICompatibility...)
	hasDisabled := false
	for index := range compat {
		hasDisabled = hasDisabled || compat[index].Disabled
		compat[index].Disabled = !compat[index].Disabled
	}
	if !hasDisabled {
		return nil
	}
	// Preserve source indices while synthesizing only the originally disabled list.
	return &config.Config{OpenAICompatibility: compat}
}
