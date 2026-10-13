package main

import "fmt"

func (a *application) cleanupDisabledRuntimeLocked() error {
	a.guard.clearAutomaticOverridesLocked()
	a.guard.clearManagedProxiesLocked()
	cooldowns, proxies := 0, 0
	for _, state := range a.store.allSnapshots(a.guard.now()) {
		if state.Cooldown.Active || state.Cooldown.Pending {
			cooldowns++
		}
		if state.ManagedProxy != nil {
			proxies++
		}
	}
	if cooldowns != 0 || proxies != 0 {
		return fmt.Errorf("runtime cleanup incomplete: %d cooldowns and %d managed proxies remain; retry deactivation", cooldowns, proxies)
	}
	return nil
}
