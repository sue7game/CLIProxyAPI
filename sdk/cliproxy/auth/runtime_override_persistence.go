package auth

import "context"

func saveAuthWithoutRuntimeOverride(ctx context.Context, store Store, auth *Auth) error {
	before := auth.Clone()
	saved := auth.Clone()
	saved.runtimeOverride = RuntimeAuthOverride{}
	saved.runtimeOverrideRevisions = RuntimeAuthOverrideRevisions{}
	_, errSave := store.Save(ctx, saved)
	// Preserve Store.Save enrichment without importing process-local routing state.
	mergeAuthSaveDelta(auth, before, saved, true)
	return errSave
}

func (m *Manager) restoreRuntimeAuthOverrideAfterSaveLocked(auth *Auth) {
	if current := m.auths[auth.ID]; current != nil {
		auth.runtimeOverride = current.runtimeOverride.Clone()
		auth.runtimeOverrideRevisions = current.runtimeOverrideRevisions
	}
	m.attachRuntimeAuthOverrideRevisionsLocked(auth)
}
