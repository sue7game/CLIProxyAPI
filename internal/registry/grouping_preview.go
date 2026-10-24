package registry

import "sort"

// ModelIDsForClients captures the registered public IDs in one registry snapshot.
// It ignores transient cooldowns and never includes another client's models.
func (r *ModelRegistry) ModelIDsForClients(clientIDs []string) map[string][]string {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	out := make(map[string][]string, len(clientIDs))
	for _, clientID := range clientIDs {
		seen := make(map[string]bool)
		ids := make([]string, 0, len(r.clientModels[clientID]))
		for _, id := range r.clientModels[clientID] {
			if seen[id] || r.clientModelInfos[clientID][id] == nil {
				continue
			}
			seen[id] = true
			ids = append(ids, id)
		}
		sort.Strings(ids)
		out[clientID] = ids
	}
	return out
}
