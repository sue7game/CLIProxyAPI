package synthesizer

func addGroupingIDToAttrs(id string, attrs map[string]string) {
	if id != "" {
		attrs["grouping_id"] = id
	}
}
