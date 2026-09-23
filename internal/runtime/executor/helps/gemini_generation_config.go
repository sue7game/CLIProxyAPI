package helps

import (
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// NormalizeGeminiCandidateCount normalizes candidate count fields to one.
// Gemini's candidate_count range is 1-8, but multiple candidates are not
// enabled for every model. Using one is the only model-independent setting.
func NormalizeGeminiCandidateCount(payload []byte) []byte {
	if len(payload) == 0 {
		return payload
	}

	paths := []string{
		"generationConfig.candidateCount",
		"generationConfig.candidate_count",
		"generation_config.candidateCount",
		"generation_config.candidate_count",
		"request.generationConfig.candidateCount",
		"request.generationConfig.candidate_count",
		"request.generation_config.candidateCount",
		"request.generation_config.candidate_count",
	}
	for _, path := range paths {
		value := gjson.GetBytes(payload, path)
		if !value.Exists() || value.Type != gjson.Number {
			continue
		}
		if value.Float() == 1 {
			continue
		}
		updated, errSet := sjson.SetBytes(payload, path, 1)
		if errSet == nil {
			payload = updated
		}
	}
	return payload
}
