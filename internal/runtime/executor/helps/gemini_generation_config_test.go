package helps

import (
	"testing"

	"github.com/tidwall/gjson"
)

func TestNormalizeGeminiCandidateCount(t *testing.T) {
	tests := []struct {
		name string
		body string
		path string
		want int64
	}{
		{name: "lower bound", body: `{"generationConfig":{"candidateCount":0}}`, path: "generationConfig.candidateCount", want: 1},
		{name: "multiple candidates", body: `{"generationConfig":{"candidateCount":2}}`, path: "generationConfig.candidateCount", want: 1},
		{name: "interactions", body: `{"generation_config":{"candidate_count":-3}}`, path: "generation_config.candidate_count", want: 1},
		{name: "antigravity wrapper", body: `{"request":{"generationConfig":{"candidateCount":9}}}`, path: "request.generationConfig.candidateCount", want: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeGeminiCandidateCount([]byte(tt.body))
			if value := gjson.GetBytes(got, tt.path).Int(); value != tt.want {
				t.Fatalf("candidate count = %d, want %d; body=%s", value, tt.want, got)
			}
		})
	}
}

func TestNormalizeGeminiCandidateCountLeavesValidAndAbsentValues(t *testing.T) {
	valid := NormalizeGeminiCandidateCount([]byte(`{"generationConfig":{"candidateCount":1}}`))
	if got := gjson.GetBytes(valid, "generationConfig.candidateCount").Int(); got != 1 {
		t.Fatalf("candidate count = %d, want 1", got)
	}
	absent := NormalizeGeminiCandidateCount([]byte(`{"contents":[]}`))
	if gjson.GetBytes(absent, "generationConfig.candidateCount").Exists() {
		t.Fatal("absent candidate count was added")
	}
}
