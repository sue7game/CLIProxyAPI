package chat_completions

import (
	"testing"

	"github.com/tidwall/gjson"
)

func TestConvertOpenAIRequestToAntigravityTrimsFinalAssistantTrailingWhitespace(t *testing.T) {
	inputJSON := `{
		"model": "claude-sonnet-4-6",
		"messages": [
			{"role": "user", "content": "Hello"},
			{"role": "assistant", "content": "partial answer \n"}
		]
	}`

	result := ConvertOpenAIRequestToAntigravity("claude-sonnet-4-6", []byte(inputJSON), false)

	if got := gjson.GetBytes(result, "request.contents.1.parts.0.text").String(); got != "partial answer" {
		t.Fatalf("final assistant text = %q, want partial answer. Output: %s", got, result)
	}
}

func TestConvertOpenAIRequestToAntigravityDoesNotTrimNonFinalAssistant(t *testing.T) {
	inputJSON := `{
		"model": "claude-sonnet-4-6",
		"messages": [
			{"role": "assistant", "content": "keep trailing \n"},
			{"role": "user", "content": "next"}
		]
	}`

	result := ConvertOpenAIRequestToAntigravity("claude-sonnet-4-6", []byte(inputJSON), false)

	if got := gjson.GetBytes(result, "request.contents.0.parts.0.text").String(); got != "keep trailing \n" {
		t.Fatalf("non-final assistant text = %q, want preserved trailing newline. Output: %s", got, result)
	}
}

func TestConvertOpenAIRequestToAntigravitySkipsEmptyTextPartsWithoutNulls(t *testing.T) {
	inputJSON := `{
		"model": "gemini-3-flash",
		"messages": [
			{
				"role": "user",
				"content": [
					{"type": "text", "text": ""},
					{"type": "input_audio", "input_audio": {"data": "SUQzBA==", "format": "mp3"}}
				]
			},
			{
				"role": "assistant",
				"content": [{"type": "text", "text": ""}],
				"tool_calls": [{
					"id": "call_1",
					"type": "function",
					"function": {"name": "read_file", "arguments": "{\"path\":\"a.txt\"}"}
				}]
			},
			{"role": "tool", "tool_call_id": "call_1", "content": "{\"output\":\"ok\"}"},
			{"role": "user", "content": "done"}
		]
	}`

	result := ConvertOpenAIRequestToAntigravity("gemini-3-flash", []byte(inputJSON), false)
	userParts := gjson.GetBytes(result, "request.contents.0.parts").Array()
	if len(userParts) != 1 {
		t.Fatalf("user parts length = %d, want 1. Output: %s", len(userParts), result)
	}
	if userParts[0].Type == gjson.Null {
		t.Fatalf("user parts.0 is null. Output: %s", result)
	}
	if got := userParts[0].Get("inlineData.mime_type").String(); got != "audio/mpeg" {
		t.Fatalf("audio mime_type = %q, want audio/mpeg. Output: %s", got, result)
	}

	assistantParts := gjson.GetBytes(result, "request.contents.1.parts").Array()
	if len(assistantParts) != 1 {
		t.Fatalf("assistant parts length = %d, want 1. Output: %s", len(assistantParts), result)
	}
	if assistantParts[0].Type == gjson.Null {
		t.Fatalf("assistant parts.0 is null. Output: %s", result)
	}
	if !assistantParts[0].Get("functionCall").Exists() {
		t.Fatalf("functionCall missing. Output: %s", result)
	}
}
