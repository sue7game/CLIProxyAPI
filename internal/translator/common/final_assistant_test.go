package common

import (
	"testing"

	"github.com/tidwall/gjson"
)

func TestSanitizeFinalAssistantMessageText_TrimsOnlyFinalAssistantString(t *testing.T) {
	input := []byte(`{"messages":[{"role":"assistant","content":"keep \n"},{"role":"user","content":"question "},{"role":"assistant","content":"prefill \n"}]}`)

	got := SanitizeFinalAssistantMessageText(input)

	if text := gjson.GetBytes(got, "messages.0.content").String(); text != "keep \n" {
		t.Fatalf("non-final assistant content changed: %q", text)
	}
	if text := gjson.GetBytes(got, "messages.1.content").String(); text != "question " {
		t.Fatalf("user content changed: %q", text)
	}
	if text := gjson.GetBytes(got, "messages.2.content").String(); text != "prefill" {
		t.Fatalf("final assistant content = %q, want prefill", text)
	}
}

func TestSanitizeFinalAssistantMessageText_TrimsOnlyFinalTextPart(t *testing.T) {
	input := []byte(`{"messages":[{"role":"assistant","content":[{"type":"thinking","thinking":"keep "},{"type":"text","text":"answer \t\n"}]}]}`)

	got := SanitizeFinalAssistantMessageText(input)

	if text := gjson.GetBytes(got, "messages.0.content.0.thinking").String(); text != "keep " {
		t.Fatalf("thinking content changed: %q", text)
	}
	if text := gjson.GetBytes(got, "messages.0.content.1.text").String(); text != "answer" {
		t.Fatalf("final text part = %q, want answer", text)
	}
}

func TestSanitizeFinalAssistantMessageText_TrimsRevealedPreviousTextPart(t *testing.T) {
	input := []byte(`{"messages":[{"role":"assistant","content":[{"type":"text","text":"answer \n"},{"type":"text","text":"  \t"}]}]}`)

	got := SanitizeFinalAssistantMessageText(input)

	parts := gjson.GetBytes(got, "messages.0.content").Array()
	if len(parts) != 1 {
		t.Fatalf("content parts length = %d, want 1: %s", len(parts), got)
	}
	if text := parts[0].Get("text").String(); text != "answer" {
		t.Fatalf("remaining text part = %q, want answer", text)
	}
}

func TestSanitizeFinalAssistantMessageText_DoesNotTrimTextBeforeNonTextFinalPart(t *testing.T) {
	input := []byte(`{"messages":[{"role":"assistant","content":[{"type":"text","text":"keep \n"},{"type":"tool_use","id":"toolu_1","name":"run","input":{}}]}]}`)

	got := SanitizeFinalAssistantMessageText(input)

	if string(got) != string(input) {
		t.Fatalf("text before non-text final part changed: %s", got)
	}
}

func TestSanitizeFinalAssistantMessageText_PreservesAssistantSidePayload(t *testing.T) {
	input := []byte(`{"messages":[{"role":"assistant","content":"  \n","tool_calls":[{"id":"call_1","type":"function","function":{"name":"run","arguments":"{}"}}]}]}`)

	got := SanitizeFinalAssistantMessageText(input)

	messages := gjson.GetBytes(got, "messages").Array()
	if len(messages) != 1 {
		t.Fatalf("messages length = %d, want 1: %s", len(messages), got)
	}
	if !messages[0].Get("tool_calls").Exists() {
		t.Fatalf("tool_calls were removed: %s", got)
	}
	if text := messages[0].Get("content").String(); text != "" {
		t.Fatalf("content = %q, want empty string", text)
	}
}

func TestSanitizeFinalAssistantMessageText_DropsWhitespaceOnlyAssistant(t *testing.T) {
	input := []byte(`{"messages":[{"role":"user","content":"hi"},{"role":"assistant","content":"  \n"}]}`)

	got := SanitizeFinalAssistantMessageText(input)

	messages := gjson.GetBytes(got, "messages").Array()
	if len(messages) != 1 {
		t.Fatalf("messages length = %d, want 1: %s", len(messages), got)
	}
	if role := messages[0].Get("role").String(); role != "user" {
		t.Fatalf("remaining role = %q, want user", role)
	}
}
