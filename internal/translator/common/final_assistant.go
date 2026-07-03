package common

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// SanitizeFinalAssistantMessageText removes trailing whitespace from the final
// assistant text prefill. Claude rejects final assistant content that ends with
// whitespace, while non-final history and non-text blocks must remain unchanged.
func SanitizeFinalAssistantMessageText(rawJSON []byte) []byte {
	messages := gjson.GetBytes(rawJSON, "messages")
	if !messages.IsArray() {
		return rawJSON
	}

	messageItems := messages.Array()
	if len(messageItems) == 0 {
		return rawJSON
	}

	messageIndex := len(messageItems) - 1
	message := messageItems[messageIndex]
	if message.Get("role").String() != "assistant" {
		return rawJSON
	}

	content := message.Get("content")
	switch {
	case content.Type == gjson.String:
		return sanitizeFinalAssistantStringContent(rawJSON, messageIndex, message, content.String())
	case content.IsArray():
		return sanitizeFinalAssistantArrayContent(rawJSON, messageIndex, message, content.Array())
	default:
		return rawJSON
	}
}

func sanitizeFinalAssistantStringContent(rawJSON []byte, messageIndex int, message gjson.Result, text string) []byte {
	trimmed := trimRightWhitespace(text)
	if trimmed == text {
		return rawJSON
	}
	if trimmed == "" && !hasAssistantSidePayload(message) {
		return deleteFinalAssistantMessage(rawJSON, messageIndex)
	}
	return setJSONBytes(rawJSON, fmt.Sprintf("messages.%d.content", messageIndex), trimmed)
}

func sanitizeFinalAssistantArrayContent(rawJSON []byte, messageIndex int, message gjson.Result, parts []gjson.Result) []byte {
	if len(parts) == 0 {
		return rawJSON
	}

	out := rawJSON
	remainingParts := len(parts)
	changed := false
	for partIndex := len(parts) - 1; partIndex >= 0; partIndex-- {
		part := parts[partIndex]
		if part.Get("type").String() != "text" {
			break
		}

		textResult := part.Get("text")
		if textResult.Type != gjson.String {
			break
		}

		text := textResult.String()
		trimmed := trimRightWhitespace(text)
		if trimmed == text {
			break
		}

		changed = true
		if trimmed == "" {
			out = deleteJSONPath(out, fmt.Sprintf("messages.%d.content.%d", messageIndex, partIndex))
			remainingParts--
			continue
		}
		out = setJSONBytes(out, fmt.Sprintf("messages.%d.content.%d.text", messageIndex, partIndex), trimmed)
		break
	}

	if !changed {
		return rawJSON
	}
	if remainingParts == 0 && !hasAssistantSidePayload(message) {
		return deleteFinalAssistantMessage(out, messageIndex)
	}
	return out
}

func trimRightWhitespace(text string) string {
	return strings.TrimRightFunc(text, unicode.IsSpace)
}

func hasAssistantSidePayload(message gjson.Result) bool {
	return message.Get("tool_calls").Exists() || message.Get("function_call").Exists()
}

func deleteFinalAssistantMessage(rawJSON []byte, messageIndex int) []byte {
	return deleteJSONPath(rawJSON, fmt.Sprintf("messages.%d", messageIndex))
}

func setJSONBytes(rawJSON []byte, path string, value any) []byte {
	out, err := sjson.SetBytes(rawJSON, path, value)
	if err != nil {
		return rawJSON
	}
	return out
}

func deleteJSONPath(rawJSON []byte, path string) []byte {
	out, err := sjson.DeleteBytes(rawJSON, path)
	if err != nil {
		return rawJSON
	}
	return out
}
