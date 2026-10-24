package management

import "strings"

// configV8ETag renders a config source hash as a strong ETag.
func configV8ETag(hash string) string {
	return `"` + hash + `"`
}

// ifMatchSatisfied reports whether the optional If-Match header lines pass
// the RFC 9110 strong comparison against currentHash. Repeated lines form
// one list. An absent header always passes; a present but blank header
// carries no tag and fails; the whole field "*" matches any current
// version; weak and malformed entity tags never match.
func ifMatchSatisfied(values []string, currentHash string) bool {
	if len(values) == 0 {
		return true
	}
	field := strings.TrimSpace(strings.Join(values, ","))
	if field == "*" {
		return true
	}
	for _, tag := range splitEntityTagList(field) {
		tag = strings.TrimSpace(tag)
		if len(tag) >= 2 && tag[0] == '"' && tag[len(tag)-1] == '"' && !strings.Contains(tag[1:len(tag)-1], `"`) && tag[1:len(tag)-1] == currentHash {
			return true
		}
	}
	return false
}

// splitEntityTagList splits an If-Match field value on list commas. A comma
// inside a quoted entity tag is tag content, not a separator.
func splitEntityTagList(field string) []string {
	parts := []string{}
	start := 0
	quoted := false
	for i := 0; i < len(field); i++ {
		switch field[i] {
		case '"':
			quoted = !quoted
		case ',':
			if !quoted {
				parts = append(parts, field[start:i])
				start = i + 1
			}
		}
	}
	return append(parts, field[start:])
}
