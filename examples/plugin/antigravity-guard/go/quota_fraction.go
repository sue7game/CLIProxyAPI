package main

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
)

type quotaFraction struct {
	Value float64
	Valid bool
}

func (f *quotaFraction) UnmarshalJSON(raw []byte) error {
	raw = bytes.TrimSpace(raw)
	if bytes.Equal(raw, []byte("null")) || len(raw) == 0 {
		return nil
	}
	var number float64
	if errNumber := json.Unmarshal(raw, &number); errNumber == nil {
		f.Value = number
		f.Valid = true
		return nil
	}
	var text string
	if errText := json.Unmarshal(raw, &text); errText != nil {
		return errText
	}
	text = strings.TrimSpace(text)
	percent := strings.HasSuffix(text, "%")
	text = strings.TrimSuffix(text, "%")
	value, errParse := strconv.ParseFloat(strings.TrimSpace(text), 64)
	if errParse != nil {
		return errParse
	}
	if percent {
		value /= 100
	}
	f.Value = value
	f.Valid = true
	return nil
}
