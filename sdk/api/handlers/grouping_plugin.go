package handlers

import (
	"errors"
	"net/http"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/interfaces"
)

func groupingPluginExecutorDenied() *interfaces.ErrorMessage {
	return &interfaces.ErrorMessage{
		StatusCode: http.StatusForbidden,
		Error:      errors.New("direct plugin executor cannot verify credential ownership while grouping is enabled"),
	}
}
