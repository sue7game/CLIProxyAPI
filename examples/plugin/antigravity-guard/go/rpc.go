package main

import (
	"encoding/json"
	"fmt"
	"sync/atomic"
)

const (
	methodHostAuthList               = "host.auth.list"
	methodHostAuthSetRuntimeOverride = "host.auth.set_runtime_override"
	methodHostAuthRequest            = "host.auth.request"
)

type hostClient interface {
	ListAuths() ([]hostAuthEntry, error)
	SetRuntimeOverride(request runtimeOverrideRequest) (runtimeOverrideResponse, error)
	Request(request hostAuthRequest) (hostAuthResponse, error)
}

type hostRPCClient struct {
	maintenance *atomic.Pointer[string]
	callbackID  *string
	transport   func(string, []byte) ([]byte, int, error)
}

func newHostRPCClient() *hostRPCClient {
	return &hostRPCClient{maintenance: &atomic.Pointer[string]{}, transport: callHostABI}
}

func (c *hostRPCClient) ListAuths() ([]hostAuthEntry, error) {
	var response authListResponse
	if errCall := c.call(methodHostAuthList, map[string]string{"host_callback_id": c.hostCallbackID()}, &response); errCall != nil {
		return nil, errCall
	}
	return response.Files, nil
}

func (c *hostRPCClient) SetRuntimeOverride(request runtimeOverrideRequest) (runtimeOverrideResponse, error) {
	request.HostCallbackID = c.requestCallbackID(request.HostCallbackID)
	var response runtimeOverrideResponse
	if errCall := c.call(methodHostAuthSetRuntimeOverride, request, &response); errCall != nil {
		return runtimeOverrideResponse{}, errCall
	}
	return response, nil
}

func (c *hostRPCClient) Request(request hostAuthRequest) (hostAuthResponse, error) {
	request.HostCallbackID = c.requestCallbackID(request.HostCallbackID)
	var response hostAuthResponse
	if errCall := c.call(methodHostAuthRequest, request, &response); errCall != nil {
		return hostAuthResponse{}, errCall
	}
	return response, nil
}

func (c *hostRPCClient) call(method string, payload any, output any) error {
	rawPayload, errMarshal := json.Marshal(payload)
	if errMarshal != nil {
		return fmt.Errorf("marshal host callback %s: %w", method, errMarshal)
	}
	rawResponse, code, errCall := c.transport(method, rawPayload)
	if errCall != nil {
		return errCall
	}
	if len(rawResponse) == 0 {
		return fmt.Errorf("host callback %s returned no response, code=%d", method, code)
	}

	var responseEnvelope envelope
	if errDecode := json.Unmarshal(rawResponse, &responseEnvelope); errDecode != nil {
		return fmt.Errorf("decode host callback envelope %s: %w", method, errDecode)
	}
	if !responseEnvelope.OK {
		return hostEnvelopeError(method, responseEnvelope.Error)
	}
	if code != 0 {
		return fmt.Errorf("host callback %s returned code=%d", method, code)
	}
	if output == nil || len(responseEnvelope.Result) == 0 {
		return nil
	}
	if errDecode := json.Unmarshal(responseEnvelope.Result, output); errDecode != nil {
		return fmt.Errorf("decode host callback result %s: %w", method, errDecode)
	}
	return nil
}

func hostEnvelopeError(method string, envelopeError *envelopeError) error {
	if envelopeError == nil {
		return fmt.Errorf("host callback %s failed", method)
	}
	return fmt.Errorf("%s: %s", envelopeError.Code, envelopeError.Message)
}
