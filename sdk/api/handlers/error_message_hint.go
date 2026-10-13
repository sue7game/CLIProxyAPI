package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

var errorMessageHints = map[int]string{
	http.StatusBadRequest:            "请求格式、参数或上下文不符合要求，或请求内容包含敏感信息",
	http.StatusUnauthorized:          "账号被封了，等我们换号",
	http.StatusPaymentRequired:       "上游要求付费或账号额度不可用",
	http.StatusForbidden:             "账号被封了，等我换号",
	http.StatusNotFound:              "模型、接口或引用的历史响应不存在",
	http.StatusRequestTimeout:        "请求已中断或超时",
	http.StatusConflict:              "请求与当前资源状态冲突",
	http.StatusRequestEntityTooLarge: "输入、上下文或上传内容超过限制",
	http.StatusUnprocessableEntity:   "请求字段或参数值无法处理",
	http.StatusUpgradeRequired:       "当前连接需要协议升级",
	http.StatusTooManyRequests:       "请求内容不符合要求或内容中敏感信息，请调整，不要一直重试",
	499:                              "客户端已主动断开连接",
	http.StatusInternalServerError:   "网络错误，请重试",
	http.StatusNotImplemented:        "当前接口未实现或不支持",
	http.StatusBadGateway:            "网络错误，请重试",
	http.StatusServiceUnavailable:    "账号暂时不可用，等我们处理好",
	http.StatusGatewayTimeout:        "上游请求超时，请稍后重试",
}

// AppendErrorMessageHint appends the configured status hint to existing JSON error messages.
// It leaves bodies without a string message field unchanged.
func AppendErrorMessageHint(status int, body []byte) []byte {
	return appendErrorMessageHint(status, body)
}

func appendErrorMessageHint(status int, body []byte) []byte {
	hint := strings.TrimSpace(errorMessageHints[status])
	if hint == "" || !json.Valid(body) {
		return body
	}
	for _, path := range []string{"error.message", "response.error.message", "message"} {
		message := gjson.GetBytes(body, path)
		if !message.Exists() || message.Type != gjson.String {
			continue
		}
		text := strings.TrimSpace(message.String())
		if text == "" || strings.Contains(text, hint) {
			return body
		}
		updated, errSet := sjson.SetBytes(body, path, text+"\n"+hint)
		if errSet == nil {
			return updated
		}
		return body
	}
	return body
}
