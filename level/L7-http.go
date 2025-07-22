package level

import (
	"errors"
	"strings"
)

// HTTP 报文结构体
// HTTP Packet Structure
// @author xuyang
// @datetime 2025/6/27 14:35
// [起始行][首部][空行][正文]
type HTTPPacket struct {
	// 起始行 Start Line (如 GET /index.html HTTP/1.1)
	StartLine string
	// 首部 Headers (多行)
	Headers map[string]string
	// 正文 Body (可选)
	Body string
}

// NewHTTPPacket 新建 HTTP 报文
// New HTTP Packet
func NewHTTPPacket(startLine string, headers map[string]string, body string) *HTTPPacket {
	return &HTTPPacket{
		StartLine: startLine,
		Headers:   headers,
		Body:      body,
	}
}

// Serialize 序列化 HTTP 报文为字节数组
// Serialize HTTP packet to []byte
func (http *HTTPPacket) Serialize() []byte {
	lines := []string{http.StartLine}
	for k, v := range http.Headers {
		lines = append(lines, k+": "+v)
	}
	lines = append(lines, "") // 空行
	if http.Body != "" {
		lines = append(lines, http.Body)
	}
	return []byte(strings.Join(lines, "\r\n"))
}

// Deserialize 反序列化字节数组为 HTTP 报文
// Deserialize []byte to HTTP packet
func DeserializeHTTPPacket(data []byte) (*HTTPPacket, error) {
	text := string(data)
	parts := strings.SplitN(text, "\r\n\r\n", 2)
	if len(parts) < 1 {
		return nil, errors.New("数据格式错误，不是有效的HTTP报文 / Invalid HTTP packet format")
	}
	headersAndStart := strings.Split(parts[0], "\r\n")
	if len(headersAndStart) < 1 {
		return nil, errors.New("缺少起始行 / Missing start line")
	}
	http := &HTTPPacket{
		StartLine: headersAndStart[0],
		Headers:   make(map[string]string),
	}
	for _, line := range headersAndStart[1:] {
		if line == "" {
			break
		}
		if idx := strings.Index(line, ": "); idx >= 0 {
			http.Headers[line[:idx]] = line[idx+2:]
		}
	}
	if len(parts) == 2 {
		http.Body = parts[1]
	}
	return http, nil
}

// IsValid 检查 HTTP 报文是否合法
// Check if HTTP packet is valid
func (http *HTTPPacket) IsValid() bool {
	return http.StartLine != ""
}
