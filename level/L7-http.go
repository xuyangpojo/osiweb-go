package level

type HTTPRequest struct {
	// 请求行
	Line HTTPRequestLine
	// 请求头
	Header map[string]string
	// 请求体
	Body string
}

type HTTPRequestLine struct {
	// 请求方法
	Method string
	// URL路径
	URL URL
	// 协议版本
	HTTPVersion string
}

func (httpRequestLine *HTTPRequestLine) checkMethos() bool {
	methods := []string{
		"GET",
		"POST",
		"PUT",
		"DELETE",
		"HEAD", // 只返回HTTP头部
		"CONNECT",
		"OPTIONS",
		"TRACE",
	}
	for _, method := range methods {
		if method == httpRequestLine.Method {
			return true
		}
	}
	return false
}

type URL struct {
	// 协议
	Protocol string
	// 主机
	Host string
	// 端口
	Pod int
	// 路径
	Path string
}

func (httpRequest *HTTPRequest) checkHeaders1() bool {
	headerKey := []string{
		"Host",            // 主机的IP地址或域名
		"User-Agent",      // 客户端信息(发出请求的应用程序)
		"Accept",          // 客户端可接受的信息类型
		"Accept-Charset",  // 客户端可接受的字符集
		"Accept-Language", // 客户端可接受的语言
		"Authorization",   // 权限认证信息
		"Cookie",          // Cookie信息
		"Referer",         // 当前URL
		"Content-Type",    // 请求体内容类型
		"Content-Length",  // 请求体数据长度
	}
	a, b := 0, 0
	for k, _ := range httpRequest.Header {
		a++
		for _, ele := range headerKey {
			if k == ele {
				b++
			}
		}
	}
	return a == b
}

type HTTPResponse struct {
	// 状态行
	Line HTTPResponseLine
	// 响应头
	Header map[string]string
	// 响应体
	Body string
}

// 状态行
type HTTPResponseLine struct {
	// 协议版本
	HTTPVersion string
	// 状态码
	StatusCode int
	// 状态码描述
	StatusString string
}

func (line *HTTPResponseLine) checkStatus() bool {
	status := map[int]string{
		100: "Continue",
		200: "OK",
		301: "Moved Permanently",
		400: "Bad Request",
		401: "Unauthorized",
		403: "Forbidden",
		404: "Not Found",
		500: "Internel Server Error",
	}
	for k, v := range status {
		if k == line.StatusCode && v == line.StatusString {
			return true
		}
	}
	return false
}

func (httpResponse *HTTPResponse) checkHeaders2() bool {
	headerKey := []string{
		"Server",         // 服务器信息
		"Date",           // 响应报文时间
		"Expires",        // 指定缓存过期时间
		"Last-Modified",  // 资源最后修改时间
		"Set-Cookie",     // 设置Cookie
		"Content-Type",   // 响应类型
		"Content-Length", // 响应长度
		"Connection",     // 连接设计
		"Location",       // 重定向位置
	}
	a, b := 0, 0
	for k, _ := range httpResponse.Header {
		a++
		for _, ele := range headerKey {
			if k == ele {
				b++
			}
		}
	}
	return a == b
}
