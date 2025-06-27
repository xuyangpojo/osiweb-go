package level

// UDP 协议
// @author xuyang
// @datetime 2025/6/27 12:00
type UDP struct {
	// TCP头部
	Header UDPHeader
	// 数据
	Data []byte
}

// UDPHeader 协议
// @author xuyang
// @datetime 2025/6/27 12:00
type UDPHeader struct {
	// 源端口
	SourcePort [2]byte
	// 目标端口
	DestinationPort [2]byte
	// Header+Data总长度 8~65535
	Length [2]byte
	// 校验字段
	Checksum [2]byte
}
