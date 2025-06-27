package level

// TCP 协议
// @author xuyang
// @datetime 2025/6/27 12:00
type TCP struct {
	// TCP头部
	Header TCPHeader
	// 数据
	Data []byte
}

// TCPHeader 协议
// @author xuyang
// @datetime 2025/6/27 12:00
type TCPHeader struct {
	// 源端口
	SourcePort [2]byte
	// 目标端口
	DestinationPort [2]byte
	// 序列号
	SequenceNumber [4]byte
	// 确认序列号
	AcknowledgmentNumber [4]byte
	// 头部序号
	HeaderLength [4]byte
	// 保留位
	Reserved [1]byte // 6bit
	// Control bits 控制位
	URG bool // 紧急位
	ACK bool // 确认位
	PSH bool // 推功能
	RST bool // 重制连接
	SYN bool // 同步序列(请求建立连接)
	FIN bool // 请求结束连接
	// 流量窗口
	Window [2]byte
	// 校验字段
	Checksum [2]byte
	// 紧急指针
	Urgent [2]byte
	// 可选项
	Options []byte // 0~40byte
}
