package level

type IP struct {
	// IPv版本
	Version byte // 4bit
	// 头部长度 20~40
	HeaderLength byte // 4bit
	// 服务类型
	TypeOfService byte
	// 总长度
	TotalLength [2]byte
	// 标识
	Identification [2]byte
	// 标志位
	Flag1 bool
	Flag2 bool
	Flag3 bool
	// 片偏移
	FragmentOffset [2]byte // 12bit
	// 生存时间
	TimeToLive [1]byte
	// 上层协议类型
	Protocol byte
	// 首部校验和
	HeaderChecksum [2]byte
	// 源IP地址
	SourceIPAddress [4]byte
	// 目的IP地址
	DestinationIPAddress [4]byte
	// 可选项
	Options []byte
	// 可填充
	Padding []byte
}
