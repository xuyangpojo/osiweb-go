package level

// ARP (Address Resolution Protocol - IPV4) 由IPv4获取MAC地址的协议
type ARP struct {
	// 下层协议类型
	HardWareType [2]byte
	// 映射协议类型(IPv4)
	ProtocolType [2]byte
	// 硬件地址长度
	HardWareAddressLength [1]byte
	// 协议地址长度
	ProtocolAddressLength [1]byte
	// 操作码
	Opcode [2]byte
	//
}

func getProtocolTypeBytes21(protocolTypeStr string) [2]byte {
	switch protocolTypeStr {
	case "Ethernet2":
		return [2]byte{0x00, 0x01}
	default:
		return [2]byte{0x00, 0x00}
	}
}
func getProtocolTypeBytes22(protocolTypeStr string) [2]byte {
	switch protocolTypeStr {
	case "Ethernet2":
		return [2]byte{0x00, 0x01}
	default:
		return [2]byte{0x00, 0x00}
	}
}
func getProtocolTypeBytes23(protocolTypeStr string) [2]byte {
	switch protocolTypeStr {
	case "Ethernet2":
		return [2]byte{0x00, 0x01}
	default:
		return [2]byte{0x00, 0x00}
	}
}
