package level

import (
	"encoding/binary"
	"hash/crc32"
)

// Ethernet2 以太网帧
// @author xuyang
// @datetime 2025/6/27 8:00
type Ethernet2 struct {
	// 目的MAC地址
	DMacAddress [6]byte
	// 源MAC地址
	SMacAddress [6]byte
	// 上层协议类型
	ProtocolType [2]byte
	// 数据包
	DataPackage []byte
	// CRC校验和
	CRCCheckSum [4]byte
}

// const 以太网帧常量
// @author xuyang
// @datetime 2025/6/27 8:00
const (
	MinDataSize        = 46   // 最小数据包大小
	MaxDataSize        = 1500 // 最大数据包大小
	EthernetHeaderSize = 14   // 以太网头部大小
)

// getProtocolTypeBytes 根据协议类型字符串返回对应的字节数组
// @param protocolTypeStr 协议类型字符串
// @return [2]byte 协议类型的字节表示
func getProtocolTypeBytes(protocolTypeStr string) [2]byte {
	switch protocolTypeStr {
	case "IP":
		return [2]byte{0x08, 0x00}
	case "ARP":
		return [2]byte{0x08, 0x06}
	case "IPv6":
		return [2]byte{0x86, 0xDD}
	case "NDP":
		return [2]byte{0x86, 0xDD}
	case "ICMP":
		return [2]byte{0x08, 0x00}
	default:
		return [2]byte{0x00, 0x00}
	}
}

// NewEthernet2 新建以太网帧
// @author xuyang
// @datetime 2025/6/27 8:00
// @param destMac 目的MAC地址
// @param srcMac 源MAC地址
// @param protocolType 上层协议类型
// @param data 数据包内容
// @return *Ethernet2 生成的以太网帧
func NewEthernet2(dMacAddress, sMacAddress [6]byte, protocolTypeS string,
	data []byte) *Ethernet2 {
	// 数据包大小限制
	dataSize := len(data)
	if dataSize < MinDataSize {
		// 如果数据包太小 -> 用零填充到最小大小
		// panic("以太网帧数据包过小!")
		paddedData := make([]byte, MinDataSize)
		copy(paddedData, data)
		data = paddedData
	} else if dataSize > MaxDataSize {
		// 如果数据包太大 -> 截断到最大大小
		// panic("以太网帧数据包过大!")
		data = data[:MaxDataSize]
	}
	protocolType := getProtocolTypeBytes(protocolTypeS)
	frame := &Ethernet2{
		DMacAddress:  dMacAddress,
		SMacAddress:  sMacAddress,
		ProtocolType: protocolType,
		DataPackage:  data,
	}
	frame.generateCRC()
	return frame
}

// Serialize 将以太网帧序列化为[]byte
// @return []byte 序列化后的字节数组
func (e *Ethernet2) Serialize() []byte {
	// 计算总长度：头部(14字节) + 数据包长度 + CRC(4字节)
	totalSize := EthernetHeaderSize + len(e.DataPackage) + 4
	result := make([]byte, totalSize)

	offset := 0

	// 复制目的MAC地址
	copy(result[offset:], e.DMacAddress[:])
	offset += 6

	// 复制源MAC地址
	copy(result[offset:], e.SMacAddress[:])
	offset += 6

	// 复制协议类型
	copy(result[offset:], e.ProtocolType[:])
	offset += 2

	// 复制数据包
	copy(result[offset:], e.DataPackage)
	offset += len(e.DataPackage)

	// 复制CRC校验和
	copy(result[offset:], e.CRCCheckSum[:])

	return result
}

// Deserialize 将[]byte反序列化为以太网帧
// @param data 要反序列化的字节数组
// @return *Ethernet2 反序列化后的以太网帧，如果失败返回nil
func Deserialize(data []byte) *Ethernet2 {
	// 检查数据长度是否足够
	if len(data) < EthernetHeaderSize+4 {
		return nil
	}

	frame := &Ethernet2{}
	offset := 0

	// 解析目的MAC地址
	copy(frame.DMacAddress[:], data[offset:offset+6])
	offset += 6

	// 解析源MAC地址
	copy(frame.SMacAddress[:], data[offset:offset+6])
	offset += 6

	// 解析协议类型
	copy(frame.ProtocolType[:], data[offset:offset+2])
	offset += 2

	// 解析数据包（除去CRC的剩余部分）
	dataSize := len(data) - EthernetHeaderSize - 4
	if dataSize > 0 {
		frame.DataPackage = make([]byte, dataSize)
		copy(frame.DataPackage, data[offset:offset+dataSize])
		offset += dataSize
	}

	// 解析CRC校验和
	copy(frame.CRCCheckSum[:], data[offset:offset+4])

	return frame
}

// ValidateCRC 检测以太网帧的CRC校验和是否正确
// @return bool 如果CRC正确返回true，否则返回false
func (e *Ethernet2) ValidateCRC() bool {
	// 计算当前数据的CRC
	calculatedCRC := e.calculateCRC()

	// 比较计算出的CRC和存储的CRC
	return calculatedCRC == e.CRCCheckSum
}

// generateCRC 生成CRC校验和
func (e *Ethernet2) generateCRC() {
	e.CRCCheckSum = e.calculateCRC()
}

// calculateCRC 计算CRC校验和
// @return [4]byte 计算出的CRC校验和
func (e *Ethernet2) calculateCRC() [4]byte {
	// 创建用于CRC计算的数据（不包括CRC字段本身）
	crcData := make([]byte, EthernetHeaderSize+len(e.DataPackage))

	offset := 0

	// 复制目的MAC地址
	copy(crcData[offset:], e.DMacAddress[:])
	offset += 6

	// 复制源MAC地址
	copy(crcData[offset:], e.SMacAddress[:])
	offset += 6

	// 复制协议类型
	copy(crcData[offset:], e.ProtocolType[:])
	offset += 2

	// 复制数据包
	copy(crcData[offset:], e.DataPackage)

	// 使用CRC32计算校验和
	crc := crc32.ChecksumIEEE(crcData)

	var result [4]byte
	binary.BigEndian.PutUint32(result[:], crc)

	return result
}
