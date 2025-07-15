package level

import (
	"encoding/binary"
	// "hash/crc32" // 不再需要
)

// Ethernet2 以太网帧
// @author xuyang
// @datetime 2025/6/27 8:00
// [D_MAC][S_MAC][⬆][...DATA...][CheckSum]
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
func getProtocolTypeBytes1(protocolTypeStr string) [2]byte {
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
	protocolType := getProtocolTypeBytes1(protocolTypeS)
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
// @author xuyang
// @datetime 2025/6/27 11:00
// @return []byte 序列化后的字节数组
func (e *Ethernet2) Serialize() []byte {
	totalSize := EthernetHeaderSize + len(e.DataPackage) + 4
	result := make([]byte, totalSize)
	offset := 0
	copy(result[offset:], e.DMacAddress[:])
	offset += 6
	copy(result[offset:], e.SMacAddress[:])
	offset += 6
	copy(result[offset:], e.ProtocolType[:])
	offset += 2
	copy(result[offset:], e.DataPackage)
	offset += len(e.DataPackage)
	copy(result[offset:], e.CRCCheckSum[:])
	return result
}

// Deserialize 将[]byte反序列化为以太网帧
// @author xuyang
// @datetime 2025/6/27 11:00
// @param data 要反序列化的字节数组
// @return *Ethernet2 反序列化后的以太网帧，如果失败返回nil
func Deserialize(data []byte) *Ethernet2 {
	if len(data) < EthernetHeaderSize+MinDataSize+4 {
		// panic("数据长度不足，数据包可能不是ErhernetII报文")
		return nil
	}
	frame := &Ethernet2{}
	offset := 0
	copy(frame.DMacAddress[:], data[offset:offset+6])
	offset += 6
	copy(frame.SMacAddress[:], data[offset:offset+6])
	offset += 6
	copy(frame.ProtocolType[:], data[offset:offset+2])
	offset += 2
	dataSize := len(data) - EthernetHeaderSize - 4
	frame.DataPackage = make([]byte, dataSize)
	copy(frame.DataPackage, data[offset:offset+dataSize])
	offset += dataSize
	copy(frame.CRCCheckSum[:], data[offset:offset+4])
	return frame
}

// ValidateCRC 检测以太网帧的CRC校验和是否正确
// @author xuyang
// @datetime 2025/6/27 12:00
// @return bool 如果CRC正确返回true，否则返回false
func (e *Ethernet2) ValidateCRC() bool {
	calculatedCRC := e.calculateCRC()
	return calculatedCRC == e.CRCCheckSum
}

// generateCRC 生成CRC校验和
// @author xuyang
// @datetime 2025/6/27 12:00
func (e *Ethernet2) generateCRC() {
	e.CRCCheckSum = e.calculateCRC()
}

// calculateCRC 计算CRC校验和
// @author xuyang
// @datetime 2025/6/27 12:00
// @return [4]byte 计算出的CRC校验和
func (e *Ethernet2) calculateCRC() [4]byte {
	crcData := make([]byte, EthernetHeaderSize+len(e.DataPackage))
	offset := 0
	copy(crcData[offset:], e.DMacAddress[:])
	offset += 6
	copy(crcData[offset:], e.SMacAddress[:])
	offset += 6
	copy(crcData[offset:], e.ProtocolType[:])
	offset += 2
	copy(crcData[offset:], e.DataPackage)
	crc := calcCRC32IEEE(crcData) // 使用自定义的CRC32实现
	var result [4]byte
	binary.BigEndian.PutUint32(result[:], crc)
	return result
}

// CRC循环冗余校验，将数据和一个固定的多项式做除法，校验余数
var crc32Table [256]uint32

func init() {
	initCRC32Table()
}

// 查表法加快运算速度
func initCRC32Table() {
	const poly = 0xEDB88320
	for i := 0; i < 256; i++ {
		crc := uint32(i)
		for j := 0; j < 8; j++ {
			if crc&1 == 1 {
				crc = (crc >> 1) ^ poly
			} else {
				crc >>= 1
			}
		}
		crc32Table[i] = crc
	}
}

func calcCRC32IEEE(data []byte) uint32 {
	crc := uint32(0xFFFFFFFF)
	for _, b := range data {
		crc = crc32Table[byte(crc)^b] ^ (crc >> 8)
	}
	return ^crc
}
