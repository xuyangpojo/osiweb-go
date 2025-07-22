package level

import (
	"encoding/binary"
	"errors"
)

// UDP 报文结构体
// UDP Packet Structure
// @author xuyang
// @datetime 2025/6/27 14:00
// [源端口][目标端口][长度][校验和][数据]
type UDPPacket struct {
	// 源端口 Source Port (2 bytes)
	SourcePort uint16
	// 目标端口 Destination Port (2 bytes)
	DestPort uint16
	// 长度 Length (2 bytes)
	Length uint16
	// 校验和 Checksum (2 bytes)
	Checksum uint16
	// 数据 Data (可变长度)
	Data []byte
}

// NewUDPPacket 新建 UDP 报文
// New UDP Packet
func NewUDPPacket(srcPort, dstPort uint16, data []byte) *UDPPacket {
	length := uint16(8 + len(data))
	return &UDPPacket{
		SourcePort: srcPort,
		DestPort:   dstPort,
		Length:     length,
		Data:       data,
	}
}

// Serialize 序列化 UDP 报文为字节数组
// Serialize UDP packet to []byte
func (udp *UDPPacket) Serialize(srcIP, dstIP [4]byte) []byte {
	buf := make([]byte, 8+len(udp.Data))
	binary.BigEndian.PutUint16(buf[0:2], udp.SourcePort)
	binary.BigEndian.PutUint16(buf[2:4], udp.DestPort)
	binary.BigEndian.PutUint16(buf[4:6], udp.Length)
	binary.BigEndian.PutUint16(buf[6:8], 0) // 校验和先置0
	copy(buf[8:], udp.Data)
	udp.Checksum = calcUDPChecksum(buf, srcIP, dstIP)
	binary.BigEndian.PutUint16(buf[6:8], udp.Checksum)
	return buf
}

// Deserialize 反序列化字节数组为 UDP 报文
// Deserialize []byte to UDP packet
func DeserializeUDPPacket(data []byte) (*UDPPacket, error) {
	if len(data) < 8 {
		return nil, errors.New("数据长度不足，不是有效的UDP报文 / Data too short, not a valid UDP packet")
	}
	udp := &UDPPacket{}
	udp.SourcePort = binary.BigEndian.Uint16(data[0:2])
	udp.DestPort = binary.BigEndian.Uint16(data[2:4])
	udp.Length = binary.BigEndian.Uint16(data[4:6])
	udp.Checksum = binary.BigEndian.Uint16(data[6:8])
	if len(data) > 8 {
		udp.Data = make([]byte, len(data)-8)
		copy(udp.Data, data[8:])
	}
	return udp, nil
}

// IsValid 检查 UDP 报文是否合法
// Check if UDP packet is valid
func (udp *UDPPacket) IsValid() bool {
	return udp.SourcePort > 0 && udp.DestPort > 0 && udp.Length >= 8
}

// calcUDPChecksum 计算UDP校验和
// Calculate UDP checksum
func calcUDPChecksum(segment []byte, srcIP, dstIP [4]byte) uint16 {
	pseudoHeader := make([]byte, 12+len(segment))
	copy(pseudoHeader[0:4], srcIP[:])
	copy(pseudoHeader[4:8], dstIP[:])
	pseudoHeader[8] = 0
	pseudoHeader[9] = 17 // UDP协议号
	binary.BigEndian.PutUint16(pseudoHeader[10:12], uint16(len(segment)))
	copy(pseudoHeader[12:], segment)
	sum := uint32(0)
	for i := 0; i < len(pseudoHeader)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pseudoHeader[i : i+2]))
	}
	if len(pseudoHeader)%2 == 1 {
		sum += uint32(pseudoHeader[len(pseudoHeader)-1]) << 8
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}
