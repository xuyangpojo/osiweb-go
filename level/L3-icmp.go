package level

import (
	"encoding/binary"
	"errors"
)

// ICMP 报文结构体
// ICMP Packet Structure
// @author xuyang
// @datetime 2025/6/27 13:40
// [类型][代码][校验和][标识][序号][数据]
type ICMPPacket struct {
	// 类型 Type (1 byte)
	Type uint8
	// 代码 Code (1 byte)
	Code uint8
	// 校验和 Checksum (2 bytes)
	Checksum uint16
	// 标识 Identifier (2 bytes)
	Identifier uint16
	// 序号 Sequence Number (2 bytes)
	Sequence uint16
	// 数据 Data (可变长度)
	Data []byte
}

// NewICMPPacket 新建 ICMP 报文
// New ICMP Packet
func NewICMPPacket(typ, code uint8, id, seq uint16, data []byte) *ICMPPacket {
	return &ICMPPacket{
		Type:       typ,
		Code:       code,
		Identifier: id,
		Sequence:   seq,
		Data:       data,
	}
}

// Serialize 序列化 ICMP 报文为字节数组
// Serialize ICMP packet to []byte
func (icmp *ICMPPacket) Serialize() []byte {
	buf := make([]byte, 8+len(icmp.Data))
	buf[0] = icmp.Type
	buf[1] = icmp.Code
	binary.BigEndian.PutUint16(buf[2:4], 0) // 校验和先置0
	binary.BigEndian.PutUint16(buf[4:6], icmp.Identifier)
	binary.BigEndian.PutUint16(buf[6:8], icmp.Sequence)
	copy(buf[8:], icmp.Data)
	icmp.Checksum = calcICMPChecksum(buf)
	binary.BigEndian.PutUint16(buf[2:4], icmp.Checksum)
	return buf
}

// Deserialize 反序列化字节数组为 ICMP 报文
// Deserialize []byte to ICMP packet
func DeserializeICMPPacket(data []byte) (*ICMPPacket, error) {
	if len(data) < 8 {
		return nil, errors.New("数据长度不足，不是有效的ICMP报文 / Data too short, not a valid ICMP packet")
	}
	icmp := &ICMPPacket{}
	icmp.Type = data[0]
	icmp.Code = data[1]
	icmp.Checksum = binary.BigEndian.Uint16(data[2:4])
	icmp.Identifier = binary.BigEndian.Uint16(data[4:6])
	icmp.Sequence = binary.BigEndian.Uint16(data[6:8])
	if len(data) > 8 {
		icmp.Data = make([]byte, len(data)-8)
		copy(icmp.Data, data[8:])
	}
	return icmp, nil
}

// IsValid 检查 ICMP 报文是否合法
// Check if ICMP packet is valid
func (icmp *ICMPPacket) IsValid() bool {
	return icmp.Type <= 255 && icmp.Code <= 255
}

// calcICMPChecksum 计算ICMP校验和
// Calculate ICMP checksum
func calcICMPChecksum(data []byte) uint16 {
	sum := uint32(0)
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}