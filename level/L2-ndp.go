package level

import (
	"encoding/binary"
	"errors"
)

// NDP 邻居发现协议报文结构体
// NDP (Neighbor Discovery Protocol) Packet Structure
// @author xuyang
// @datetime 2025/6/27 13:10
// [类型][代码][校验和][保留][目标地址][选项...]
type NDPPacket struct {
	// 类型 Type (1 byte)
	Type uint8
	// 代码 Code (1 byte)
	Code uint8
	// 校验和 Checksum (2 bytes)
	Checksum uint16
	// 保留字段 Reserved (4 bytes)
	Reserved uint32
	// 目标地址 Target Address (16 bytes, IPv6)
	TargetAddress [16]byte
	// 选项 Options (可变长度)
	Options []byte
}

// NewNDPPacket 新建 NDP 报文
// New NDP Packet
func NewNDPPacket(typ, code uint8, targetAddr [16]byte, options []byte) *NDPPacket {
	return &NDPPacket{
		Type:         typ,
		Code:         code,
		Reserved:     0,
		TargetAddress: targetAddr,
		Options:      options,
	}
}

// Serialize 序列化 NDP 报文为字节数组
// Serialize NDP packet to []byte
func (n *NDPPacket) Serialize() []byte {
	buf := make([]byte, 24+len(n.Options))
	buf[0] = n.Type
	buf[1] = n.Code
	binary.BigEndian.PutUint16(buf[2:4], n.Checksum)
	binary.BigEndian.PutUint32(buf[4:8], n.Reserved)
	copy(buf[8:24], n.TargetAddress[:])
	copy(buf[24:], n.Options)
	return buf
}

// Deserialize 反序列化字节数组为 NDP 报文
// Deserialize []byte to NDP packet
func DeserializeNDPPacket(data []byte) (*NDPPacket, error) {
	if len(data) < 24 {
		return nil, errors.New("数据长度不足，不是有效的NDP报文 / Data too short, not a valid NDP packet")
	}
	n := &NDPPacket{}
	n.Type = data[0]
	n.Code = data[1]
	n.Checksum = binary.BigEndian.Uint16(data[2:4])
	n.Reserved = binary.BigEndian.Uint32(data[4:8])
	copy(n.TargetAddress[:], data[8:24])
	if len(data) > 24 {
		n.Options = make([]byte, len(data)-24)
		copy(n.Options, data[24:])
	}
	return n, nil
}

// IsValid 检查 NDP 报文是否合法
// Check if NDP packet is valid
func (n *NDPPacket) IsValid() bool {
	return n.Type >= 133 && n.Type <= 136 // 133~136为NDP相关类型
}
