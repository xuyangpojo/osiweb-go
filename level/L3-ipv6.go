package level

import (
	"encoding/binary"
	"errors"
)

// IPv6 报文结构体
// IPv6 Packet Structure
// @author xuyang
// @datetime 2025/6/27 13:30
// [版本+流量类][流量标签][有效载荷长度][下一个头部][跳数限制][源地址][目标地址][数据]
type IPv6Packet struct {
	// 版本+流量类 Version+Traffic Class (1 byte)
	VersionTrafficClass uint8
	// 流量标签 Flow Label (3 bytes)
	FlowLabel [3]byte
	// 有效载荷长度 Payload Length (2 bytes)
	PayloadLength uint16
	// 下一个头部 Next Header (1 byte)
	NextHeader uint8
	// 跳数限制 Hop Limit (1 byte)
	HopLimit uint8
	// 源地址 Source Address (16 bytes)
	SourceAddr [16]byte
	// 目标地址 Destination Address (16 bytes)
	DestAddr [16]byte
	// 数据 Data (可变长度)
	Data []byte
}

// NewIPv6Packet 新建 IPv6 报文
// New IPv6 Packet
func NewIPv6Packet(src, dst [16]byte, nextHeader uint8, data []byte) *IPv6Packet {
	return &IPv6Packet{
		VersionTrafficClass: (6 << 4),
		FlowLabel:           [3]byte{0, 0, 0},
		PayloadLength:       uint16(len(data)),
		NextHeader:          nextHeader,
		HopLimit:            64,
		SourceAddr:          src,
		DestAddr:            dst,
		Data:                data,
	}
}

// Serialize 序列化 IPv6 报文为字节数组
// Serialize IPv6 packet to []byte
func (ip *IPv6Packet) Serialize() []byte {
	buf := make([]byte, 40+len(ip.Data))
	buf[0] = ip.VersionTrafficClass
	copy(buf[1:4], ip.FlowLabel[:])
	binary.BigEndian.PutUint16(buf[4:6], ip.PayloadLength)
	buf[6] = ip.NextHeader
	buf[7] = ip.HopLimit
	copy(buf[8:24], ip.SourceAddr[:])
	copy(buf[24:40], ip.DestAddr[:])
	copy(buf[40:], ip.Data)
	return buf
}

// Deserialize 反序列化字节数组为 IPv6 报文
// Deserialize []byte to IPv6 packet
func DeserializeIPv6Packet(data []byte) (*IPv6Packet, error) {
	if len(data) < 40 {
		return nil, errors.New("数据长度不足，不是有效的IPv6报文 / Data too short, not a valid IPv6 packet")
	}
	ip := &IPv6Packet{}
	ip.VersionTrafficClass = data[0]
	copy(ip.FlowLabel[:], data[1:4])
	ip.PayloadLength = binary.BigEndian.Uint16(data[4:6])
	ip.NextHeader = data[6]
	ip.HopLimit = data[7]
	copy(ip.SourceAddr[:], data[8:24])
	copy(ip.DestAddr[:], data[24:40])
	if len(data) > 40 {
		ip.Data = make([]byte, len(data)-40)
		copy(ip.Data, data[40:])
	}
	return ip, nil
}

// IsValid 检查 IPv6 报文是否合法
// Check if IPv6 packet is valid
func (ip *IPv6Packet) IsValid() bool {
	return (ip.VersionTrafficClass>>4) == 6 && ip.PayloadLength+40 <= uint16(40+len(ip.Data))
}
