package level

import (
	"encoding/binary"
	"errors"
)

// TLS 1.3 报文结构体
// TLS 1.3 Packet Structure
// @author xuyang
// @datetime 2025/6/27 14:15
// [内容类型][版本][长度][负载数据]
type TLS13Packet struct {
	// 内容类型 Content Type (1 byte)
	ContentType uint8
	// 版本 Version (2 bytes)
	Version [2]byte // 0x03 0x03 for TLS 1.3
	// 长度 Length (2 bytes)
	Length uint16
	// 负载数据 Payload (可变长度)
	Payload []byte
}

// NewTLS13Packet 新建 TLS 1.3 报文
// New TLS 1.3 Packet
func NewTLS13Packet(contentType uint8, payload []byte) *TLS13Packet {
	return &TLS13Packet{
		ContentType: contentType,
		Version:     [2]byte{0x03, 0x03},
		Length:      uint16(len(payload)),
		Payload:     payload,
	}
}

// Serialize 序列化 TLS 1.3 报文为字节数组
// Serialize TLS 1.3 packet to []byte
func (tls *TLS13Packet) Serialize() []byte {
	buf := make([]byte, 5+len(tls.Payload))
	buf[0] = tls.ContentType
	copy(buf[1:3], tls.Version[:])
	binary.BigEndian.PutUint16(buf[3:5], tls.Length)
	copy(buf[5:], tls.Payload)
	return buf
}

// Deserialize 反序列化字节数组为 TLS 1.3 报文
// Deserialize []byte to TLS 1.3 packet
func DeserializeTLS13Packet(data []byte) (*TLS13Packet, error) {
	if len(data) < 5 {
		return nil, errors.New("数据长度不足，不是有效的TLS 1.3报文 / Data too short, not a valid TLS 1.3 packet")
	}
	tls := &TLS13Packet{}
	tls.ContentType = data[0]
	copy(tls.Version[:], data[1:3])
	tls.Length = binary.BigEndian.Uint16(data[3:5])
	if len(data) > 5 {
		tls.Payload = make([]byte, len(data)-5)
		copy(tls.Payload, data[5:])
	}
	return tls, nil
}

// IsValid 检查 TLS 1.3 报文是否合法
// Check if TLS 1.3 packet is valid
func (tls *TLS13Packet) IsValid() bool {
	return tls.Version == [2]byte{0x03, 0x03} && int(tls.Length) == len(tls.Payload)
}
