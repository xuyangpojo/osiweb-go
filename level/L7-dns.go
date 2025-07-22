package level

import (
	"encoding/binary"
	"errors"
)

// DNS 报文结构体
// DNS Packet Structure
// @author xuyang
// @datetime 2025/6/27 14:20
// [标识][标志][问题数][回答数][授权数][附加数][问题][回答][授权][附加]
type DNSPacket struct {
	// 标识 Transaction ID (2 bytes)
	ID uint16
	// 标志 Flags (2 bytes)
	Flags uint16
	// 问题数 Questions (2 bytes)
	QDCount uint16
	// 回答数 Answers (2 bytes)
	ANCount uint16
	// 授权数 Authority RRs (2 bytes)
	NSCount uint16
	// 附加数 Additional RRs (2 bytes)
	ARCount uint16
	// 负载数据 Payload (可变长度)
	Payload []byte
}

// NewDNSPacket 新建 DNS 报文
// New DNS Packet
func NewDNSPacket(id, flags, qd, an, ns, ar uint16, payload []byte) *DNSPacket {
	return &DNSPacket{
		ID:      id,
		Flags:   flags,
		QDCount: qd,
		ANCount: an,
		NSCount: ns,
		ARCount: ar,
		Payload: payload,
	}
}

// Serialize 序列化 DNS 报文为字节数组
// Serialize DNS packet to []byte
func (dns *DNSPacket) Serialize() []byte {
	buf := make([]byte, 12+len(dns.Payload))
	binary.BigEndian.PutUint16(buf[0:2], dns.ID)
	binary.BigEndian.PutUint16(buf[2:4], dns.Flags)
	binary.BigEndian.PutUint16(buf[4:6], dns.QDCount)
	binary.BigEndian.PutUint16(buf[6:8], dns.ANCount)
	binary.BigEndian.PutUint16(buf[8:10], dns.NSCount)
	binary.BigEndian.PutUint16(buf[10:12], dns.ARCount)
	copy(buf[12:], dns.Payload)
	return buf
}

// Deserialize 反序列化字节数组为 DNS 报文
// Deserialize []byte to DNS packet
func DeserializeDNSPacket(data []byte) (*DNSPacket, error) {
	if len(data) < 12 {
		return nil, errors.New("数据长度不足，不是有效的DNS报文 / Data too short, not a valid DNS packet")
	}
	dns := &DNSPacket{}
	dns.ID = binary.BigEndian.Uint16(data[0:2])
	dns.Flags = binary.BigEndian.Uint16(data[2:4])
	dns.QDCount = binary.BigEndian.Uint16(data[4:6])
	dns.ANCount = binary.BigEndian.Uint16(data[6:8])
	dns.NSCount = binary.BigEndian.Uint16(data[8:10])
	dns.ARCount = binary.BigEndian.Uint16(data[10:12])
	if len(data) > 12 {
		dns.Payload = make([]byte, len(data)-12)
		copy(dns.Payload, data[12:])
	}
	return dns, nil
}

// IsValid 检查 DNS 报文是否合法
// Check if DNS packet is valid
func (dns *DNSPacket) IsValid() bool {
	return dns.QDCount > 0 || dns.ANCount > 0 || dns.NSCount > 0 || dns.ARCount > 0
}
