package level

import (
	"encoding/binary"
	"errors"
)

// ARP 报文结构体
// ARP Packet Structure
// @author xuyang
// @datetime 2025/6/27 13:00
// [硬件类型][协议类型][硬件地址长度][协议地址长度][操作码][发送方MAC][发送方IP][目标MAC][目标IP]
type ARPPacket struct {
	// 硬件类型 Hardware Type (2 bytes)
	HardwareType uint16 // 1: Ethernet
	// 协议类型 Protocol Type (2 bytes)
	ProtocolType uint16 // 0x0800: IPv4
	// 硬件地址长度 Hardware Address Length (1 byte)
	HardwareAddrLen uint8 // 6 for MAC
	// 协议地址长度 Protocol Address Length (1 byte)
	ProtocolAddrLen uint8 // 4 for IPv4
	// 操作码 Operation Code (2 bytes)
	Operation uint16 // 1: request, 2: reply
	// 发送方MAC地址 Sender MAC Address (6 bytes)
	SenderMAC [6]byte
	// 发送方IP地址 Sender IP Address (4 bytes)
	SenderIP [4]byte
	// 目标MAC地址 Target MAC Address (6 bytes)
	TargetMAC [6]byte
	// 目标IP地址 Target IP Address (4 bytes)
	TargetIP [4]byte
}

// NewARPPacket 新建 ARP 报文
// New ARP Packet
// @param op 操作码 Operation code
// @param senderMAC 发送方MAC Sender MAC
// @param senderIP 发送方IP Sender IP
// @param targetMAC 目标MAC Target MAC
// @param targetIP 目标IP Target IP
// @return *ARPPacket
func NewARPPacket(op uint16, senderMAC [6]byte, senderIP [4]byte, targetMAC [6]byte, targetIP [4]byte) *ARPPacket {
	return &ARPPacket{
		HardwareType:    1,        // Ethernet
		ProtocolType:    0x0800,   // IPv4
		HardwareAddrLen: 6,
		ProtocolAddrLen: 4,
		Operation:       op,
		SenderMAC:       senderMAC,
		SenderIP:        senderIP,
		TargetMAC:       targetMAC,
		TargetIP:        targetIP,
	}
}

// Serialize 序列化 ARP 报文为字节数组
// Serialize ARP packet to []byte
func (a *ARPPacket) Serialize() []byte {
	buf := make([]byte, 28) // ARP 报文固定长度 28 字节
	binary.BigEndian.PutUint16(buf[0:2], a.HardwareType)
	binary.BigEndian.PutUint16(buf[2:4], a.ProtocolType)
	buf[4] = a.HardwareAddrLen
	buf[5] = a.ProtocolAddrLen
	binary.BigEndian.PutUint16(buf[6:8], a.Operation)
	copy(buf[8:14], a.SenderMAC[:])
	copy(buf[14:18], a.SenderIP[:])
	copy(buf[18:24], a.TargetMAC[:])
	copy(buf[24:28], a.TargetIP[:])
	return buf
}

// Deserialize 反序列化字节数组为 ARP 报文
// Deserialize []byte to ARP packet
// @param data 字节数组
// @return *ARPPacket, error
func DeserializeARPPacket(data []byte) (*ARPPacket, error) {
	if len(data) < 28 {
		return nil, errors.New("数据长度不足，不是有效的ARP报文 / Data too short, not a valid ARP packet")
	}
	arp := &ARPPacket{}
	arp.HardwareType = binary.BigEndian.Uint16(data[0:2])
	arp.ProtocolType = binary.BigEndian.Uint16(data[2:4])
	arp.HardwareAddrLen = data[4]
	arp.ProtocolAddrLen = data[5]
	arp.Operation = binary.BigEndian.Uint16(data[6:8])
	copy(arp.SenderMAC[:], data[8:14])
	copy(arp.SenderIP[:], data[14:18])
	copy(arp.TargetMAC[:], data[18:24])
	copy(arp.TargetIP[:], data[24:28])
	return arp, nil
}

// IsValid 检查 ARP 报文是否合法
// Check if ARP packet is valid
func (a *ARPPacket) IsValid() bool {
	return a.HardwareType == 1 && a.ProtocolType == 0x0800 && a.HardwareAddrLen == 6 && a.ProtocolAddrLen == 4
}
