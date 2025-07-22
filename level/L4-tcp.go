package level

import (
	"encoding/binary"
	"errors"
)

// TCP 报文结构体
// TCP Packet Structure
// @author xuyang
// @datetime 2025/6/27 13:50
// [源端口][目标端口][序号][确认号][数据偏移+保留+标志][窗口][校验和][紧急指针][选项][数据]
type TCPPacket struct {
	// 源端口 Source Port (2 bytes)
	SourcePort uint16
	// 目标端口 Destination Port (2 bytes)
	DestPort uint16
	// 序号 Sequence Number (4 bytes)
	SeqNum uint32
	// 确认号 Acknowledgment Number (4 bytes)
	AckNum uint32
	// 数据偏移+保留+标志 Data Offset+Reserved+Flags (2 bytes)
	DataOffsetFlags uint16
	// 窗口 Window Size (2 bytes)
	Window uint16
	// 校验和 Checksum (2 bytes)
	Checksum uint16
	// 紧急指针 Urgent Pointer (2 bytes)
	UrgentPointer uint16
	// 选项 Options (可变长度)
	Options []byte
	// 数据 Data (可变长度)
	Data []byte
}

// NewTCPPacket 新建 TCP 报文
// New TCP Packet
func NewTCPPacket(srcPort, dstPort uint16, seq, ack uint32, flags uint16, window uint16, data []byte) *TCPPacket {
	dataOffset := uint16(5) << 12 // 无选项时数据偏移为5
	return &TCPPacket{
		SourcePort:      srcPort,
		DestPort:        dstPort,
		SeqNum:          seq,
		AckNum:          ack,
		DataOffsetFlags: dataOffset | (flags & 0x01FF),
		Window:          window,
		UrgentPointer:   0,
		Options:         nil,
		Data:            data,
	}
}

// Serialize 序列化 TCP 报文为字节数组
// Serialize TCP packet to []byte
func (tcp *TCPPacket) Serialize(srcIP, dstIP [4]byte) []byte {
	dataOffset := (tcp.DataOffsetFlags >> 12) & 0xF
	headLen := int(dataOffset) * 4
	buf := make([]byte, headLen+len(tcp.Data))
	binary.BigEndian.PutUint16(buf[0:2], tcp.SourcePort)
	binary.BigEndian.PutUint16(buf[2:4], tcp.DestPort)
	binary.BigEndian.PutUint32(buf[4:8], tcp.SeqNum)
	binary.BigEndian.PutUint32(buf[8:12], tcp.AckNum)
	binary.BigEndian.PutUint16(buf[12:14], tcp.DataOffsetFlags)
	binary.BigEndian.PutUint16(buf[14:16], tcp.Window)
	binary.BigEndian.PutUint16(buf[16:18], 0) // 校验和先置0
	binary.BigEndian.PutUint16(buf[18:20], tcp.UrgentPointer)
	if headLen > 20 && tcp.Options != nil {
		copy(buf[20:headLen], tcp.Options)
	}
	copy(buf[headLen:], tcp.Data)
	// 计算校验和
	tcp.Checksum = calcTCPChecksum(buf, srcIP, dstIP)
	binary.BigEndian.PutUint16(buf[16:18], tcp.Checksum)
	return buf
}

// Deserialize 反序列化字节数组为 TCP 报文
// Deserialize []byte to TCP packet
func DeserializeTCPPacket(data []byte) (*TCPPacket, error) {
	if len(data) < 20 {
		return nil, errors.New("数据长度不足，不是有效的TCP报文 / Data too short, not a valid TCP packet")
	}
	dataOffset := (binary.BigEndian.Uint16(data[12:14]) >> 12) & 0xF
	headLen := int(dataOffset) * 4
	if len(data) < headLen {
		return nil, errors.New("数据长度不足，不是有效的TCP头部 / Data too short for TCP header")
	}
	tcp := &TCPPacket{}
	tcp.SourcePort = binary.BigEndian.Uint16(data[0:2])
	tcp.DestPort = binary.BigEndian.Uint16(data[2:4])
	tcp.SeqNum = binary.BigEndian.Uint32(data[4:8])
	tcp.AckNum = binary.BigEndian.Uint32(data[8:12])
	tcp.DataOffsetFlags = binary.BigEndian.Uint16(data[12:14])
	tcp.Window = binary.BigEndian.Uint16(data[14:16])
	tcp.Checksum = binary.BigEndian.Uint16(data[16:18])
	tcp.UrgentPointer = binary.BigEndian.Uint16(data[18:20])
	if headLen > 20 {
		tcp.Options = make([]byte, headLen-20)
		copy(tcp.Options, data[20:headLen])
	}
	if len(data) > headLen {
		tcp.Data = make([]byte, len(data)-headLen)
		copy(tcp.Data, data[headLen:])
	}
	return tcp, nil
}

// IsValid 检查 TCP 报文是否合法
// Check if TCP packet is valid
func (tcp *TCPPacket) IsValid() bool {
	return tcp.SourcePort > 0 && tcp.DestPort > 0
}

// calcTCPChecksum 计算TCP校验和
// Calculate TCP checksum
func calcTCPChecksum(segment []byte, srcIP, dstIP [4]byte) uint16 {
	pseudoHeader := make([]byte, 12+len(segment))
	copy(pseudoHeader[0:4], srcIP[:])
	copy(pseudoHeader[4:8], dstIP[:])
	pseudoHeader[8] = 0
	pseudoHeader[9] = 6 // TCP协议号
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
