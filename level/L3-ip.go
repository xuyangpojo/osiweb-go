package level

import (
	"encoding/binary"
	"errors"
)

// IPv4 报文结构体
// IPv4 Packet Structure
// @author xuyang
// @datetime 2025/6/27 13:20
// [版本+头部长度][服务类型][总长度][标识][标志+片偏移][TTL][协议][头部校验和][源IP][目标IP][选项][数据]
type IPv4Packet struct {
	// 版本 Version (4 bits) + 头部长度 IHL (4 bits)
	VersionIHL uint8
	// 服务类型 Type of Service (1 byte)
	TOS uint8
	// 总长度 Total Length (2 bytes)
	TotalLength uint16
	// 标识 Identification (2 bytes)
	Identification uint16
	// 标志 Flags (3 bits) + 片偏移 Fragment Offset (13 bits)
	FlagsFragOffset uint16
	// 生存时间 TTL (1 byte)
	TTL uint8
	// 协议 Protocol (1 byte)
	Protocol uint8
	// 头部校验和 Header Checksum (2 bytes)
	HeaderChecksum uint16
	// 源IP地址 Source IP Address (4 bytes)
	SourceIP [4]byte
	// 目标IP地址 Destination IP Address (4 bytes)
	DestIP [4]byte
	// 选项 Options (可变长度)
	Options []byte
	// 数据 Data (可变长度)
	Data []byte
}

// NewIPv4Packet 新建 IPv4 报文
// New IPv4 Packet
func NewIPv4Packet(srcIP, dstIP [4]byte, protocol uint8, data []byte) *IPv4Packet {
	ihl := uint8(5) // 无选项时IHL=5
	totalLen := uint16(ihl*4 + len(data))
	return &IPv4Packet{
		VersionIHL:    (4 << 4) | ihl,
		TOS:           0,
		TotalLength:   totalLen,
		Identification: 0,
		FlagsFragOffset: 0,
		TTL:           64,
		Protocol:      protocol,
		SourceIP:      srcIP,
		DestIP:        dstIP,
		Options:       nil,
		Data:          data,
	}
}

// Serialize 序列化 IPv4 报文为字节数组
// Serialize IPv4 packet to []byte
func (ip *IPv4Packet) Serialize() []byte {
	ihl := ip.VersionIHL & 0x0F
	headLen := int(ihl) * 4
	buf := make([]byte, headLen+len(ip.Data))
	buf[0] = ip.VersionIHL
	buf[1] = ip.TOS
	binary.BigEndian.PutUint16(buf[2:4], ip.TotalLength)
	binary.BigEndian.PutUint16(buf[4:6], ip.Identification)
	binary.BigEndian.PutUint16(buf[6:8], ip.FlagsFragOffset)
	buf[8] = ip.TTL
	buf[9] = ip.Protocol
	// 校验和先置0
	binary.BigEndian.PutUint16(buf[10:12], 0)
	copy(buf[12:16], ip.SourceIP[:])
	copy(buf[16:20], ip.DestIP[:])
	if headLen > 20 && ip.Options != nil {
		copy(buf[20:headLen], ip.Options)
	}
	copy(buf[headLen:], ip.Data)
	// 计算校验和
	ip.HeaderChecksum = calcIPv4Checksum(buf[:headLen])
	binary.BigEndian.PutUint16(buf[10:12], ip.HeaderChecksum)
	return buf
}

// Deserialize 反序列化字节数组为 IPv4 报文
// Deserialize []byte to IPv4 packet
func DeserializeIPv4Packet(data []byte) (*IPv4Packet, error) {
	if len(data) < 20 {
		return nil, errors.New("数据长度不足，不是有效的IPv4报文 / Data too short, not a valid IPv4 packet")
	}
	ihl := data[0] & 0x0F
	headLen := int(ihl) * 4
	if len(data) < headLen {
		return nil, errors.New("数据长度不足，不是有效的IPv4头部 / Data too short for IPv4 header")
	}
	ip := &IPv4Packet{}
	ip.VersionIHL = data[0]
	ip.TOS = data[1]
	ip.TotalLength = binary.BigEndian.Uint16(data[2:4])
	ip.Identification = binary.BigEndian.Uint16(data[4:6])
	ip.FlagsFragOffset = binary.BigEndian.Uint16(data[6:8])
	ip.TTL = data[8]
	ip.Protocol = data[9]
	ip.HeaderChecksum = binary.BigEndian.Uint16(data[10:12])
	copy(ip.SourceIP[:], data[12:16])
	copy(ip.DestIP[:], data[16:20])
	if headLen > 20 {
		ip.Options = make([]byte, headLen-20)
		copy(ip.Options, data[20:headLen])
	}
	if int(ip.TotalLength) > headLen && int(ip.TotalLength) <= len(data) {
		ip.Data = make([]byte, int(ip.TotalLength)-headLen)
		copy(ip.Data, data[headLen:int(ip.TotalLength)])
	} else if len(data) > headLen {
		ip.Data = make([]byte, len(data)-headLen)
		copy(ip.Data, data[headLen:])
	}
	return ip, nil
}

// IsValid 检查 IPv4 报文是否合法
// Check if IPv4 packet is valid
func (ip *IPv4Packet) IsValid() bool {
	return (ip.VersionIHL>>4) == 4 && ip.TotalLength >= 20
}

// calcIPv4Checksum 计算IPv4头部校验和
// Calculate IPv4 header checksum
func calcIPv4Checksum(header []byte) uint16 {
	sum := uint32(0)
	for i := 0; i < len(header)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}
	if len(header)%2 == 1 {
		sum += uint32(header[len(header)-1]) << 8
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}
