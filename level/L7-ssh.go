package level

import (
	"errors"
)

// SSH 报文结构体
// SSH Packet Structure
// @author xuyang
// @datetime 2025/6/27 14:40
// [协议版本][软件版本][换行][负载数据]
type SSHPacket struct {
	// 协议版本 Protocol Version (如 SSH-2.0)
	ProtocolVersion string
	// 软件版本 Software Version (如 OpenSSH_8.0)
	SoftwareVersion string
	// 负载数据 Payload (可选)
	Payload []byte
}

// NewSSHPacket 新建 SSH 报文
// New SSH Packet
func NewSSHPacket(protoVer, softVer string, payload []byte) *SSHPacket {
	return &SSHPacket{
		ProtocolVersion: protoVer,
		SoftwareVersion: softVer,
		Payload:         payload,
	}
}

// Serialize 序列化 SSH 报文为字节数组
// Serialize SSH packet to []byte
func (ssh *SSHPacket) Serialize() []byte {
	line := ssh.ProtocolVersion + "-" + ssh.SoftwareVersion + "\r\n"
	buf := []byte(line)
	if len(ssh.Payload) > 0 {
		buf = append(buf, ssh.Payload...)
	}
	return buf
}

// Deserialize 反序列化字节数组为 SSH 报文
// Deserialize []byte to SSH packet
func DeserializeSSHPacket(data []byte) (*SSHPacket, error) {
	lineEnd := -1
	for i := 0; i < len(data)-1; i++ {
		if data[i] == '\r' && data[i+1] == '\n' {
			lineEnd = i
			break
		}
	}
	if lineEnd == -1 {
		return nil, errors.New("数据格式错误，不是有效的SSH报文 / Invalid SSH packet format")
	}
	line := string(data[:lineEnd])
	protoVer := ""
	softVer := ""
	if idx := indexOfDash(line); idx >= 0 {
		protoVer = line[:idx]
		softVer = line[idx+1:]
	} else {
		protoVer = line
	}
	payload := []byte{}
	if lineEnd+2 < len(data) {
		payload = data[lineEnd+2:]
	}
	return &SSHPacket{ProtocolVersion: protoVer, SoftwareVersion: softVer, Payload: payload}, nil
}

// indexOfDash 查找第一个'-'的位置
// Find the first dash index
func indexOfDash(s string) int {
	for i, c := range s {
		if c == '-' {
			return i
		}
	}
	return -1
}

// IsValid 检查 SSH 报文是否合法
// Check if SSH packet is valid
func (ssh *SSHPacket) IsValid() bool {
	return ssh.ProtocolVersion != ""
}
