package level

import (
	"errors"
)

// FTP 报文结构体
// FTP Packet Structure
// @author xuyang
// @datetime 2025/6/27 14:30
// [命令][参数]
type FTPPacket struct {
	// 命令 Command (如 USER, PASS, RETR 等)
	Command string
	// 参数 Arguments (可选)
	Arguments string
}

// NewFTPPacket 新建 FTP 报文
// New FTP Packet
func NewFTPPacket(cmd, args string) *FTPPacket {
	return &FTPPacket{
		Command:   cmd,
		Arguments: args,
	}
}

// Serialize 序列化 FTP 报文为字节数组
// Serialize FTP packet to []byte
func (ftp *FTPPacket) Serialize() []byte {
	line := ftp.Command
	if ftp.Arguments != "" {
		line += " " + ftp.Arguments
	}
	line += "\r\n"
	return []byte(line)
}

// Deserialize 反序列化字节数组为 FTP 报文
// Deserialize []byte to FTP packet
func DeserializeFTPPacket(data []byte) (*FTPPacket, error) {
	line := string(data)
	if len(line) < 2 || line[len(line)-2:] != "\r\n" {
		return nil, errors.New("数据格式错误，不是有效的FTP报文 / Invalid FTP packet format")
	}
	line = line[:len(line)-2]
	cmd := ""
	args := ""
	if idx := indexOfSpace(line); idx >= 0 {
		cmd = line[:idx]
		args = line[idx+1:]
	} else {
		cmd = line
	}
	return &FTPPacket{Command: cmd, Arguments: args}, nil
}

// indexOfSpace 查找第一个空格的位置
// Find the first space index
func indexOfSpace(s string) int {
	for i, c := range s {
		if c == ' ' {
			return i
		}
	}
	return -1
}

// IsValid 检查 FTP 报文是否合法
// Check if FTP packet is valid
func (ftp *FTPPacket) IsValid() bool {
	return ftp.Command != ""
}
