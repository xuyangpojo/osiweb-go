package host

import "fmt"

// BaseHost 基本主机-端系统
// @author xuyang
// @datetime 2025/6/27 8:00
type BaseHost struct {
	// MAC地址
	MACAddress [6]byte
	// IPv4地址
	IPv4Address [4]byte
	// 通信端口
	NetChannel []chan []byte
}

// Print 打印主机信息
// @author xuyang
// @datetime 2025/6/27 8:00
func (host *BaseHost) print() {
	fmt.Printf("MAC地址: %02X:%02X:%02X:%02X:%02X:%02X\n",
		host.MACAddress[0], host.MACAddress[1], host.MACAddress[2],
		host.MACAddress[3], host.MACAddress[4], host.MACAddress[5])
	fmt.Printf("IPv4地址: %02d,%02d,%02d,%02d\n",
		host.IPv4Address[0], host.IPv4Address[1],
		host.IPv4Address[2], host.IPv4Address[3])
}

// 全局主机列表
var HostList []BaseHost

// 全局广播地址 0.0.0.0
var Forcast chan []byte

// 创建主机
func NewHost() *BaseHost {
	newMacAddress := generateMacAddress()
	newIPv4Address := generateIPv4Address()
	host := &BaseHost{
		MACAddress:  newMacAddress,
		IPv4Address: newIPv4Address,
		NetChannel:  append(make([]chan []byte, 0), Forcast),
	}
	HostList = append(HostList, *host)
	return host
}

func generateMacAddress() [6]byte {
	return [6]byte{0, 0, 0, 0, 0, 0}
}

func generateIPv4Address() [4]byte {
	return [4]byte{0, 0, 0, 0}
}
