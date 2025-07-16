package level

// @author xuyang
// @datetime 2025/7/15 23:00
type ICMP struct {
	Type byte
	Code byte
	CheckSum [2]byte
	MessageBody []byte
}

// @author xuyang
// @datetime 2025/7/15 23:00
func NewICMP(stype string) *ICMP {
	itype := 0
	code := 0
	// ping请求
	if stype == "pingRequest" {
		itype = 8
		code = 0
	}
	// ping应答
	if stype == "pingResponse" {
		itype = 0
		code = 0
	}
	// TODO: CheckSum校验和计算
	newICMP := &ICMP{
		Type: itype,
		Code: code,
	}
}