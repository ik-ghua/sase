package ztnaterm

import "net"

// fiveTuple 是内层 L3 包的 5 元组(逐流 PEP / 出站所需)。
type fiveTuple struct {
	SrcIP   net.IP
	DstIP   net.IP
	Proto   uint8
	SrcPort uint16
	DstPort uint16
}

// parse5Tuple 从解封出的内层 L3 包提取 5 元组(IPv4/IPv6;只读不修改入参)。
// 与 dptunnel.parse5Tuple 同口径(IHL 计算 L4 偏移、IPv6 不解扩展头);独立一份以保终结器自包含、
// 不依赖 dptunnel 的未导出函数。坏包/短包 → (零值, false),调用方降级丢弃(数据面绝不 panic)。
func parse5Tuple(pkt []byte) (fiveTuple, bool) {
	if len(pkt) < 1 {
		return fiveTuple{}, false
	}
	var t fiveTuple
	var l4off int
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 {
			return fiveTuple{}, false
		}
		t.Proto = pkt[9]
		t.SrcIP = append(net.IP(nil), pkt[12:16]...)
		t.DstIP = append(net.IP(nil), pkt[16:20]...)
		l4off = int(pkt[0]&0x0f) * 4 // IHL
		if l4off < 20 {
			return fiveTuple{}, false // 畸形 IHL
		}
	case 6:
		if len(pkt) < 40 {
			return fiveTuple{}, false
		}
		t.Proto = pkt[6] // NextHeader(扩展头未解析)
		t.SrcIP = append(net.IP(nil), pkt[8:24]...)
		t.DstIP = append(net.IP(nil), pkt[24:40]...)
		l4off = 40
	default:
		return fiveTuple{}, false
	}
	if (t.Proto == 6 || t.Proto == 17) && len(pkt) >= l4off+4 {
		t.SrcPort = uint16(pkt[l4off])<<8 | uint16(pkt[l4off+1])
		t.DstPort = uint16(pkt[l4off+2])<<8 | uint16(pkt[l4off+3])
	}
	return t, true
}

// flowKey 是连接级裁决缓存键(逐流 PEP):同一 5 元组的后续包复用首流裁决,不重判(Slice77 §3.3)。
// 用紧凑字符串键(IP 字节 + proto + 端口),避免持有 net.IP 切片作 map 键(切片不可比较)。
type flowKey struct {
	src   string // SrcIP.String()
	dst   string
	proto uint8
	sport uint16
	dport uint16
}

func keyOf(t fiveTuple) flowKey {
	return flowKey{src: t.SrcIP.String(), dst: t.DstIP.String(), proto: t.Proto, sport: t.SrcPort, dport: t.DstPort}
}
