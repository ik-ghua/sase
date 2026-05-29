package dptunnel

import (
	"encoding/binary"
	"fmt"
)

// 数据报帧格式(big-endian):
//
//	[0]    Version
//	[1]    Type        (0=data, 1=parity)
//	[2:6]  BlockID     (FEC 块序号)
//	[6]    Index       (块内序号:data 0..K-1;parity = K)
//	[7]    K           (块内数据帧数,每帧都带,使解码侧知块大小)
//	[8:]   Body
//
// Body 即 FEC 保护单元(parity = 块内各 data Body 零填充到 maxlen 后逐字节 XOR):
//   - data Body  : Counter(8) | PayloadLen(2) | SealedPayload(PayloadLen)   —— 自然长度上线
//   - parity Body: 长度 = 块内最大 data Body 长度(maxlen)
//
// 把 Counter/PayloadLen 也放进 Body(而非帧头),使丢失的 data 帧可经 parity 完整恢复(含其 nonce 计数器)。
const (
	frameVersion = 1
	typeData     = 0
	typeParity   = 1

	frameHeaderLen = 1 + 1 + 4 + 1 + 1 // 8
	bodyPrefixLen  = 8 + 2             // Counter(8) + PayloadLen(2)
)

type frame struct {
	Type    uint8
	BlockID uint32
	Index   uint8
	K       uint8
	Body    []byte
}

// headerBytes 产 8 字节帧头。data 帧用它作 AEAD aad——认证 Type/BlockID/Index/K(FEC 路由元数据),
// 使篡改/伪造帧头(改 BlockID 污染块、改 K 乱算 missing)致 AEAD 认证失败被丢(评审 B2/S2/S3)。
func headerBytes(typ uint8, blockID uint32, index, k uint8) []byte {
	b := make([]byte, frameHeaderLen)
	b[0] = frameVersion
	b[1] = typ
	binary.BigEndian.PutUint32(b[2:6], blockID)
	b[6] = index
	b[7] = k
	return b
}

func (f frame) marshal() []byte {
	b := append(headerBytes(f.Type, f.BlockID, f.Index, f.K), f.Body...)
	return b
}

func parseFrame(b []byte) (frame, error) {
	if len(b) < frameHeaderLen {
		return frame{}, fmt.Errorf("dptunnel: 帧过短(%d<%d)", len(b), frameHeaderLen)
	}
	if b[0] != frameVersion {
		return frame{}, fmt.Errorf("dptunnel: 帧版本 %d 不支持", b[0])
	}
	if b[1] != typeData && b[1] != typeParity {
		return frame{}, fmt.Errorf("dptunnel: 帧类型 %d 非法", b[1])
	}
	return frame{
		Type:    b[1],
		BlockID: binary.BigEndian.Uint32(b[2:6]),
		Index:   b[6],
		K:       b[7],
		Body:    b[frameHeaderLen:],
	}, nil
}

// dataBody 构造 data Body(Counter|PayloadLen|sealed)。
func dataBody(counter uint64, sealed []byte) []byte {
	body := make([]byte, bodyPrefixLen+len(sealed))
	binary.BigEndian.PutUint64(body[0:8], counter)
	binary.BigEndian.PutUint16(body[8:10], uint16(len(sealed)))
	copy(body[bodyPrefixLen:], sealed)
	return body
}

// parseDataBody 拆 data Body → counter, sealed。校验 PayloadLen 自洽。
func parseDataBody(body []byte) (counter uint64, sealed []byte, err error) {
	if len(body) < bodyPrefixLen {
		return 0, nil, fmt.Errorf("dptunnel: data body 过短")
	}
	counter = binary.BigEndian.Uint64(body[0:8])
	plen := int(binary.BigEndian.Uint16(body[8:10]))
	if bodyPrefixLen+plen > len(body) {
		return 0, nil, fmt.Errorf("dptunnel: PayloadLen %d 超出 body", plen)
	}
	return counter, body[bodyPrefixLen : bodyPrefixLen+plen], nil
}
