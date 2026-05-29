package dptunnel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
)

// ErrRekeyRequired:发送计数器接近回绕安全阈值,继续发会复用 nonce(灾难)。fail-closed 停发,
// 等握手层 rekey(换会话密钥/epoch)。本包不做握手,故越阈即拒(见 L2 7.1)。
var ErrRekeyRequired = errors.New("dptunnel: 计数器达阈值,须 rekey(换会话密钥)")

// rekeyAfter:单调计数器安全上限。远低于 2^64,留充裕 rekey 窗口;单会话发这么多包前早该 rekey。
const rekeyAfter = uint64(1) << 48

// maxSealed:单帧密文上限(PayloadLen 为 uint16);超出 fail-loud,不静默截断(评审 S5)。
const maxSealed = 1<<16 - 1

// Session 是一条隧道会话的密文数据报编解码:发送侧 AEAD 封装 + 单调计数器 + XOR-FEC 产帧;
// 接收侧解封 + 重放保护 + FEC 恢复。**会话密钥由握手层(Noise+ZTP,待审查)协商后注入**,本结构不做握手。
//
// nonce 含方向字节,使同一会话密钥下收发两方向计数器不冲突(不复用 nonce)。计数器近回绕须 rekey(握手层)。
type Session struct {
	aead    AEAD
	sendDir byte
	recvDir byte

	mu      sync.Mutex
	sendCtr uint64
	enc     *fecEncoder

	replay replayWindow
	dec    *fecDecoder
}

// NewSession 构造会话。fecK>1 启用 FEC(每 K 数据帧 1 校验帧);sendDir/recvDir 须与对端镜像(本端 send=对端 recv)。
// sendDir != recvDir 是 nonce 不复用的前提,违反即编程错误,fail-loud panic(评审 B1)。
func NewSession(aead AEAD, fecK int, sendDir, recvDir byte) *Session {
	if sendDir == recvDir {
		panic("dptunnel.NewSession: sendDir 须 != recvDir(否则同密钥下 nonce 复用)")
	}
	return &Session{
		aead:    aead,
		sendDir: sendDir,
		recvDir: recvDir,
		enc:     newFECEncoder(fecK),
		dec:     newFECDecoder(),
	}
}

func nonce(dir byte, counter uint64) []byte {
	n := make([]byte, 12) // ChaCha20-Poly1305 与 GCM 均 12 字节 nonce
	n[0] = dir
	binary.BigEndian.PutUint64(n[4:12], counter)
	return n
}

// Seal 封装一个明文 L3 包,返回待发数据报(1 个 data 帧;若该帧凑满 FEC 块,附 1 个 parity 帧)。
// 计数器达阈值 → ErrRekeyRequired(不复用 nonce);密文超 uint16 → 错误(不截断)。
func (s *Session) Seal(plaintext []byte) ([][]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.sendCtr >= rekeyAfter {
		return nil, ErrRekeyRequired
	}
	ctr := s.sendCtr

	// 帧头(Type/BlockID/Index/K)作 AEAD aad 认证:无 FEC 时 blockID=ctr、index0、K1;有 FEC 时取编码器下一槽。
	var blockID uint32
	var index, k uint8
	if s.enc.enabled() {
		blockID, index = s.enc.peek()
		k = uint8(s.enc.k)
	} else {
		blockID, index, k = uint32(ctr), 0, 1
	}
	aad := headerBytes(typeData, blockID, index, k)
	sealed := s.aead.Seal(nil, nonce(s.sendDir, ctr), plaintext, aad)
	if len(sealed) > maxSealed {
		return nil, fmt.Errorf("dptunnel.Seal: 密文 %d 超上限 %d(包过大)", len(sealed), maxSealed)
	}
	s.sendCtr++ // 仅在确定产帧后自增
	body := dataBody(ctr, sealed)

	df := frame{Type: typeData, BlockID: blockID, Index: index, K: k, Body: body}
	out := [][]byte{df.marshal()}
	if s.enc.enabled() {
		if _, _, done := s.enc.add(body); done {
			bid, parity := s.enc.sealParity()
			pf := frame{Type: typeParity, BlockID: bid, Index: k, K: k, Body: parity}
			out = append(out, pf.marshal())
		}
	}
	return out, nil
}

// Open 解析一个收到的数据报,返回应交付的明文 L3 包(0..2 个:本帧解出的 + FEC 恢复出的)。
// 重放/解密失败的帧被丢弃(不计入交付);parity 帧本身不交付,仅用于恢复缺失 data。
func (s *Session) Open(datagram []byte) ([][]byte, error) {
	f, err := parseFrame(datagram)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	var out [][]byte
	switch f.Type {
	case typeData:
		// aad = 收到的帧头字节;篡改/伪造帧头 → 认证失败丢弃
		pt, ok := s.openAndAccept(f.Body, datagram[:frameHeaderLen])
		if !ok {
			return nil, nil // 未通过认证的帧不交付、也不喂 FEC(S1:只缓冲已认证帧)
		}
		out = append(out, pt)
		if s.enc.enabled() {
			if rec, missing, recovered := s.dec.addData(f.BlockID, f.K, f.Index, f.Body); recovered {
				out = s.appendRecovered(out, rec, f.BlockID, missing, f.K)
			}
		}
	case typeParity:
		if s.enc.enabled() {
			if rec, missing, recovered := s.dec.addParity(f.BlockID, f.K, f.Body); recovered {
				out = s.appendRecovered(out, rec, f.BlockID, missing, f.K)
			}
		}
	}
	return out, nil
}

// appendRecovered 对 FEC 恢复出的缺失 data Body:用重建的帧头作 aad 认证后交付(误恢复的垃圾 → 认证失败丢弃)。
func (s *Session) appendRecovered(out [][]byte, recBody []byte, blockID uint32, missing, k uint8) [][]byte {
	aad := headerBytes(typeData, blockID, missing, k) // 与发送方封装缺失帧时的 aad 一致
	if pt, ok := s.openAndAccept(recBody, aad); ok {
		out = append(out, pt)
	}
	return out
}

// openAndAccept 解封一个 data Body(aad 认证帧头)并过重放窗口;解密/认证失败、重放 → (nil,false) 丢弃。
func (s *Session) openAndAccept(body, aad []byte) ([]byte, bool) {
	ctr, sealed, err := parseDataBody(body)
	if err != nil {
		return nil, false
	}
	plain, err := s.aead.Open(nil, nonce(s.recvDir, ctr), sealed, aad)
	if err != nil {
		return nil, false // 解密/认证失败(含帧头篡改、FEC 误恢复出的垃圾)
	}
	if !s.replay.accept(ctr) {
		return nil, false // 重放/重复(含已被 FEC 提前恢复又迟到的原帧)
	}
	return plain, true
}
