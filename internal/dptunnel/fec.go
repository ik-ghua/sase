package dptunnel

// 块状 XOR 前向纠错(m=1):每 K 个 data 帧发 1 个 parity 帧(块内各 data Body 零填充到 maxlen 后 XOR),
// 可恢复块内**任意 1 个**丢失 data 帧。K<=1 视为关闭 FEC。
// 起步方案;纠多丢包的 Reed-Solomon、按丢包率自适应留后置(L2 §5)。

// fecEncoder 累积 data Body,满 K 个产 parity Body。
type fecEncoder struct {
	k       int
	blockID uint32
	count   int    // 当前块已累积 data 数
	parity  []byte // 当前块各 Body XOR(随累积增长到 maxlen)
}

func newFECEncoder(k int) *fecEncoder { return &fecEncoder{k: k} }

func (e *fecEncoder) enabled() bool { return e.k > 1 }

// peek 返回下一个待封 data 帧的 (blockID, index),不改状态(供封装前算 aad)。
func (e *fecEncoder) peek() (blockID uint32, index uint8) {
	return e.blockID, uint8(e.count)
}

// add 累积一个 data Body,返回 (blockID, indexInBlock);若该 Body 是块内第 K 个,blockDone=true。
func (e *fecEncoder) add(body []byte) (blockID uint32, index uint8, blockDone bool) {
	blockID, index = e.blockID, uint8(e.count)
	xorInto(&e.parity, body)
	e.count++
	if e.count >= e.k {
		blockDone = true
	}
	return blockID, index, blockDone
}

// sealParity 取当前块的 parity Body 并翻到下一块(调用方在 blockDone 后调用)。
func (e *fecEncoder) sealParity() (blockID uint32, parity []byte) {
	blockID = e.blockID
	parity = e.parity
	e.parity = nil
	e.count = 0
	e.blockID++
	return blockID, parity
}

// xorInto 把 src 逐字节 XOR 进 *dst(dst 自动扩到 max(len)),实现零填充 XOR。
func xorInto(dst *[]byte, src []byte) {
	if len(src) > len(*dst) {
		grown := make([]byte, len(src))
		copy(grown, *dst)
		*dst = grown
	}
	d := *dst
	for i := 0; i < len(src); i++ {
		d[i] ^= src[i]
	}
}

// fecDecoder 按块缓冲收到的 data Body 与 parity,凑齐"恰缺 1 个 data + 有 parity"时恢复缺失 Body。
type fecBlock struct {
	k         uint8
	data      map[uint8][]byte // 已收到的 data Body(index→body)
	parity    []byte
	hasParity bool
	recovered bool // 已恢复过(避免重复)
}

// 解码侧缓冲上限(防伪造 parity 帧——parity 不经 AEAD 认证——撑爆内存,评审 B2):
// 仅缓冲 [highest-window, highest] 内的块,且硬顶 maxBlocks 个。data 帧的 blockID/index/k 经 AEAD aad 认证
// (见 session),只有认证通过的 data 才进解码器;parity 帧 blockID/k 不可信,靠窗口+硬顶约束。
const (
	fecWindow    = 64
	fecMaxBlocks = 256
)

type fecDecoder struct {
	blocks  map[uint32]*fecBlock
	highest uint32
	seen    bool
}

func newFECDecoder() *fecDecoder { return &fecDecoder{blocks: map[uint32]*fecBlock{}} }

// block 取/建块。过旧(滑窗外)→ nil 丢弃;已存在但 k 不一致(伪造 parity)→ nil 拒绝。
func (d *fecDecoder) block(id uint32, k uint8) *fecBlock {
	if d.seen && id < d.highest && d.highest-id > fecWindow {
		return nil // 过旧,窗口外
	}
	if b := d.blocks[id]; b != nil {
		if b.k != k {
			return nil // k 与已建块不一致 → 伪造,拒
		}
		return b
	}
	b := &fecBlock{k: k, data: map[uint8][]byte{}}
	d.blocks[id] = b
	if !d.seen || id > d.highest {
		d.highest, d.seen = id, true
	}
	d.evict()
	return b
}

// evict 淘汰滑窗外的旧块,并在超硬顶时删最旧块(blockID 单调递增;uint32 回绕极远,骨架忽略)。
func (d *fecDecoder) evict() {
	for id := range d.blocks {
		if id < d.highest && d.highest-id > fecWindow {
			delete(d.blocks, id)
		}
	}
	for len(d.blocks) > fecMaxBlocks {
		low, first := uint32(0), true
		for id := range d.blocks {
			if first || id < low {
				low, first = id, false
			}
		}
		delete(d.blocks, low)
	}
}

// addData 记录一个收到的(已认证)data Body,尝试恢复。返回 (恢复出的缺失 Body, 缺失 index, ok)。
func (d *fecDecoder) addData(blockID uint32, k, index uint8, body []byte) ([]byte, uint8, bool) {
	b := d.block(blockID, k)
	if b == nil {
		return nil, 0, false
	}
	b.data[index] = body
	return d.tryRecover(blockID)
}

// addParity 记录块的 parity,尝试恢复。
func (d *fecDecoder) addParity(blockID uint32, k uint8, parity []byte) ([]byte, uint8, bool) {
	b := d.block(blockID, k)
	if b == nil {
		return nil, 0, false
	}
	b.parity = parity
	b.hasParity = true
	return d.tryRecover(blockID)
}

// tryRecover:有 parity 且恰好缺 1 个 data → XOR 恢复缺失 Body(及其 index)。否则 ok=false。
func (d *fecDecoder) tryRecover(blockID uint32) ([]byte, uint8, bool) {
	b := d.blocks[blockID]
	if b == nil || !b.hasParity || b.recovered {
		return nil, 0, false
	}
	if int(b.k)-len(b.data) != 1 { // 全到(无需恢复)或缺多个(XOR 无能为力)
		return nil, 0, false
	}
	// 找缺失 index
	var missing uint8
	for i := uint8(0); i < b.k; i++ {
		if _, ok := b.data[i]; !ok {
			missing = i
			break
		}
	}
	// 缺失 Body = parity XOR 所有已收到 data(零填充对齐)
	var rec []byte
	xorInto(&rec, b.parity)
	for _, body := range b.data {
		xorInto(&rec, body)
	}
	b.recovered = true
	delete(d.blocks, blockID) // 恢复后即删;迟到原帧由接收侧 replay 窗拦
	return rec, missing, true
}
