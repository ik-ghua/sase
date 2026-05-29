package dptunnel

import "testing"

// 伪造 parity 帧(blockID 任意、不可恢复)不应让解码器缓冲无界增长(评审 B2)。
func TestDecoderBounded(t *testing.T) {
	d := newFECDecoder()
	// 灌入 10000 个不同 blockID 的孤立 parity(各自缺多个 data,永不恢复)
	for i := uint32(0); i < 10000; i++ {
		d.addParity(i, 4, []byte{1, 2, 3})
	}
	if len(d.blocks) > fecMaxBlocks {
		t.Fatalf("解码器块数 %d 超硬顶 %d(伪造 parity 可撑爆内存)", len(d.blocks), fecMaxBlocks)
	}
}

// 滑窗外(过旧)的 blockID 被丢弃,不建块。
func TestDecoderWindowDropsOld(t *testing.T) {
	d := newFECDecoder()
	d.addParity(1000, 4, []byte{1}) // 确立 highest=1000
	d.addParity(1, 4, []byte{1})    // 远低于窗口(1000-1>64)→ 应丢弃
	if _, ok := d.blocks[1]; ok {
		t.Fatal("窗口外的旧 blockID 不应建块")
	}
}
