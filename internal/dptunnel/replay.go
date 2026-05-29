package dptunnel

// replayWindow 防重放:接受单调递增计数器,容忍乱序(滑动窗口位图),拒绝重复/过旧计数器。
// 沿用 IPsec/WireGuard 同类机制。计数器由发送侧单调自增,与 AEAD nonce 同源 → 不复用 nonce
// (计数器接近回绕前须 rekey,属握手层职责,见 L2 7.1 待审查项)。
type replayWindow struct {
	last   uint64 // 已见的最大计数器
	bitmap uint64 // last 往前 64 个计数器的接收位图(bit i = last-i 已见)
	seen   bool
}

const replayWindowSize = 64

// accept 判定 counter 是否可接受(首见 → true 并记录;重复/过旧 → false)。
func (w *replayWindow) accept(counter uint64) bool {
	if !w.seen {
		w.seen = true
		w.last = counter
		w.bitmap = 1 // 标记 last 自身已见(bit0)
		return true
	}
	switch {
	case counter > w.last:
		shift := counter - w.last
		if shift >= replayWindowSize {
			w.bitmap = 1 // 远超窗口,重置位图(只标新 last)
		} else {
			w.bitmap = (w.bitmap << shift) | 1
		}
		w.last = counter
		return true
	case counter == w.last:
		return false // 重复
	default: // counter < last
		diff := w.last - counter
		if diff >= replayWindowSize {
			return false // 过旧,窗口外
		}
		mask := uint64(1) << diff
		if w.bitmap&mask != 0 {
			return false // 已见
		}
		w.bitmap |= mask
		return true
	}
}
