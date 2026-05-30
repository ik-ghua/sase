//go:build !linux

package ztnaterm

// redirect_other.go 是透明代理(Slice78)在非 linux 平台的 stub:SO_ORIGINAL_DST / iptables REDIRECT 是
// Linux 特性(本机 Mac 仅为编译/单测 ztnaterm 其余逻辑)。stub 使 cmd/pop-agent 在 Mac 可编译;
// 真正透明代理只在 linux 容器(deploy)运行。

import (
	"context"
	"log"
	"net"
)

// RunRedirectProxy 在非 linux 平台为 no-op(SO_ORIGINAL_DST 不可用):接受连接即关(不泄漏)。
// 真实运行在 linux 容器(redirect_linux.go)。
func (tm *Terminator) RunRedirectProxy(ctx context.Context, lis net.Listener) {
	log.Printf("[ztnaterm] 透明代理仅 linux 支持(SO_ORIGINAL_DST);本平台为 no-op,关闭 listener")
	go func() { <-ctx.Done(); _ = lis.Close() }()
	for {
		conn, err := lis.Accept()
		if err != nil {
			return
		}
		_ = conn.Close() // 非 linux 无法取原始目的 → fail-closed 关连接
	}
}
