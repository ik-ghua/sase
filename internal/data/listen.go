package data

import (
	"context"
	"log"
	"time"

	"github.com/jackc/pgx/v5"
)

// NotifyChannelPolicyBundle 是策略 bundle 变更通知通道(policy 写时 NOTIFY,xds-server LISTEN)。
// 解 xDS server L2 LC4 / 3.5:DB 变更经 LISTEN/NOTIFY 低延迟触发 xds-server 重建快照下发。
const NotifyChannelPolicyBundle = "policy_bundle_changed"

// NotifyChannelRevocation 是撤销变更通知通道(identity 撤销时 NOTIFY,xds-server LISTEN 经独立流推送)。
// 秒级失效(ZTNA 硬化 L2 3.4 / xDS server L2 3.7)。
const NotifyChannelRevocation = "revocation_changed"

// NotifyChannelSWG 是 SWG 规则变更通知通道(安全栈 L2:SWG 规则经独立流下发 PoP)。
const NotifyChannelSWG = "swg_changed"

// NotifyChannelSite 是 SD-WAN 站点变更通知通道(站点清单经 xDS 下发各 CPE)。
const NotifyChannelSite = "site_changed"

// NotifyChannelFW 是 FWaaS 规则变更通知通道(安全栈 L2:FW 规则经独立流下发 PoP)。
const NotifyChannelFW = "fw_changed"

// NotifyChannelDLP 是 CASB-DLP 规则变更通知通道(安全栈 L2:DLP 规则经独立流下发 PoP)。
const NotifyChannelDLP = "dlp_changed"

// ListenNotify 在专用连接上 LISTEN channel,每条通知回调 onNotify(payload)。连接断开自动重连,
// 直到 ctx 取消。注:NOTIFY 不持久,断连期间通知会丢 —— 调用方须在(重)连后做一次全量对账
// (xDS server L2 3.5)。**onReconnect(可空)在每次成功 LISTEN 后调一次**(首连 + 每次重连),
// 调用方据此做全量对账兜底断连期间丢失的通知;本函数仍负责实时信号 onNotify。
func ListenNotify(ctx context.Context, dsn, channel string, onNotify func(payload string), onReconnect func()) error {
	for ctx.Err() == nil {
		if err := listenOnce(ctx, dsn, channel, onNotify, onReconnect); err != nil && ctx.Err() == nil {
			// 记一行:NOTIFY 通道静默断开运维无感知(断连期间的通知会丢,重连后 onReconnect 全量对账兜底)
			log.Printf("[data] LISTEN %s 断开,1s 后重连: %v", channel, err)
			time.Sleep(time.Second)
			continue
		}
	}
	return ctx.Err()
}

func listenOnce(ctx context.Context, dsn, channel string, onNotify func(string), onReconnect func()) error {
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, "LISTEN "+pgx.Identifier{channel}.Sanitize()); err != nil {
		return err
	}
	// LISTEN 已就位:此刻起新 NOTIFY 不会再丢。先做一次全量对账,补上「断连~LISTEN 就位」窗口内丢失的通知。
	if onReconnect != nil {
		onReconnect()
	}
	for {
		n, err := conn.WaitForNotification(ctx)
		if err != nil {
			return err
		}
		onNotify(n.Payload)
	}
}
