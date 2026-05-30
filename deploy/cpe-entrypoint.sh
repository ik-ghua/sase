#!/bin/sh
# deploy/cpe-entrypoint.sh —— SD-WAN CPE 容器入口(demo)。
#
# 背景:cmd/cpe 的 runTunnel 在握手成功后才创建 TUN 设备(SDWAN_TUN 指定名,如 sase0),并阻塞跑收发 pump。
# TUN 设备本身**无 IP/路由**——须在它出现后由本脚本配:① 本站点网关 IP(掩码=站点 CIDR);
# ② 通往**对端站点 CIDR** 的路由(经 TUN)。这样本地 ping/curl 对端站点 IP 的 L3 包才会进隧道。
#
# 设计:**后台轮询器**等 TUN 出现→配 IP+路由(它配完即退);**前台 exec /app/app**(cpe 成为 PID 1,
#   直接收信号、容器生命周期==cpe 生命周期)。不追踪 cpe 的子 PID——BusyBox ash 在 PID 1 下 `$!`/`kill -0`
#   不可靠(实测 `$!` 返回的 PID 与真实 cpe 进程不符),故只轮询 TUN 设备本身(有界超时),不做进程 liveness 判定。
#
# 必需 env(compose 注入):
#   SDWAN_TUN        TUN 设备名(如 sase0)——必须显式设,脚本据此轮询/配置。
#   CPE_TUN_ADDR     本站点在 TUN 上的地址(CIDR,如 10.10.0.1/24)——本站点 LAN 网段内一地址。
#   CPE_PEER_CIDR    对端站点 CIDR(如 10.20.0.0/24)——经 TUN 路由,使去对端的包进隧道。
#   （以及 cmd/cpe 自身的 TENANT/SITE/SDWAN_TUNNEL_ADDR/... 见 docker-compose.yml）
set -eu

: "${SDWAN_TUN:?须设 SDWAN_TUN(TUN 设备名,如 sase0)}"
: "${CPE_TUN_ADDR:?须设 CPE_TUN_ADDR(本站 TUN 地址 CIDR,如 10.10.0.1/24)}"
: "${CPE_PEER_CIDR:?须设 CPE_PEER_CIDR(对端站点 CIDR,如 10.20.0.0/24)}"

# 后台轮询器:等 TUN 出现(握手 + 建 TUN 通常秒级;60s 上限)→ 配 IP + 对端路由 → 退出。
# cpe 握手失败则 TUN 永不出现 → 轮询器超时退出(仅告警,不杀 cpe;cpe 自身会因握手失败退出 → 容器退出)。
(
  i=0
  until ip link show "$SDWAN_TUN" >/dev/null 2>&1; do
    i=$((i + 1))
    if [ "$i" -gt 120 ]; then
      echo "[cpe-entrypoint] 等待 TUN $SDWAN_TUN 出现超时(60s);cpe 可能握手失败" >&2
      exit 0
    fi
    sleep 0.5
  done
  echo "[cpe-entrypoint] TUN $SDWAN_TUN 已出现,配置 IP=$CPE_TUN_ADDR 路由→$CPE_PEER_CIDR"
  # 幂等容错:重复 add 报错不致命(|| true);本站 CIDR 由 addr 的 on-link 路由覆盖,对端 CIDR 显式经 TUN。
  ip addr add "$CPE_TUN_ADDR" dev "$SDWAN_TUN" 2>/dev/null || true
  ip link set "$SDWAN_TUN" up
  ip route add "$CPE_PEER_CIDR" dev "$SDWAN_TUN" 2>/dev/null || true
  echo "[cpe-entrypoint] TUN 就绪:"
  ip -br addr show "$SDWAN_TUN" || true
  ip route show dev "$SDWAN_TUN" || true
) &

echo "[cpe-entrypoint] exec cpe 二进制(PID 1);握手成功后将创建 TUN=$SDWAN_TUN,后台轮询器随后配 IP/路由"
exec /app/app
