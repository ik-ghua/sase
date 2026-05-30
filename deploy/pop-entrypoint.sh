#!/bin/sh
# deploy/pop-entrypoint.sh —— PoP 容器入口(Slice77 ZTNA 终结 + 出站 SNAT)。
#
# 背景:pop-agent 的 ZTNA 终结器(ZTNA_TUNNEL_ADDR/ZTNA_DATA_ADDR)在启动时开一个 PoP 侧 TUN(ZTNA_TUN
# 指定名,如 saze0)。**allow 的内层包**写入该 TUN → 须经内核转发 + SNAT 到内部应用,回程经 conntrack
# 返回 TUN → 终结器 Seal 回 Agent。Go 侧只开 TUN + 读写包;**ip_forward/路由/MASQUERADE 在本脚本配**
# (§3.4 b:出站 = PoP-TUN + 内核 SNAT)。
#
# 必需 env(compose 注入):
#   ZTNA_TUN          PoP-TUN 设备名(如 saze0)——必须显式设,与 pop-agent 的 ZTNA_TUN 一致。
#   ZTNA_POP_TUN_ADDR PoP-TUN 上的地址(CIDR,如 10.88.0.1/24)——其网段须含 Agent 内层源 IP,
#                     使回程包(dst=Agent 内层 IP)经路由进 TUN 被终结器读到、Seal 回 Agent。
#   ZTNA_EGRESS_IF    出口网卡名(SNAT 经此出站到 app,默认 eth0)。
#   ZTNA_AGENT_CIDR   Agent 内层源网段(MASQUERADE 限定源,默认 = ZTNA_POP_TUN_ADDR 的网段)。
# 可选 env(Slice78 零暴露透明代理):
#   ZTNA_PROXY_PORT     透明代理 listener 端口(与 pop-agent 的 ZTNA_PROXY_PORT 一致)。
#   ZTNA_REDIRECT_CIDRS 逗号分隔的 connector-backed CIDR;到这些目的的 TCP 经 iptables REDIRECT 到 ZTNA_PROXY_PORT
#                       由透明代理终结(连接级 PEP + connector 反向出站),不走 PoP-TUN SNAT。
set -eu

: "${ZTNA_TUN:?须设 ZTNA_TUN(PoP-TUN 名,如 saze0)}"
: "${ZTNA_POP_TUN_ADDR:?须设 ZTNA_POP_TUN_ADDR(PoP-TUN 地址 CIDR,如 10.88.0.1/24)}"
EGRESS_IF="${ZTNA_EGRESS_IF:-eth0}"
AGENT_CIDR="${ZTNA_AGENT_CIDR:-$(echo "$ZTNA_POP_TUN_ADDR" | sed 's#\.[0-9]*/#.0/#')}"

# 内核 IP 转发:优先由 compose 的 sysctls(启动时应用,/proc/sys 在容器内只读不能运行期改)。
# 这里只**校验**已开;未开(=0)才尝试运行期写(裸 docker run 未带 sysctl 时的兜底),仍失败则告警。
IPF="$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)"
if [ "$IPF" != "1" ]; then
  echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || sysctl -w net.ipv4.ip_forward=1 2>/dev/null || \
    echo "[pop-entrypoint] 警告:ip_forward 未开且无法运行期开启(请用 compose sysctls 或 docker run --sysctl net.ipv4.ip_forward=1)" >&2
else
  echo "[pop-entrypoint] ip_forward 已开启(由 compose sysctls)"
fi

# 出站 SNAT(MASQUERADE):Agent 内层源经出口网卡出站时改写源地址,使 app 回程可经 conntrack 回到 PoP。
iptables -t nat -C POSTROUTING -s "$AGENT_CIDR" -o "$EGRESS_IF" -j MASQUERADE 2>/dev/null || \
  iptables -t nat -A POSTROUTING -s "$AGENT_CIDR" -o "$EGRESS_IF" -j MASQUERADE 2>/dev/null || \
  echo "[pop-entrypoint] 警告:配置 MASQUERADE 失败(出站源 NAT 可能不通)" >&2

# 后台轮询器:等 PoP-TUN 出现(pop-agent 启动即开)→ 配 IP(给 Agent 内层网段的回程路由)→ up →
# (Slice78)给 connector-backed CIDR 配 REDIRECT 透明代理规则。
(
  i=0
  until ip link show "$ZTNA_TUN" >/dev/null 2>&1; do
    i=$((i + 1))
    if [ "$i" -gt 120 ]; then
      echo "[pop-entrypoint] 等待 PoP-TUN $ZTNA_TUN 出现超时(60s);ZTNA 终结可能未启用" >&2
      exit 0
    fi
    sleep 0.5
  done
  echo "[pop-entrypoint] PoP-TUN $ZTNA_TUN 已出现,配置 IP=$ZTNA_POP_TUN_ADDR(回程网段 $AGENT_CIDR)"
  ip addr add "$ZTNA_POP_TUN_ADDR" dev "$ZTNA_TUN" 2>/dev/null || true
  ip link set "$ZTNA_TUN" up
  echo "[pop-entrypoint] PoP-TUN 就绪;SNAT 源=$AGENT_CIDR 出口=$EGRESS_IF:"
  ip -br addr show "$ZTNA_TUN" || true
  iptables -t nat -L POSTROUTING -n 2>/dev/null | grep -i masq || true

  # Slice78 零暴露透明代理:把 connector-backed CIDR 的 TCP REDIRECT 到本地 ZTNA_PROXY_PORT。
  # REDIRECT 改目的为 127.0.0.1:<port>;入向 TUN 的包目的是非本地 IP(VIP),内核默认不路由到 lo,
  # 故须对 TUN 开 route_localnet=1(允许把目的视为本地回环路由)。仅命名空间内生效。
  if [ -n "${ZTNA_PROXY_PORT:-}" ] && [ -n "${ZTNA_REDIRECT_CIDRS:-}" ]; then
    sysctl -w "net.ipv4.conf.${ZTNA_TUN}.route_localnet=1" 2>/dev/null || \
      echo 1 > "/proc/sys/net/ipv4/conf/${ZTNA_TUN}/route_localnet" 2>/dev/null || \
      echo "[pop-entrypoint] 警告:开 ${ZTNA_TUN}.route_localnet 失败(REDIRECT 可能不通)" >&2
    # all.route_localnet 兜底(部分内核 REDIRECT 经 all 生效)。
    sysctl -w "net.ipv4.conf.all.route_localnet=1" 2>/dev/null || true
    OLDIFS="$IFS"; IFS=','
    for cidr in $ZTNA_REDIRECT_CIDRS; do
      cidr="$(echo "$cidr" | tr -d ' ')"
      [ -z "$cidr" ] && continue
      iptables -t nat -C PREROUTING -i "$ZTNA_TUN" -p tcp -d "$cidr" -j REDIRECT --to-ports "$ZTNA_PROXY_PORT" 2>/dev/null || \
        iptables -t nat -A PREROUTING -i "$ZTNA_TUN" -p tcp -d "$cidr" -j REDIRECT --to-ports "$ZTNA_PROXY_PORT" 2>/dev/null || \
        echo "[pop-entrypoint] 警告:配置 REDIRECT $cidr → :$ZTNA_PROXY_PORT 失败" >&2
      echo "[pop-entrypoint] 零暴露 REDIRECT:$cidr (tcp) → 透明代理 :$ZTNA_PROXY_PORT"
    done
    IFS="$OLDIFS"
    iptables -t nat -L PREROUTING -n 2>/dev/null | grep -i redirect || true
  fi
) &

echo "[pop-entrypoint] exec pop-agent(PID 1);ZTNA 终结器启动后将创建 PoP-TUN=$ZTNA_TUN,后台轮询器随后配 IP"
exec /app/app
