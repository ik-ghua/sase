#!/bin/sh
# deploy/agent-entrypoint.sh —— ZTNA 真 OS Agent 容器入口(Slice77 端到端演示)。
#
# 背景:cmd/agent(agentd.Daemon)握手成功后开 TUN(AGENT_TUN,如 saze0),并把 INTERNAL_CIDR 路由进 TUN
# (split-tunnel)。但 agentd 只 `ip link up` + 配路由,**不给 TUN 分配源 IP**——而隧道内层包须有合法源 IP
# (= PoP 回程能定位回本 Agent 的内层 IP)。故本脚本在 TUN 出现后给它配 AGENT_TUN_ADDR。
#
# 演示流量:容器内 `curl http://<internal-app-ip>` → dst ∈ INTERNAL_CIDR → 路由进 TUN → agentd 抓包封进
# dptunnel → PoP 终结 → PEP allow → 内核 SNAT 到 internal-app;回程原路返回。
#
# 必需 env(compose 注入):
#   AGENT_TUN        TUN 设备名(如 saze0)——须与 cmd/agent 的 AGENT_TUN 一致。
#   AGENT_TUN_ADDR   本 Agent 在 TUN 上的内层地址(CIDR,如 10.88.0.2/24)——隧道内层源 IP。
set -eu

: "${AGENT_TUN:?须设 AGENT_TUN(TUN 设备名,如 saze0)}"
: "${AGENT_TUN_ADDR:?须设 AGENT_TUN_ADDR(本 Agent TUN 内层地址 CIDR,如 10.88.0.2/24)}"

# 会话凭证:issue-session 把 token/jti 写入共享卷;本脚本读文件 → 导出 env(cmd/agent 读 SESSION_TOKEN/JTI)。
if [ -n "${SESSION_TOKEN_FILE:-}" ] && [ -f "$SESSION_TOKEN_FILE" ]; then
  SESSION_TOKEN="$(cat "$SESSION_TOKEN_FILE")"
  export SESSION_TOKEN
  echo "[agent-entrypoint] 已从 $SESSION_TOKEN_FILE 载入会话凭证(len=${#SESSION_TOKEN})"
else
  echo "[agent-entrypoint] 警告:未找到会话凭证文件 $SESSION_TOKEN_FILE —— PoP ZTNA 握手将因缺 cred 被拒" >&2
fi
if [ -n "${SESSION_JTI_FILE:-}" ] && [ -f "$SESSION_JTI_FILE" ]; then
  SESSION_JTI="$(cat "$SESSION_JTI_FILE")"
  export SESSION_JTI
fi

# 后台轮询器:等 TUN 出现(握手 + 建 TUN 通常秒级;60s 上限)→ 配内层 IP → 退出。
(
  i=0
  until ip link show "$AGENT_TUN" >/dev/null 2>&1; do
    i=$((i + 1))
    if [ "$i" -gt 120 ]; then
      echo "[agent-entrypoint] 等待 TUN $AGENT_TUN 出现超时(60s);Agent 可能握手失败" >&2
      exit 0
    fi
    sleep 0.5
  done
  echo "[agent-entrypoint] TUN $AGENT_TUN 已出现,配置内层 IP=$AGENT_TUN_ADDR"
  ip addr add "$AGENT_TUN_ADDR" dev "$AGENT_TUN" 2>/dev/null || true
  ip link set "$AGENT_TUN" up
  ip -br addr show "$AGENT_TUN" || true
) &

echo "[agent-entrypoint] exec agent(PID 1);握手成功后将创建 TUN=$AGENT_TUN,后台轮询器随后配内层 IP"
exec /app/app
