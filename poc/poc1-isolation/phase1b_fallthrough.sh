#!/bin/bash
# PoC-1 Phase 1b:坐实 "SO_MARK+ip rule fall-through 跨租户可达" 漏洞,并验证修法。
# 发现:per-tenant 表无匹配时,ip rule 默认 fall-through 到 main 表;
#       若 main 表(共享 Envoy 所在 netns)有到他租户子网的连通路由 → mark=A 的包够到 B。
# 修法:每租户表加 `unreachable default`(或 blackhole),使表内无匹配即丢、不 fall-through。
set -u
PASS=0; FAIL=0
ok(){ echo "  [PASS] $1"; PASS=$((PASS+1)); }
no(){ echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }
cleanup(){
  pkill -f "TCP-LISTEN" 2>/dev/null
  ip rule del fwmark 0x1 lookup 101 2>/dev/null
  ip rule del fwmark 0x2 lookup 102 2>/dev/null
  ip netns del t-a 2>/dev/null; ip netns del t-b 2>/dev/null
  ip link del vetha 2>/dev/null; ip link del vethb 2>/dev/null
}
cleanup

cat >/tmp/mc.py <<'PY'
import socket,sys
mark=int(sys.argv[1]); host=sys.argv[2]; port=int(sys.argv[3])
s=socket.socket(); s.settimeout(3)
if mark>0: s.setsockopt(socket.SOL_SOCKET,36,mark)
try:
    s.connect((host,port)); print(s.recv(64).decode(errors="replace").strip() or "EMPTY")
except Exception as e: print("ERR:%s"%type(e).__name__)
PY
mc(){ timeout 6 python3 /tmp/mc.py "$@" 2>/dev/null; }

mk(){ local ns=$1 hostif=$2 nsif=$3 hostip=$4 nsip=$5 tag=$6
  ip netns add "$ns"; ip link add "$hostif" type veth peer name "$nsif"
  ip link set "$nsif" netns "$ns"; ip addr add "$hostip/30" dev "$hostif"; ip link set "$hostif" up
  ip netns exec "$ns" ip link set lo up
  ip netns exec "$ns" ip addr add "$nsip/30" dev "$nsif"; ip netns exec "$ns" ip link set "$nsif" up
  ip netns exec "$ns" ip addr add 100.64.0.10/32 dev lo
  ip netns exec "$ns" socat TCP-LISTEN:8080,bind=100.64.0.10,fork,reuseaddr SYSTEM:"echo $tag" &
  # 额外:在 t-b 的 veth 接口 IP 上也挂一个服务,用于坐实"够到 B 接口"
  ip netns exec "$ns" socat TCP-LISTEN:9090,bind="$nsip",fork,reuseaddr SYSTEM:"echo ${tag}-IFACE" &
  sleep 0.4
}

mk t-a vetha vetha-p 169.254.10.1 169.254.10.2 TENANT-A
mk t-b vethb vethb-p 169.254.20.1 169.254.20.2 TENANT-B
ip rule add fwmark 0x1 lookup 101
ip rule add fwmark 0x2 lookup 102
ip route add 100.64.0.10/32 via 169.254.10.2 dev vetha table 101
ip route add 100.64.0.10/32 via 169.254.20.2 dev vethb table 102

echo "############ 阶段A:仅 SO_MARK+ip rule(无兜底)############"
echo "main 表对 t-b 子网的可达性(共享 Envoy 所在 netns):"
ip route get 169.254.20.2 2>/dev/null | head -1
echo "-- mark=1 直连 t-b 接口 169.254.20.2:9090(期望:不该到 B)--"
RX=$(mc 1 169.254.20.2 9090); echo "  结果: '$RX'"
if echo "$RX" | grep -q "TENANT-B"; then
  no "漏洞坐实:mark=1 经 fall-through 够到了 t-b 接口(拿到 '$RX')"
  echo "      >>> 确认:SO_MARK+ip rule 单独【不足以】隔离;无匹配 fall-through 到 main 表跨租户可达"
else
  ok "mark=1 未够到 t-b(得 '$RX')——与预期漏洞不符,需再查"
fi

echo
echo "############ 阶段B:每租户表加 unreachable default(堵 fall-through)############"
ip route add unreachable default table 101
ip route add unreachable default table 102
echo "t101 现状:"; ip route show table 101
echo "-- 再测 mark=1 直连 t-b 接口 169.254.20.2:9090(期望:被封)--"
RY=$(mc 1 169.254.20.2 9090); echo "  结果: '$RY'"
echo "$RY" | grep -q "TENANT-B" && no "修法无效:仍够到 t-b" || ok "修法有效:mark=1 够不到 t-b(得 '$RY')"
echo "-- 回归:加兜底后,本租户复用地址仍正常 --"
RA=$(mc 1 100.64.0.10 8080); RB=$(mc 2 100.64.0.10 8080)
echo "  mark=1->'$RA' mark=2->'$RB'"
{ [ "$RA" = "TENANT-A" ] && [ "$RB" = "TENANT-B" ]; } && ok "加兜底后正常路径仍正确(A->A,B->B)" || no "兜底误伤正常路径"

echo
echo "== 结论 PASS=$PASS FAIL=$FAIL =="
cleanup
