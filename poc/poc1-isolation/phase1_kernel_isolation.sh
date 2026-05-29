#!/bin/bash
# PoC-1 Phase 1: 内核级租户隔离语义验证(SO_MARK + ip rule + per-tenant table)
# 对应 sase-poc-plan.md I-2(出口绑定)/ I-3(内核兜底);L1 3.7 方案B(SO_MARK+ip rule)、3.6 地址复用。
# 场景(最硬):两个租户 t-a / t-b 复用【同一】overlay 地址 100.64.0.10。
# "共享 Envoy" = root netns 里打 SO_MARK 的 egress 连接,ip rule 按 mark 选 per-tenant 表。
# 在特权容器内运行;开头清理,可重复跑。
set -u
PASS=0; FAIL=0
ok(){ echo "  [PASS] $1"; PASS=$((PASS+1)); }
no(){ echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }

cleanup(){
  pkill -f "TCP-LISTEN:8080" 2>/dev/null
  ip rule del fwmark 0x1 lookup 101 2>/dev/null
  ip rule del fwmark 0x2 lookup 102 2>/dev/null
  ip netns del t-a 2>/dev/null; ip netns del t-b 2>/dev/null
  ip link del vetha 2>/dev/null; ip link del vethb 2>/dev/null
}
cleanup

echo "== env =="; ip -V; echo "kernel $(uname -r)"

mk_tenant(){ # ns hostif nsif hostip nsip tag
  local ns=$1 hostif=$2 nsif=$3 hostip=$4 nsip=$5 tag=$6
  ip netns add "$ns"
  ip link add "$hostif" type veth peer name "$nsif"
  ip link set "$nsif" netns "$ns"
  ip addr add "$hostip/30" dev "$hostif"; ip link set "$hostif" up
  ip netns exec "$ns" ip link set lo up
  ip netns exec "$ns" ip addr add "$nsip/30" dev "$nsif"
  ip netns exec "$ns" ip link set "$nsif" up
  ip netns exec "$ns" ip addr add 100.64.0.10/32 dev lo
  ip netns exec "$ns" socat TCP-LISTEN:8080,bind=100.64.0.10,fork,reuseaddr SYSTEM:"echo $tag" &
  sleep 0.4
}

# 打标客户端:用 python 设 SO_MARK(SO_MARK=36),最稳;读一行返回
cat >/tmp/mc.py <<'PY'
import socket,sys
mark=int(sys.argv[1]); host=sys.argv[2]; port=int(sys.argv[3])
s=socket.socket(); s.settimeout(3)
if mark>0: s.setsockopt(socket.SOL_SOCKET,36,mark)  # SO_MARK
try:
    s.connect((host,port)); data=s.recv(64).decode(errors="replace").strip()
    print(data if data else "EMPTY")
except Exception as e:
    print("ERR:%s"%type(e).__name__)
PY
mc(){ timeout 6 python3 /tmp/mc.py "$@" 2>/dev/null; }

echo "== 搭拓扑:t-a / t-b 复用 100.64.0.10 =="
mk_tenant t-a vetha vetha-p 169.254.10.1 169.254.10.2 TENANT-A
mk_tenant t-b vethb vethb-p 169.254.20.1 169.254.20.2 TENANT-B
ip rule add fwmark 0x1 lookup 101
ip rule add fwmark 0x2 lookup 102
ip route add 100.64.0.10/32 via 169.254.10.2 dev vetha table 101
ip route add 100.64.0.10/32 via 169.254.20.2 dev vethb table 102
echo "rules:"; ip rule show | grep fwmark
echo "t101:"; ip route show table 101
echo "t102:"; ip route show table 102

echo "== I-2:同一地址 100.64.0.10,按 SO_MARK 消歧 =="
RA=$(mc 1 100.64.0.10 8080); RB=$(mc 2 100.64.0.10 8080)
echo "  mark=1 -> '$RA' ; mark=2 -> '$RB'"
[ "$RA" = "TENANT-A" ] && ok "mark=1 命中 t-a" || no "mark=1 未命中 t-a(得 '$RA')"
[ "$RB" = "TENANT-B" ] && ok "mark=2 命中 t-b" || no "mark=2 未命中 t-b(得 '$RB')"
{ [ "$RA" = "TENANT-A" ] && [ "$RB" = "TENANT-B" ]; } && ok "同一 IP 按租户 mark 正确消歧" || no "消歧失败"

echo "== 无身份(mark=0,main表)访问 100.64.0.10:应不可达 =="
RM=$(mc 0 100.64.0.10 8080); echo "  mark=0 -> '$RM'"
echo "$RM" | grep -q TENANT && no "无身份竟可达(泄漏!)" || ok "无身份不可达(main 表无路由)"

echo "== I-3 兜底:mark=1(t-a)尝试 t-b 专属子网 169.254.20.2:应失败 =="
RX=$(mc 1 169.254.20.2 8080); echo "  mark=1 -> t-b subnet: '$RX'"
echo "$RX" | grep -q TENANT && no "mark=1 竟够到 t-b(跨租户泄漏!)" || ok "mark=1 够不到 t-b 域(table 101 无该路由)"

echo "== I-3 兜底2:table 101 是否含 t-b 路由 =="
ip route show table 101 | grep -q 169.254.20 && no "table 101 含 t-b 路由" || ok "table 101 无任何 t-b 路由"

echo
echo "== 结果:PASS=$PASS FAIL=$FAIL =="
[ "$FAIL" -eq 0 ] && echo "PHASE1_RESULT=ALL_PASS" || echo "PHASE1_RESULT=HAS_FAIL"
cleanup
