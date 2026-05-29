#!/bin/bash
# 在 poc-root(共享 Envoy 所在 netns)内搭拓扑:t-a/t-b 复用 100.64.0.10;
# per-tenant 表 + ip rule;默认带 unreachable default(修法 ON)。
set -u
ip netns del t-a 2>/dev/null; ip netns del t-b 2>/dev/null
ip link del vetha 2>/dev/null; ip link del vethb 2>/dev/null
ip rule del fwmark 0x1 lookup 101 2>/dev/null
ip rule del fwmark 0x2 lookup 102 2>/dev/null

mk(){ local ns=$1 hostif=$2 nsif=$3 hostip=$4 nsip=$5 tag=$6
  ip netns add "$ns"; ip link add "$hostif" type veth peer name "$nsif"
  ip link set "$nsif" netns "$ns"; ip addr add "$hostip/30" dev "$hostif"; ip link set "$hostif" up
  ip netns exec "$ns" ip link set lo up
  ip netns exec "$ns" ip addr add "$nsip/30" dev "$nsif"; ip netns exec "$ns" ip link set "$nsif" up
  ip netns exec "$ns" ip addr add 100.64.0.10/32 dev lo
  ip netns exec "$ns" socat TCP-LISTEN:8080,bind=100.64.0.10,fork,reuseaddr SYSTEM:"echo $tag" &
  ip netns exec "$ns" socat TCP-LISTEN:9090,bind="$nsip",fork,reuseaddr SYSTEM:"echo ${tag}-IFACE" &
  sleep 0.3
}
mk t-a vetha vetha-p 169.254.10.1 169.254.10.2 TENANT-A
mk t-b vethb vethb-p 169.254.20.1 169.254.20.2 TENANT-B
ip rule add fwmark 0x1 lookup 101
ip rule add fwmark 0x2 lookup 102
ip route add 100.64.0.10/32 via 169.254.10.2 dev vetha table 101
ip route add 100.64.0.10/32 via 169.254.20.2 dev vethb table 102
# 修法(默认 ON):每租户表 unreachable default,堵 fall-through
ip route add unreachable default table 101
ip route add unreachable default table 102
echo "topo ready; t101:"; ip route show table 101
echo "rules:"; ip rule show | grep fwmark
