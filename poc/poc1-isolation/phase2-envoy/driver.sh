#!/bin/bash
# 在 VM host 上编排 Phase 2(需 /tmp/envoy.yaml /tmp/setup_topo.sh 已就位)
set -u
NETSHOOT=docker.m.daocloud.io/nicolaka/netshoot:latest
ENVOY=docker.m.daocloud.io/envoyproxy/envoy:v1.31-latest
docker rm -f poc-root poc-envoy >/dev/null 2>&1

echo "== 起 poc-root(共享 Envoy netns)+ 搭拓扑(修法 unreachable default 默认 ON)=="
docker run -d --name poc-root --privileged -v /lib/modules:/lib/modules:ro "$NETSHOOT" sleep 3600 >/dev/null
docker cp /tmp/setup_topo.sh poc-root:/setup.sh
docker exec poc-root bash /setup.sh

echo "== 起真实 Envoy(共享 poc-root netns, root, 打 SO_MARK 需 NET_ADMIN)=="
# ENVOY_UID=0:阻止镜像 entrypoint 降权,使 Envoy 保持 root 持 CAP_NET_ADMIN(打 SO_MARK 必需)
docker run -d --name poc-envoy --network container:poc-root --privileged -e ENVOY_UID=0 \
  -v /tmp/envoy.yaml:/etc/envoy/envoy.yaml "$ENVOY" \
  -c /etc/envoy/envoy.yaml --log-level warning >/dev/null

echo -n "等待 Envoy listener 就绪"
for i in $(seq 1 30); do
  if docker exec poc-root bash -c 'exec 3<>/dev/tcp/127.0.0.1/10001' 2>/dev/null; then echo " ok"; break; fi
  echo -n "."; sleep 0.5
done
echo "listeners:"; docker exec poc-root ss -tlnp 2>/dev/null | grep -E '1000[123]' || echo "  (无 listener?见 envoy 日志)"

t(){ docker exec poc-root bash -c "exec 3<>/dev/tcp/127.0.0.1/$1 2>/dev/null && timeout 4 cat <&3 2>/dev/null"; }

echo "== 修法 ON:Envoy 上游打 SO_MARK + per-tenant 表(含 unreachable default)=="
RA=$(t 10001); RB=$(t 10002); RX=$(t 10003)
echo "  :10001 (cluster_a, mark=1) -> '$RA'   [期望 TENANT-A]"
echo "  :10002 (cluster_b, mark=2) -> '$RB'   [期望 TENANT-B]"
echo "  :10003 (错配 mark=1->B接口) -> '$RX'   [期望 被拦/空]"

echo "== 修法 OFF:删 table 101 的 unreachable default,复测错配 =="
docker exec poc-root ip route del unreachable default table 101 2>/dev/null
RX2=$(t 10003)
echo "  :10003 (错配 mark=1->B接口) -> '$RX2'  [若得 TENANT-B-IFACE = 真Envoy下也会跨租户泄漏]"

echo "== envoy 上游统计(connect_fail / cx_total)=="
docker exec poc-root bash -c 'timeout 3 curl -s 127.0.0.1:9901/clusters 2>/dev/null | grep -E "cx_connect_fail|cx_total" | grep -E "cluster_a:|cluster_b:|cluster_misroute:"' 2>/dev/null || true
echo "== cleanup =="
docker rm -f poc-root poc-envoy >/dev/null 2>&1; echo "removed; host netns 残留:"; ip netns list 2>/dev/null | grep -c "t-a\|t-b"
