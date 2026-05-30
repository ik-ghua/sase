#!/bin/sh
# deploy/devpki-entrypoint.sh —— devpki init 容器入口(demo;**幂等**封装)。
#
# 背景:devpki(cmd/devpki)每次跑都**重新生成自签 CA + 叶证书**。compose 的 `docker compose up -d <子集>`
# 会为满足 `depends_on: service_completed_successfully` 而**重跑** restart:"no" 的 devpki → 重生成 CA →
# 与已在运行、持旧 CA 的 api-server/pop-agent 不一致 → mTLS 校验 "certificate signed by unknown authority"。
#
# 修法(纯 deploy 层,不动 cmd/devpki):若共享卷已有 ca.crt 则**跳过**生成(幂等)——首次 down -v 后 up
# 仍正常生成一套;之后 partial up 重跑本容器只是 no-op,不破坏在运行服务的证书一致性。
# 要强制重生成:`docker compose down -v` 清卷(连同 pgdata)后再 up。
set -eu

OUT="${OUT:-/certs}"
if [ -f "$OUT/ca.crt" ] && [ -f "$OUT/server.crt" ] && [ -f "$OUT/pop.crt" ] && [ -f "$OUT/device.crt" ]; then
  echo "[devpki-entrypoint] $OUT 已有完整证书集,跳过生成(幂等;清卷重生成请 down -v)"
  exit 0
fi
echo "[devpki-entrypoint] 生成 dev mTLS 证书到 $OUT"
exec /app/app
