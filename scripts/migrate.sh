#!/bin/sh
# scripts/migrate.sh —— 按序应用 migrations/*.up.sql + seed,作为 docker-compose 的 migrate init 容器入口。
#
# 以 **superuser**(postgres)执行(migrations 含 CREATE ROLE,且 0013 视图 owner 须 superuser/BYPASSRLS,
# 否则跨租户视图静默少行 —— 见 0013 自检 DO 块)。幂等:迁移内多用 IF NOT EXISTS / CREATE OR REPLACE,
# 但仍记账到 schema_migrations 防重复跑(本脚本只做"未记账才跑")。
#
# 环境变量(由 compose 注入):
#   PGHOST      Postgres 主机(compose 服务名,如 postgres)
#   PGPORT      端口(默认 5432)
#   PGUSER      superuser(默认 postgres)
#   PGPASSWORD  superuser 密码
#   PGDATABASE  目标库(默认 sase)
#   MIGRATIONS_DIR  迁移目录(默认 /migrations)
#   SEED_FILE       可选 seed SQL(默认 /seed/seed.sql;不存在则跳过)
set -eu

PGHOST="${PGHOST:-postgres}"
PGPORT="${PGPORT:-5432}"
PGUSER="${PGUSER:-postgres}"
PGDATABASE="${PGDATABASE:-sase}"
MIGRATIONS_DIR="${MIGRATIONS_DIR:-/migrations}"
SEED_FILE="${SEED_FILE:-/seed/seed.sql}"

export PGPASSWORD="${PGPASSWORD:-postgres}"
PSQL="psql -v ON_ERROR_STOP=1 -h $PGHOST -p $PGPORT -U $PGUSER -d $PGDATABASE"

echo "[migrate] 等待 Postgres $PGHOST:$PGPORT 就绪..."
i=0
until pg_isready -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" >/dev/null 2>&1; do
  i=$((i + 1))
  if [ "$i" -gt 60 ]; then
    echo "[migrate] Postgres 60s 内未就绪,放弃" >&2
    exit 1
  fi
  sleep 1
done
echo "[migrate] Postgres 就绪"

# 记账表(append-only;记录已应用的迁移文件名,防重复跑)。
$PSQL -c "CREATE TABLE IF NOT EXISTS schema_migrations (filename text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now());"

# 按文件名排序遍历所有 *.up.sql(0001_..0024_.. 自然字典序即正确顺序)。
for f in $(ls "$MIGRATIONS_DIR"/*.up.sql | sort); do
  base=$(basename "$f")
  already=$($PSQL -tAc "SELECT 1 FROM schema_migrations WHERE filename = '$base'")
  if [ "$already" = "1" ]; then
    echo "[migrate] 跳过(已应用) $base"
    continue
  fi
  echo "[migrate] 应用 $base"
  $PSQL -f "$f"
  $PSQL -c "INSERT INTO schema_migrations (filename) VALUES ('$base');"
done
echo "[migrate] 全部迁移已应用"

# Seed(可选):种子 demo 数据。幂等(seed.sql 用 ON CONFLICT DO NOTHING)。
if [ -f "$SEED_FILE" ]; then
  echo "[migrate] 应用 seed $SEED_FILE"
  $PSQL -f "$SEED_FILE"
  echo "[migrate] seed 完成"
else
  echo "[migrate] 无 seed 文件($SEED_FILE),跳过"
fi

echo "[migrate] 完成"
