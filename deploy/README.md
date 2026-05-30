# SASE 一键演示部署(deploy/)

把全栈一键跑起来用于**现场演示**:Postgres + 迁移 + dev mTLS 证书 + 控制面(api-server)+
配置分发(xds-server)+ 一个 PoP(pop-agent)+ **两个 SD-WAN 分支站点 CPE(cpe-site-a/b)经真隧道互通**,
并种子一个 demo 租户 + 两站点 + ZTP 入网 + FWaaS 放行规则 + 一枚引导 platform_admin 令牌。

> ⚠️ **全部 dev/演示用途**:自签 mTLS 证书(私钥在共享 volume)、内存 DevProvider KEK、bootstrap 令牌进日志、
> 容器以 root 跑、Postgres 弱密码。**生产严禁原样使用**(证书须 PoP CA/KMS 经独立分发、KEK 走 KMS/HSM、
> 角色密码经 secret 注入、服务最小权限非 root)。

---

## 一、起栈

```bash
cd deploy
cp .env.example .env          # 可选:仅在要改默认值时
docker compose up -d --build  # 首次构建 3 个 Go 镜像(api-server/xds-server/pop-agent)+ devpki,约几分钟
docker compose ps             # 看各服务状态(api-server 显示 healthy 即就绪)
```

启动编排(由 `depends_on` + healthcheck 保证顺序):

1. `postgres`(healthy)→ 2. `devpki`(生成证书到共享 volume,跑完退出 0)+ `migrate`(应用
   migrations 0001–0024 + seed,跑完退出 0)→ 3. `api-server`(等 healthy)+ `xds-server` →
   4. `pop-agent`(等 api-server healthy)。

停栈:

```bash
docker compose down       # 停容器,保留数据卷(pgdata/certs)
docker compose down -v    # 连数据卷一起删(干净重来)
```

---

## 二、访问 / 演示

### 1. 健康检查与签发公钥(无需鉴权)

```bash
curl -sk https://localhost:8443/healthz                 # → ok
curl -sk https://localhost:8443/api/v1/trust/pubkey     # → {"alg":"ed25519","pubkey":"..."}
```

(`-k`:管理面是自签 HTTPS。`/healthz` 本身也在 TLS 之后。)

### 2. 取引导 platform_admin 令牌

api-server 启动时为 `SASE_BOOTSTRAP_PLATFORM_ADMIN`(默认 `ops@demo.local`)签发一枚 **15 分钟**有效的
platform_admin 令牌,打印在日志:

```bash
docker compose logs api-server | grep -A1 "引导 platform_admin 令牌"
# 复制下一行那串 JWT,即 TOKEN
```

> 令牌只 15min 有效;过期后 `docker compose restart api-server` 会重新签发一枚(bootstrap env 仍在)。

### 3. 用令牌调管理 API(平台跨租户读)

```bash
TOKEN=<上一步复制的 JWT>
curl -sk -H "Authorization: Bearer $TOKEN" https://localhost:8443/api/v1/platform/tenants
# → [{"id":"11111111-...","name":"Demo 公司","status":"active","plan":"standard",...}]

curl -sk https://localhost:8443/api/v1/platform/tenants    # 无令牌 → 401
```

这条路径串起:bootstrap RBAC → authz 中间件 → `app_platform_ro` 角色 → 策展视图 `tenant_summary`(跨租户只读)。

### 4. 数据路径(PoP 已接入控制面)

`pop-agent` 已订阅 demo 租户的策略/撤销/SWG/FW/DLP/站点资源(经 mTLS gRPC 连 `xds-server`),
并经 `TRUST_URL` 从 api-server 取签发公钥离线验凭证:

```bash
docker compose logs pop-agent | grep 装载
# → 装载 SWG/DLP/站点/吊销 规则 tenant=11111111-... N 条(初始 0,经控制台/API 下发后变化)
```

PoP 接入面在 `:8081`(mTLS),连接器反向注册口 `:7000`。完整 ZTNA 端到端(agent 连接器
→ PoP → 上游)需另起 `cmd/agent` / `cmd/connector` / `cmd/echo-app`,本 demo 栈未含(见"未做项")。

### 5. SD-WAN 真隧道:两分支站点经 PoP 互通(本栈已开)

本栈含两个 **SD-WAN 软件 CPE** 容器(`cpe-site-a` 北京 10.10.0.0/24 / `cpe-site-b` 上海 10.20.0.0/24),
经**真 dptunnel 隧道**(TUN + UDP + ChaCha20-Poly1305 AEAD,非 revtunnel L7 stand-in)过 pop-agent 互通:

- 每个 CPE 凭 ZTP 激活码(seed 预置)换取**租户绑定证书**(tenant=Organization / site=CommonName,W9);
- 与 pop-agent 做 **mutual-TLS 握手**(`tunhandshake`,RFC5705 导出会话密钥);
- 建 TUN 设备 `sase0`,容器入口脚本(`cpe-entrypoint.sh`)配本站网关 IP + 对端站点路由;
- 站点间转发经 pop-agent 的 `dptunnel.Router`:解封 → **FWaaS L3/L4 裁决**(seed 放行 site-a↔site-b)→ 按内层 dst IP 在租户路由域内选路 → 重封转发到对端 CPE。

验证(站点 A → 站点 B,真隧道):

```bash
docker compose exec cpe-site-a ping -c 4 10.20.0.1   # → 0% packet loss(经隧道 + PoP + FWaaS allow)
docker compose exec cpe-site-b ping -c 4 10.10.0.1   # 反向同样可达
# TCP L4 也通(在 site-b 起监听,site-a 连):
docker compose exec -d cpe-site-b sh -c "echo hi-from-b | nc -l -p 9999 -w 5"
docker compose exec    cpe-site-a sh -c "echo probe | nc -w 3 10.20.0.1 9999"   # → 回显 hi-from-b

# FWaaS 默认拒绝可见(去掉 seed 的 allow 规则则站点间被丢,计入丢包指标):
docker compose exec pop-agent sh -c "wget -qO- http://127.0.0.1:9101/metrics | grep tunnel_drops"
# → sase_pop_tunnel_drops_total{reason="firewall_deny"} N(无 FW allow 规则时站点间转发全丢)
```

> **依赖**:CPE 容器需 `cap_add: NET_ADMIN` + `devices: /dev/net/tun`(compose 已配)。Docker Desktop 的
> 容器是 Linux,可建 TUN。CPE 的 ZTP 激活码**一次性**:首次成功握手后入网记录置 `redeemed`;**重起 CPE
> 须 `docker compose down -v` 全清重来**(否则旧码已兑换 → ZTP 401)。算法档 dev 用 `chacha20poly1305`
> (非国密);国密 SM4-GCM 档待国密 CPU(`SDWAN_TUNNEL_ALG=sm4gcm`,见 gm-crypto 选型)。

### 5. /metrics(内部抓取,容器内可达)

各服务 `/metrics` 端口(未对宿主暴露,容器网络内 Prometheus/VictoriaMetrics 抓):
api-server `:9100`(管理面 RED)+ `:9101`(设备面);xds-server `:9102`;pop-agent `:9101`。

---

## 三、前端控制台(可选)

前端 `web/admin` 未打进本 compose(避免陷入 nginx/构建,以后端栈能起为主)。本地起前端(对齐
Slice49/51 的 vite proxy 经验):

```bash
cd web/admin
pnpm install
VITE_API_TARGET=https://localhost:8443 pnpm dev   # vite proxy /api → compose 的 api-server
# 浏览器开 http://localhost:5173,登录页 dev token tab 粘上面第 2 步的 JWT
```

compose 的 `SASE_CSRF_ALLOWED_ORIGINS` 默认已含 `http://localhost:5173`(跨源写放行)。

---

## 四、env / 端口对账(从 cmd/*/main.go 实读)

### api-server(`cmd/api-server/main.go`)

| 用途 | env | 默认 | compose 值 |
|---|---|---|---|
| 管理 HTTPS | `ADMIN_ADDR` | `:8443` | `:8443`(宿主 `ADMIN_PORT`) |
| 控制+遥测 gRPC | `AGENTCTL_ADDR` | `:8082` | `:8082`(宿主 `AGENTCTL_PORT`) |
| 设备 ZTP 续期 mTLS | `DEVICE_ADDR` | `:8444` | `:8444`(宿主 `DEVICE_PORT`) |
| 管理面 /metrics | `SASE_API_METRICS_ADDR` | `:9100` | `:9100`(不暴露宿主) |
| 设备面 /metrics | `SASE_DEVICE_METRICS_ADDR` | `:9101` | `:9101`(不暴露宿主) |
| 四 DSN | `SASE_DB_RW_DSN` / `SASE_DB_RO_DSN` / `SASE_DB_PLATFORM_DSN` / `SASE_DB_PLATFORM_RW_DSN` | (无则退桩 / 平台端点 503) | 指向 `postgres:5432`,角色 app_rw/app_ro/app_platform_ro/app_platform_rw |
| 证书目录 | `SASE_TLS_DIR` | `./certs` | `/certs`(共享 volume) |
| 引导首枚 admin | `SASE_BOOTSTRAP_PLATFORM_ADMIN` | (空=不引导) | `.env` `BOOTSTRAP_PLATFORM_ADMIN` |
| 凭证 ed25519 种子 | `SASE_CRED_ED25519_SEED` | (空=临时随机) | 固定 base64url(解码恰 32B) |
| secret dev KEK | `SASE_DEV_KEK` | (空=临时随机) | 固定 base64(StdEncoding,解码恰 32B) |
| CSRF 允许源 | `SASE_CSRF_ALLOWED_ORIGINS` | (空=同源回退) | `http://localhost:5173,https://localhost:8443` |
| 遥测角色门控 | `SASE_TELEMETRY_REQUIRE_POP_ROLE` | 关 | 未设(dev 关;生产置 1) |
| 凭证算法 | `SASE_CRED_ALG` | `ed25519` | 未设(默认 ed25519) |
| sweep cron | `SASE_SWEEP_INTERVAL` | (空=不启) | 未设 |

### xds-server(`cmd/xds-server/main.go`)

| 用途 | env | 默认 | compose 值 |
|---|---|---|---|
| ADS/Delta mTLS gRPC | `XDS_ADDR` | `:9090` | `:9090` |
| /metrics | `METRICS_ADDR` | `:9102` | `:9102` |
| DSN(RW/RO) | `SASE_DB_RW_DSN` / `SASE_DB_RO_DSN` | (必须) | 指向 postgres |
| 证书目录 | `SASE_TLS_DIR` | `./certs` | `/certs` |
| 订阅授权严格模式 | `SASE_XDS_REQUIRE_CERT_SCOPE` | 关 | `.env` `XDS_REQUIRE_CERT_SCOPE`(默认 0;生产 1) |
| 周期对账间隔 | `SASE_XDS_RECONCILE_INTERVAL` | `30s` | 未设(默认 30s) |

### pop-agent(`cmd/pop-agent/main.go`)

| 用途 | env | 默认 | compose 值 |
|---|---|---|---|
| xDS 地址 | `XDS_ADDR` | `127.0.0.1:9090` | `xds-server:9090` |
| TrustBundle 来源(api-server HTTPS) | `TRUST_URL` | `https://127.0.0.1:8443` | `https://api-server:8443` |
| 遥测上报(api-server gRPC) | `TELEMETRY_ADDR` | (空=本地日志兜底) | `api-server:8082` |
| **租户(必填)** | `TENANT` | (无则 fatal) | demo 租户 UUID(与 seed 一致) |
| PoP 标识 | `NODE` | `pop-dev` | `.env` `POP_NODE`(默认 pop-demo) |
| 接入面 | `INGRESS_ADDR` | `:8081` | `:8081`(宿主 `INGRESS_PORT`) |
| 连接器口 | `CONNECTOR_ADDR` | `:7000` | `:7000` |
| /metrics | `METRICS_ADDR` | `:9101` | `:9101` |
| 证书目录 | `SASE_TLS_DIR` | `./certs` | `/certs` |
| W9 fail-closed | `SASE_REQUIRE_CERT_TENANT` | 关 | `.env` `REQUIRE_CERT_TENANT`(默认 0;生产 1) |
| SD-WAN 握手 | `SDWAN_TUNNEL_ADDR` | (空=不启) | `:7200`(本 demo 已开 SD-WAN) |
| SD-WAN 数据面 UDP | `SDWAN_DATA_ADDR` | `:7100` | `:7100` |
| SD-WAN 数据面通告地址 | `SDWAN_DATA_ADV` | (默认本地监听地址) | `pop-agent:7100`(容器网络内 CPE 可达) |
| SD-WAN 算法档 | `SDWAN_TUNNEL_ALG` | `chacha20poly1305` | `.env` `SDWAN_TUNNEL_ALG`(国密 `sm4gcm` 待国密 CPU) |

### cpe-site-a / cpe-site-b(`cmd/cpe/main.go`,SD-WAN 软件 CPE)

| 用途 | env | 默认 | compose 值 |
|---|---|---|---|
| 租户 | `TENANT` | (必填) | demo 租户 UUID |
| 站点逻辑键(=证书 CN) | `SITE` | (必填) | `site-a` / `site-b` |
| ZTP 激活码 | `ZTP_CODE` | (空=回退共享证书) | `.env` `SITE_A_ZTP_CODE` / `SITE_B_ZTP_CODE`(须与 seed 一致) |
| 管理面(ZTP /enroll) | `MGMT_URL` | `https://localhost:8443` | `https://api-server:8443`(ServerName 仍验 localhost) |
| 设备面(续期) | `DEVICE_URL` | `https://localhost:8444` | `https://api-server:8444` |
| SD-WAN 真隧道开关 | `SDWAN_TUNNEL` | 关 | `1` |
| PoP 握手地址 | `SDWAN_TUNNEL_ADDR` | (必填) | `pop-agent:7200` |
| 本端数据面 UDP | `SDWAN_DATA_ADDR` | `127.0.0.1:0` | `:7101`(固定端口) |
| 本端通告地址 | `SDWAN_DATA_ADV` | (默认本地监听地址) | `cpe-site-a:7101`(服务名→容器 IP,与源地址一致) |
| TUN 设备名 | `SDWAN_TUN` | (内核分配) | `sase0` |
| TUN 本站地址(entrypoint 用) | `CPE_TUN_ADDR` | — | `10.10.0.1/24` / `10.20.0.1/24` |
| 对端站点 CIDR(entrypoint 用) | `CPE_PEER_CIDR` | — | `10.20.0.0/24` / `10.10.0.0/24` |

> `SDWAN_DATA_ADV` 是 T1 新增的本端通告地址覆盖:容器/多址下 `dataConn.LocalAddr()`(`0.0.0.0`/ephemeral)
> 不是 PoP 可达地址,须显式设为**服务名:固定端口**——既是 PoP 回程目的,又须与 PoP 看到的 UDP 源地址一致
> (非 NAT 下 Docker 服务名解析的 IP == 源 IP),否则 PoP `bySrc` 解复用命中失败(`no_session` 丢包)。

### devpki(`cmd/devpki/main.go`)

| 用途 | env | 默认 | compose 值 |
|---|---|---|---|
| 证书输出目录 | `OUT` | `./certs` | `/certs`(共享 volume) |

产出:`ca.{crt,key}` / `server.{crt,key}`(SAN: `localhost`, `xds-server`)/ `client.{crt,key}`(role-less 兜底)/
`pop.{crt,key}`(role:pop)/ `device.{crt,key}`(role:device)。

> **mTLS ServerName 注意**:pop-agent 连 api-server 时把 TLS ServerName 钉为 `localhost`(`fetchPubkey`),
> 连 xds-server / 遥测时钉为 `xds-server`——两者都在 server 证书 SAN 内,故 compose 服务名(`api-server`/`xds-server`)
> 与证书 SAN 不需一致,验证靠 SAN 而非连接 host。

---

## 五、迁移与种子(scripts/)

- `scripts/migrate.sh`:migrate init 容器入口。以 **superuser**(postgres)按文件名序应用
  `migrations/*.up.sql`(0001–0024),记账到 `schema_migrations` 防重复;末尾跑 seed。
  **必须 superuser**:迁移含 `CREATE ROLE`,且 0013 的跨租户视图 owner 须 superuser/BYPASSRLS(否则视图静默少行)。
- `scripts/seed.sql`:种子一个固定 UUID 的 demo 租户(`11111111-...`,Demo 公司)+ 一个 demo 用户(alice@demo.local)。
  幂等(`ON CONFLICT DO NOTHING`)。
  > 经直接 SQL 种子的租户**没有 tenant_keys(DEK)行**——`tenant.Create()` 走 API 才同事务建 DEK。
  > 本 demo 数据路径不依赖 DEK;要演示带 DEK 的真租户,经控制台/管理 API 新建。

PG 版本要求 **>= 15**(migration 0020 的 `NULLS NOT DISTINCT`),compose 用 `postgres:16-alpine`。

---

## 六、制品清单

| 文件 | 作用 |
|---|---|
| `deploy/Dockerfile` | 多阶段:`golang:1.22` build 任一 cmd(build-arg `CMD`)→ alpine 运行镜像 |
| `deploy/docker-compose.yml` | 编排 postgres + devpki + migrate + api-server + xds-server + pop-agent |
| `deploy/.env.example` | 可覆盖的环境变量(角色密码/端口/引导 admin/密钥/硬化开关) |
| `deploy/README.md` | 本文件 |
| `.dockerignore`(仓库根) | 排除 node_modules/.pnpm-store/certs/output 等,精简 build context |
| `scripts/migrate.sh` | 迁移 + seed 运行脚本(migrate 容器入口) |
| `scripts/seed.sql` | demo 租户/用户种子 |

---

## 七、未做项 / 诚实标注

- **ZTNA 完整数据路径端到端未含**:本 demo 起到「PoP 接入控制面 + 订阅资源」。完整
  agent→连接器→PoP→上游 echo 需另起 `cmd/agent`/`cmd/connector`/`cmd/echo-app`(各有 env/证书需求),
  本栈聚焦"后端栈能起 + 控制台/API 可演示"。
- **SD-WAN 数据面隧道已开(T1)**:见"二、5"。两站点经真 dptunnel 隧道 + FWaaS L4 互通已端到端跑通。
  诚实局限:① 仅非国密档(`chacha20poly1305`);国密 `sm4gcm` 待国密 CPU。② 单 PoP 实例(单租户);
  多 PoP / per-PoP 租户分配未含。③ 非 NAT 假设(`SDWAN_DATA_ADV` 须与源地址一致);NAT 下 receiver-index
  待握手 L2 §4.4。④ ZTP 激活码一次性、硬编码于 seed(重起须 `down -v`);生产经管理 API 动态签发。
  ⑤ CPE TUN 配 IP/路由由 `cpe-entrypoint.sh` 在 TUN 出现后做(cpe 二进制本身不配,真实 CPE 由本地编排配)。
- **前端未打进镜像**:见"三、前端控制台",本地 `pnpm dev` + `VITE_API_TARGET`。
- **dev 安全取舍**:容器以 root 跑(共享 certs volume 私钥 0600)、自签 mTLS、内存 KEK、
  bootstrap 令牌进日志、PG 弱密码——全部生产严禁(见顶部 ⚠️)。
- **seed 租户无 DEK**:见"五、迁移与种子"。
