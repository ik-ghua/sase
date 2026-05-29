# SASE Go Monorepo 目录规划

> **状态:** 工程结构规划 / 随编码演进
> **版本:** v0.1
> **日期:** 2026-05-25
> **设计者:** 花刚 <ghua@ikuai8.com>
>
> **依据:** 控制面 L2 总览 `sase-l2-control-plane-overview.md` 3.5(Go 包结构骨架)+ 各 L2 的模块/组件;扩展到全系统(控制面 + 数据面 PoP + 客户端 + 共享 + 契约 + 迁移 + 部署)。
>
> **原则:** ① `internal/` 机制阻止跨包乱 import(强化模块边界,总览 3.3);② `cmd/` 一进程一发布单元;③ `api/` 契约单一来源(proto/OpenAPI 生成,总览 3.6);④ 模块按 L1 实体/职责切,不按技术分层(总览 3.2);⑤ 数据面(PoP)与控制面进程分离但同仓共享 `internal/` 与 `api/`(地基统一)。

---

## 一、顶层布局

```
sase/                          # 仓库根(= /Users/hg/work/sase),单一 Go module
  go.mod  go.sum               # module: github.com/ikuai8/sase(占位,接入爱快内部 VCS 时调整)
  Makefile                     # build-all / build-single / test / lint / vet / migrate
  README.md
  cmd/                         # 发布单元入口(每个一个二进制)
    # —— 控制面三单元(控制面 L2 总览)
    api-server/                # ① 模块化单体 API(租户/身份/策略/资源/计费/admin/risk)
    xds-server/                # ② 配置分发(xDS server)
    telemetry/                 # ③ 遥测/审计管道
    # —— 数据面 / 边缘(后续 slice)
    pop-agent/                 # PoP 本机编排器(xDS client + 驱动 WG/Envoy/eBPF/PEP)
    agent/                     # 客户端 Agent(跨平台共享核心)
    connector/                 # App Connector(出站反向)
    cpe/                       # SD-WAN 软件 CPE
  internal/                    # 私有包(Go internal 机制禁外部 import → 守模块边界)
    # —— 控制面业务模块(6 + risk = 7)
    tenant/  identity/  policy/{authoring,compiler}/  resource/  billing/  admin/  risk/
    platform/                  # 平台级(PoP/容量,非租户作用域)
    # —— 控制面横切层
    data/                      # Postgres 访问 + RLS 上下文 + 事务(InTx/InTxRO)+ 迁移
    authz/  secret/  audit/
    # —— 控制面单元内部
    xds/                       # 单元② 内部:snapshot/资源构建
    telemetry/                 # 单元③ 内部
    # —— 数据面/边缘内部(后续)
    pop/  agent/  connector/  cpe/
    # —— 共享内核
    system/                    # booting(DI/生命周期)、config、log、httpx 等
  pkg/                         # 可被外部(客户端等)复用的稳定库(谨慎放;优先用 api/ 生成)
  api/
    openapi/                   # Admin REST 契约(单一来源)
    proto/                     # 内部 gRPC + xDS 自定义资源(单一来源)
  migrations/                  # schema 迁移(含 RLS 检查门禁)
  deploy/                      # IaC(Terraform/Ansible)、systemd 单元(后续,运维/部署 L2)
  docs/                        # 设计文档(已存在)
  poc/                         # PoC harness/结果(已存在)
```

---

## 二、与 L2 设计的对应

| 目录 | 对应 L2 | 说明 |
|------|---------|------|
| `cmd/api-server` + `internal/{tenant,identity,policy,resource,billing,admin,risk,platform}` + `internal/{data,authz,secret,audit}` | 控制面 L2 总览(6+risk 业务 + 4 横切 + 平台)| 模块化单体起步、内部接口边界 |
| `cmd/xds-server` + `internal/xds` | xDS server L2 | 消费 PolicyBundle/资源、下发 |
| `cmd/telemetry` + `internal/telemetry` | 遥测/审计管道 | Metrics/Logs/计量摄取 |
| `internal/policy/{authoring,compiler}` | 策略编译器 L2 | 编写态/执行态隔离(总览规则 4)|
| `internal/data`(InTx/InTxRO + RLS) | 数据访问层 L2 | sqlc+pgx、RLS 上下文、app_rw/app_ro |
| `internal/risk` | 信任/风险引擎 L2 | 第 7 业务模块 |
| `cmd/{pop-agent,agent,connector,cpe}` + `internal/{pop,agent,connector,cpe}` | PoP 编排 / 客户端 / CPE L2 | 数据面/边缘(后续 slice;加密栈待国密)|
| `api/{proto,openapi}` | 各 L2 契约 | 单一来源、生成代码 |
| `migrations/` | 数据访问层 L2 | RLS catalog 门禁 |
| `deploy/` | 运维/部署 L2 | IaC/systemd |

---

## 三、纵向切片(walking skeleton)推进顺序

> 目的:先证明**整套集成能跑通**(而非把水平设计全实现),逐刀加厚。每刀避开未定项(非国密档、用已评审的控制面 L2 + PoC-1 隔离结论)。

1. **Slice 0(本次):骨架可编译可跑** —— monorepo 结构 + `api-server` 健康端点 + booting/分层骨架 + `data` 的 `InTx/InTxRO` 接口形态(RLS 上下文占位)+ 一个业务模块(`tenant`)接口与桩。**仅标准库,离线可构建**;在 VM 上真编译验证。
2. **Slice 1:控制面最小可用** —— 接 Postgres + RLS(`data` 实)+ `tenant`/`identity` 最小 CRUD + Admin API(健康/创建租户)+ migrations + RLS catalog 门禁。
3. **Slice 2:策略下发链** —— `policy.compiler` 产最小 PolicyBundle → 落库 → `xds-server` 下发(自定义资源)→ 一个最小 `pop-agent` 收到并打印(验证控制面→PoP 契约)。
4. **Slice 3:最小 ZTNA 数据路径** —— Agent(非国密档,先 WireGuard/标准 TLS)→ PoP(最小 PEP 验凭证)→ Connector → echo 应用;在 VM 上跑通端到端。
5. 后续逐能力加厚(SWG/FWaaS/CASB、国密栈待 PoC-G、SPA/实时通道等)。

---

## 四、约定

- **模块边界**:业务模块只经 Go 接口互调,不读对方内部包/库表;`internal/` 机制 + 后续 depguard 门禁(总览 3.3)。
- **数据访问**:一律经 `internal/data` 的 `InTx`(读写,`app_rw`)/`InTxRO`(只读,`app_ro`),强制事务 + RLS 上下文(数据访问层 L2);不暴露裸连接。
- **契约**:proto/OpenAPI 为单一来源,生成代码;不手写请求类型(总览 3.6)。
- **构建**:`make build-all` 输出到 `./output/binary`;`make build-single s=api-server`。
- **module 路径**:占位 `github.com/ikuai8/sase`,接入爱快内部 VCS 时统一替换。

> 本规划随编码演进;新增模块/单元时按本布局放置并回写本文。
