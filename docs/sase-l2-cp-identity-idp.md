# 控制面 L2 子文档 · 身份与 IdP

> **状态:** L2 组件设计 / 机制深挖 / 待评审
> **版本:** v0.1
> **日期:** 2026-05-24
> **设计者:** 花刚 <ghua@ikuai8.com>
>
> **层级与上承:** L2 子文档,深挖**控制面 `identity` 模块**。上承控制面 L2 总览 `sase-l2-control-plane-overview.md` 的 3.2(`identity` 模块:IdP 配置与适配器、用户/组、SCIM 同步、令牌交换)、3.4(IdP 适配机制点名:adapter 接口 + 企微/钉钉/飞书、IdP 认证后换发自签短 TTL 凭证不透传 IdP 长令牌);及 L1 `sase-architecture-design.md` v0.6 的 **3.4(IdP 对接 + 令牌模型)**、3.3(`IdPConfig`/`User`/`Group`/`Device`)、3.8(身份+姿态+持续验证、短 TTL、快速撤销)、3.5(Agent 证书:IdP 认证→CSR→短期证书)、3.6(Agent 入网拉配置)、3.11(`Enroll` 协议、SCIM)、3.2(身份与租户绑定,令牌不跨租户)、3.12(PoP 失陷爆炸半径)、R6(国产 IdP/SaaS API 维护成本)、R7(国密影响凭证签名算法)。
>
> **衔接下游文档:** **解策略编译器子 L2 `sase-l2-cp-policy-compiler.md` 的 RP7**——本文定义的**凭证声明 schema** 即 `subject` 选择器(group/device-posture)与运行期条件的**输入,二者同源**;为 xDS server 子 L2 `sase-l2-cp-xds-server.md` 生产 `RevocationTable` 与 `TrustBundle`(凭证验证公钥)(及 `WGPeerSet` 的公钥来源);IdP 密钥经数据访问层子 L2 `sase-l2-cp-data-access-rls.md` 的 `secret` 边界存 KMS 引用。
>
> **为什么深挖它:** 它是租户"开通即用"的入口,客群(金融/政企/央国企/网络科技公司)**强依赖国产 IdP**(企微/钉钉/飞书);且"IdP 认证 → 自签短 TTL 凭证"是连接身份与数据面策略求值的桥(L1 3.4/3.8)。
>
> **范围:** adapter 接口与协议适配、令牌交换与自签短 TTL 凭证、凭证声明 schema、入网认证流、用户/组同步(SCIM+JIT)、持续验证/刷新/撤销、多租户 IdP 隔离与密钥保护、适配器维护与降级。
>
> **不含(明确边界):** **PEP 在 PoP 侧如何验凭证**(PoP L2);**Agent 侧如何持凭证/采集姿态/刷新**(客户端 Agent L2);**凭证签名的具体国密算法**(待 R7/PoC-G,算法敏捷,见 3.2);各国产 IdP 的**具体 API 字段/端点**(易变,待确认,见 3.1/3.8)。**本文定"控制面身份逻辑 + 凭证契约",不定端侧/PoP 侧实现。**
>
> **设计先行:** 含机制与契约语义说明,**不写代码、不搭脚手架**。每个决策配依据 / 备选及落选 / 可行方案;未定项标「待确认 / 待客户端 L2 / 待 PoP L2」。

---

## 目录

- 一、背景
- 二、目标
- 三、设计
  - 3.1 adapter 接口抽象与协议适配
  - 3.2 令牌交换与自签短 TTL 凭证
  - 3.3 凭证声明 schema(解 RP7)
  - 3.4 入网与认证流(证书 vs 凭证)
  - 3.5 用户/组同步(SCIM + JIT)
  - 3.6 持续验证、刷新、撤销
  - 3.7 多租户隔离与 IdP 密钥保护
  - 3.8 适配器维护与降级(R6)
- 四、风险
- 五、结论与衔接
- 附录:待确认 / 待客户端 L2 / 待 PoP L2

---

## 一、背景

L1 3.4 定 IdP 对接覆盖标准(OIDC/SAML/SCIM)+ 企微/钉钉/飞书,并定**令牌模型**:IdP 认证后控制面**自签短 TTL 凭证**,不把 IdP 长令牌透给数据面;L1 3.8 定 ZTNA 用"身份 + 姿态 + 策略"求值、短 TTL、姿态/风险变化即快速撤销;R6 指出国产 IdP/SaaS API 变更带来维护成本,需契约隔离。总览把这些归入 `identity` 模块、点名 adapter 接口与令牌交换。

本文回答:**多种 IdP(含非标准国产)如何统一接入、IdP 认证如何换成数据面可离线验证的短 TTL 凭证、凭证里带什么(供策略求值)、用户/组怎么同步、撤销怎么传到数据面。** 凭证声明 schema 同时是策略编译器 `subject` 选择器的输入契约(解其 RP7)。

---

## 二、目标(可衡量)

1. **统一 adapter 接口**:OIDC/SAML/SCIM 与企微/钉钉/飞书经同一接口接入;第三方 API 变更被隔离在 adapter 内(R6)。
2. **令牌交换**:IdP 认证 → 控制面自签**短 TTL 会话凭证**;**不透传 IdP 长令牌到数据面**;凭证可被 PoP/PEP **离线验证**(对接 fail-static,L1 3.1)。
3. **凭证声明 schema**:定清 claims,使其**恰好是**策略编译器 `subject` 选择器(group/posture)与运行期条件的输入(同源,解 RP7)。
4. **用户/组同步**:SCIM 推送为主 + JIT 兜底;`Group.source` 区分;成员变动可传播到授权。
5. **持续验证与撤销**:短 TTL 静默刷新;姿态/风险/IdP 禁用触发撤销 → 经 `RevocationTable` 下发(xDS 子 L2);控制面不可达时短 TTL 兜底。
6. **多租户隔离**:每租户独立 IdP 配置;令牌只走该租户 IdP、不跨租户(L1 3.2);凭证绑租户。
7. **IdP 密钥保护**:IdP client_secret 等只存 KMS 引用(L1 3.3/3.5),不入库明文。

**非目标:** PEP 验凭证实现(PoP L2);Agent 持凭证/采姿态/刷新实现(客户端 L2);凭证签名国密算法选定(待 PoC-G,算法敏捷);各国产 IdP 具体 API 字段(易变,待确认)。

---

## 三、设计

### 3.1 adapter 接口抽象与协议适配

**背景** IdP 形态差异大:OIDC/SAML 是标准协议;企微/钉钉/飞书是各自的 OAuth2 变体 + 私有通讯录 API,且 API 会变(R6)。

**目标** 定统一 adapter 接口,把差异与变更收敛在 adapter 内,上层 `identity` 逻辑与具体 IdP 无关。

**设计 —— 统一 adapter 接口(逻辑职责,非完整签名)**

下表 IdP 对应 `IdPConfig.type ∈ {oidc, saml, wecom(企业微信), dingtalk(钉钉), feishu(飞书)}`(L1 3.3 枚举);adapter 按 type 选实现。
- `StartAuth(tenant, ctx) → 重定向/扫码引导`:发起认证(各 IdP 的授权码/扫码/免登流)。
- `CompleteAuth(tenant, callback) → ExternalIdentity{external_id, email, raw_attrs}`:处理回调、校验、取外部身份。
- `FetchGroups(tenant, external_id) → []GroupRef`:取用户组/部门(映射到 `Group`,L1 3.3)。
- `(可选) SyncDirectory(tenant) → []User/Group`:SCIM 或通讯录全量/增量同步(3.5)。
- adapter 把各 IdP 的字段**映射到内部模型**(`User.external_id/email/group_ids`、`Group.source`,L1 3.3)。

| IdP | 协议 | 适配要点 | 状态 |
|-----|------|---------|------|
| OIDC | 标准 | 授权码 + id_token 校验 | 标准 |
| SAML | 标准 | SP 发起/IdP 发起、断言校验 | 标准 |
| SCIM | 标准 | 用户/组推送供给(3.5) | 标准 |
| 企业微信 | OAuth2 变体 + 通讯录 API | 网页授权/扫码、通讯录取部门 | **具体端点/字段待确认** |
| 钉钉 | OAuth2 变体 + 通讯录 API | 登录 + 通讯录 | **具体端点/字段待确认** |
| 飞书 | OAuth2 变体 + 通讯录 API | 登录 + 通讯录 | **具体端点/字段待确认** |

依据:统一接口使新增/变更 IdP = 实现一个 adapter,不动 `identity` 核心与下游(凭证、策略);把 R6 的维护成本**局部化**在 adapter。
- 备选:为每种 IdP 在 `identity` 内写专用分支。落选:第三方 API 变更扩散到核心逻辑,违背 R6 契约隔离。
- 可行:国产 IdP 的具体端点/字段易变,作为 adapter **内部实现 + 契约测试**(3.8),不进核心契约;字段细节列待确认(附录)。

**风险** 国产 IdP API 变更致 adapter 失效 → 契约测试 + 监控 + 版本(3.8);非标准流(扫码/免登)语义差异 → adapter 内吸收,对外暴露统一 `ExternalIdentity`。

**结论** 统一 adapter 接口(StartAuth/CompleteAuth/FetchGroups/SyncDirectory),差异与变更局部化在 adapter;国产 IdP 具体字段待确认、作 adapter 内部实现 + 契约测试。

**as-built(Slice37a):** 落地为 `internal/oidc` 模块独立(与 `identity` 分:`identity` 持用户/凭证模型与发凭证,`oidc` 持登录流程编排)。**标准 OIDC adapter 已通(generic)**:Adapter 接口收敛到 `AuthURL(state, code_verifier, redirect_uri) → URL` + `Exchange(code, code_verifier, redirect_uri) → UserInfo`(StartAuth/CompleteAuth 的最小化版),无状态,验证经 httptest mock IdP 完整 OIDC 流(discovery/token/userinfo/JWKS+RS256+id_token 校验+PKCE S256)+ JWKS 拒伪签。**FetchGroups 走 `UserInfo.Groups` 字段**(若 IdP groups scope 配了),SyncDirectory/SCIM 暂未做(后续刀)。**厂商 adapter(企微/钉钉/飞书)**未做——三家都不完全标准 OIDC,需 `cfg.Kind` 派发到各自 factory(Slice37b)。**登录端点**单一 callback URL `/api/v1/idp/callback`,租户/IdP 信息走服务端 `InMemoryStateStore`(state ID=256bit 随机 b64url capability,**`TakeOnce` 一次性 + 取后即删防重放**,TTL 5min)+ janitor;`/idp/login + /callback` 在 authz 公开白名单(未认证)。3.6 用户/组同步 SCIM = Slice37c。

---

### 3.2 令牌交换与自签短 TTL 凭证

**背景** L1 3.4/3.8 核心安全机制:不把 IdP 长令牌透给数据面,控制面换发自签短 TTL 凭证。数据面(PEP)还要能在控制面不可达时验证它(fail-static)。

**目标** 定令牌交换流与凭证的可验证形态。

**设计**
- **交换:** IdP 认证成功(3.1)→ `identity` 模块用外部身份解析内部 `User`(3.5)→ **签发控制面自有的短 TTL 会话凭证**(claims 见 3.3)。**IdP 的 access/refresh token 留在控制面,绝不下发数据面**(L1 3.4)。
- **可离线验证(关键):** 凭证为**自包含、签名**的令牌(JWS 式),PoP/PEP 用**签发方公钥离线验证**,无需每次回调控制面。依据:**fail-static**(L1 3.1)——控制面可能不可达、且每请求回调不可接受(热路径),故凭证必须自包含可离线验。
  - 备选:**不透明令牌 + 在线 introspection**。落选:每次验证需在线回调控制面,违背 fail-static 与热路径(L1 3.1/3.19),且控制面成单点。
- **签名密钥:** 凭证由控制面**专用签发密钥**签名(其私钥在控制面侧受保护,不下发 PoP);**验证公钥经 xDS 的 `TrustBundle` 资源下发到 PoP**(xDS 子 L2 3.1;下发形态/打包待 LX10/LI7 契约定)。PoP/PEP 不持签发私钥 → **PoP 失陷不能伪造凭证**(限爆炸半径,L1 3.12)。
- **签名算法(算法敏捷):** 默认随国密选型(`sase-gm-crypto-selection.md`:国密档用 SM2,其余可 ECDSA),经其 crypto provider 抽象切换;**算法选定待 PoC-G**,本文只定"自包含签名 + 离线验证"形态,不锁算法。注:**"自签会话凭证签名"是 crypto provider 的新增签发用途**——已并入 gm-crypto provider 用途清单,且 PoC-G **M-G2 已实测**(SM2 签名 ≈ Ed25519,凭证/PKI 无性能顾虑;crypto-agility `internal/cred` 算法可插拔已码,LI3 收口)。
- **TTL:** 分钟级(L1 3.1/3.8);**具体值建议 ~5min,待确认/待调**(权衡:越短撤销兜底越快、刷新负载越高,3.6)。

**风险** 签发密钥泄露=可伪造任意凭证 → 私钥受 HSM/KMS 保护(L1 3.5)、可轮换、短有效期签发密钥;凭证重放 → 短 TTL + 绑定设备证书(3.4)/会话;时钟偏移致验证误判 → 允许小幅 skew + PoP 时钟同步(机制待 PoP L2,附录 LI9)。

**结论** IdP 认证→控制面自签短 TTL 自包含凭证、IdP 长令牌不下发;PoP 用下发的公钥离线验(对接 fail-static);签发私钥不下发 PoP(限爆炸半径);算法随国密选型敏捷切换、TTL 分钟级(值待定)。

---

### 3.3 凭证声明 schema(解 RP7)

**背景** 策略编译器子 L2 把 `subject` 保持为选择器(group/device-posture),求值期由 PEP 用**凭证里的身份/组/姿态声明**匹配,并留 RP7:声明 schema 须与选择器同源。本文是该 schema 的**定义方**。

**目标** 定凭证 claims,使其恰好覆盖策略求值所需,且与 `subject` 选择器、运行期条件同源。

**设计 —— 会话凭证 claims(逻辑,字节级编码待契约)**

| claim | 含义 | 供谁 |
|-------|------|------|
| `iss` | 签发方(控制面) | PoP 验签 |
| `tenant_id` | 租户(绑定,不跨租户) | 隔离(L1 3.2)/作用域 |
| `sub` | 用户 id(`User.id`) | 审计/选择器 |
| `groups` | 组 id 列表(`User.group_ids`) | **策略 `subject` 的 group 选择器**(编译器 3.1) |
| `posture` | 设备姿态摘要(签发时点) | **`subject` 的 device-posture 选择器**输入(编译器 3.1/3.6);**posture 不作 `condition`**——与编译器"condition=time/geo/risk、posture 不在此"口径一致 |
| `device` | 设备证书指纹/`cert_serial`(L1 3.3) | 绑设备(3.4)、撤销关联 |
| `risk` | 风险分(签发时点,可选) | 运行期 risk 条件输入(编译器 3.6) |
| `exp`/`iat` | 过期/签发时刻 | TTL(3.2)、time 条件基准 |
| `aud` | 受众(租户/范围) | 防跨租户/跨用途重用 |

- **同源保证(解 RP7):** `groups`/`posture`/`risk` 的取值定义在**本 schema(`api/proto` 单一来源,总览 3.6)**,策略编译器的选择器/条件**引用同一 schema**;契约测试覆盖二者一致(对接编译器 RP7)。本 schema **同时为编译器 LP4 的 `posture`/`risk` 取值域提供来源**(geo 来源不在本文,仍属编译器 LP4)。
- **posture 的时效:** 凭证携带**签发时点**的姿态摘要;TTL 内姿态变化由刷新(3.6,下次签发更新摘要)或撤销(姿态恶化即撤,3.6)处理。**Agent 如何采集 posture 属客户端 L2**;本文只定 posture 在凭证中的**字段契约**,取值域与 Agent 上报对齐(待客户端 L2,附录)。
- **risk 来源:** 遥测/姿态派生(L1 3.8/3.14),签发时取值;本文只消费。

依据:claims 恰好覆盖策略求值输入且单一来源,消除"凭证有什么 vs 策略要什么"的漂移(编译器 RP7 的根因)。

**风险** schema 演进致新旧凭证字段不一致 → 版本字段 + 向后兼容(对接 L1 3.11 协议演进);posture 摘要过大 → 摘要化(布尔/枚举集)而非全量姿态,全量留 Agent 侧。

**结论** 定义会话凭证 claims(tenant/sub/groups/posture/device/risk/exp/aud),与策略 `subject` 选择器/条件**同源于 `api/proto`**,解 RP7;posture 携签发时点摘要、取值域待与客户端 L2 对齐。

---

### 3.4 入网与认证流(证书 vs 凭证)

**背景** L1 3.11 `Enroll{idp_token, device_info, csr} → {cert(短期), pop_list, tenant_domains, split_tunnel_rules, policy_version}`。这里有**两类身份物**易混:设备**证书**(mTLS 传输身份)与会话**凭证**(授权声明)。

**目标** 厘清入网流与两类身份物的职责。

**设计 —— 入网流**
1. Agent 经 IdP 认证(3.1)拿到外部身份;设备本地生成密钥对 + **CSR**(L1 3.5,私钥不离设备)。
2. `identity` 校验认证、解析 `User`,协同 PKI(L1 3.5):
   - **签发短期设备证书**(Agent CA,L1 3.5)——**传输身份**:用于 mTLS、WireGuard peer 绑定(`WGPeerSet`,xDS 子 L2)、`device` claim 关联。
   - **签发短 TTL 会话凭证**(3.2/3.3)——**授权声明**:用于 PEP 策略求值。
3. 返回(对接 L1 3.11 Enroll 响应):证书 + 凭证 + `pop_list` + `tenant_domains` + `split_tunnel_rules` + `policy_version`(后几项来自 `resource`/`policy` 模块,本文只在身份环节衔接)。

**两类身份物的区别(关键):**
| | 设备证书 | 会话凭证 |
|--|---------|---------|
| 身份 | 设备/传输 | 用户会话授权 |
| 签发 | Agent CA(PKI,L1 3.5) | 控制面签发密钥(3.2) |
| 用途 | mTLS、WG peer、绑设备 | PEP 策略求值(claims,3.3) |
| 生命周期 | 短期(小时/天,3.5) | 短 TTL(分钟,3.2) |
| 验证 | PKI 链 + 吊销表 | 签发公钥离线验 + 吊销表 |

依据:传输身份(证书)与授权声明(凭证)职责不同、生命周期不同,分离避免"用证书扛授权"或"用凭证扛传输"的耦合;两者都可经吊销表撤销(3.6)。

**风险** 两者生命周期不一致致状态错配 → 凭证绑 `device`(cert_serial),证书撤销连带凭证失效(3.6);Enroll 一步失败的部分状态 → 入网为原子(证书+凭证一并成功或回滚)。

**结论** 入网=IdP 认证 + CSR → 短期设备证书(传输身份,PKI)+ 短 TTL 会话凭证(授权,3.2/3.3)+ 拉配置;两类身份物职责/生命周期分离、经 `device` 关联、均可撤销。

---

### 3.5 用户/组同步(SCIM + JIT)

**背景** L1 3.3 `Group.source ∈ {scim, idp}`。用户/组从 IdP 来,需保持同步,组成员决定策略 `subject` 匹配(编译器 3.1)。

**目标** 定用户/组的供给与同步策略。

**设计 —— SCIM 推送为主 + JIT 兜底**
- **SCIM 推送(主,当 IdP 支持):** IdP 经 SCIM 主动推用户/组增删改到控制面(`Group.source=scim`);保持目录与授权同步。
- **JIT 兜底(首次登录即建):** IdP 不支持/未配 SCIM 时,首次登录从 IdP 声明(3.1 `FetchGroups`)**即时创建/更新** `User`/`Group`(`Group.source=idp`)。
- **国产 IdP:** 企微/钉钉/飞书的通讯录同步走 adapter 的 `SyncDirectory`(3.1),其 SCIM 支持参差 → **JIT 兜底保证可用**。
- **成员变动传播:** SCIM 推送/重新登录刷新 `group_ids` → 影响后续凭证 claims(3.3);**已签发凭证在 TTL 内不变**,变动经下次刷新(3.6)或撤销生效。

依据:SCIM 保实时同步但国产支持不一,JIT 保证"未配 SCIM 也能用";二者覆盖客群现实(L1 3.4 国产 IdP)。
- 备选:仅 SCIM。落选:国产 IdP SCIM 支持参差,部分租户无法开通。
- 备选:仅 JIT(每次登录拉)。落选:用户禁用/离职若不重新登录则不被感知 → 须配合 SCIM/定期同步 + 撤销(3.6)。

**风险** SCIM 与 JIT 双源不一致 → `Group.source` 标明来源、同一组不双源管理;离职用户未及时同步 → SCIM 禁用事件触发撤销(3.6)+ 定期同步兜底 + 短 TTL 限窗口。

**结论** SCIM 推送为主 + JIT 兜底(国产 IdP 尤需);`Group.source` 区分来源;成员变动经刷新/撤销在短 TTL 内生效。

---

### 3.6 持续验证、刷新、撤销

**背景** L1 3.8:持续验证、短 TTL、姿态/风险变化即快速撤销;撤销走 L1 3.1 快速通道(吊销表)。本文是撤销的**生产侧**(消费侧是 xDS 子 L2/PoP)。

**目标** 定刷新与撤销的触发与传播。

**设计**
- **静默刷新:** 凭证近过期时 Agent 静默换新(重走令牌交换的轻量路径,带更新的 posture/risk,3.3);依据:短 TTL(3.2)需自动续期以不打断会话(L1 3.8)。
- **撤销触发(任一即撤):** ① IdP 侧禁用/离职(SCIM 事件,3.5);② 设备姿态恶化(L1 3.8);③ 风险升高;④ 管理员手动;⑤ 设备证书撤销(连带,3.4)。
- **撤销传播:** `identity`(/PKI)把被撤的凭证/证书/会话写入 **`RevocationTable`** → 经 **xDS 独立高优先流**下发 PoP(xDS 子 L2 3.7),PEP 即时拒绝。
- **不可达兜底:** 控制面/ xDS 不可达时,**短 TTL 到期自动失效**(L1 3.1/3.5)——撤销的最终保证不依赖网络可达。即:吊销表=可达时快撤,短 TTL=不可达时终撤(与 xDS 子 L2 3.7 一致)。

依据:刷新保会话连续 + 撤销双保(吊销表快 + 短 TTL 兜底),实现 L1 3.8"持续验证、撤销实时"且不违 fail-static。

**风险** 刷新风暴(大量凭证同期到期)→ 刷新时间抖动(jitter)分散;撤销表增长 → 只列未过期凭证(过期者自然失效,无需列),控制表大小;撤销延迟 → 走独立流(xDS 3.7)+ 单列 SLO(xDS 3.10/LX9)。

**结论** 短 TTL 静默刷新保会话;五类触发 → 写 `RevocationTable` → xDS 独立流即时下发;控制面不可达靠短 TTL 兜底;撤销表只列未过期项。

---

### 3.7 多租户隔离与 IdP 密钥保护

**背景** L1 3.2 第 3 层:身份与租户绑定,令牌不跨租户;L1 3.3/3.5:IdP secret 只存 KMS 引用。

**目标** 定身份维度的多租户隔离与 IdP 凭据保护。

**设计**
- **每租户 IdP 配置:** `IdPConfig` 按 `tenant_id`(L1 3.3,受 RLS,数据层子 L2);认证只走**该租户配置的 IdP**,不跨租户。
- **凭证绑租户:** 会话凭证 `tenant_id` + `aud`(3.3)绑租户;PoP/PEP 校验租户匹配,防跨租户重用。
- **IdP 凭据保护:** IdP `client_secret`、SAML 签名材料等**经 `secret` 模块加密落库**(L1 3.3/3.5/3.16),不入库明文、不出控制面;明文仅在 Create/Update 请求体短窗内存。**as-built(Slice36):** 选了"信封加密直存"实现路径——`encrypted_client_secret bytea`(`secret.Encrypt`/`Decrypt` 经 GetDEK + ChaCha20-Poly1305 + 12B 随机 nonce + 16B tag,DEK 用完即弃);**等价于 KMS 引用方案**(KEK 由 Provider 持/将来上 HSM,wrapped_dek 落库,与业务密文同存)、少一跳查询。`Config` 响应 struct 有意不含 `ClientSecret` 字段防序列化泄漏;DEK 销毁后 Decrypt→`secret.ErrDestroyed`(L1 3.16 不可逆删除工程化,链路证据测试已覆盖)。
- **adapter 多租户:** adapter 实例/调用按租户隔离,一个租户的 IdP 故障/配置错不影响他租户(对接 L1 3.2 吵闹邻居理念)。

依据:IdPConfig 受 RLS + 凭证绑租户 + secret 只存引用,使身份维度的隔离与 PKI/数据维度一致(L1 3.2 三层)。

**风险** 凭证 `aud`/`tenant` 校验遗漏致跨租户重用 → PEP 强制校验(PoP L2 契约)+ 隔离测试(对接数据层子 L2 3.9 风格);IdP 配置变更影响在线会话 → 变更不撤已签发凭证(短 TTL 内有效),新认证用新配置。

**结论** 每租户 IdP 配置受 RLS、令牌不跨租户、凭证绑租户+aud;IdP 密钥只存 KMS 引用经 secret 模块;adapter 按租户隔离。

---

### 3.8 适配器维护与降级(R6)

**背景** L1 R6:国产 IdP/SaaS API 变更带来维护成本,需契约隔离 + 监控。

**目标** 定 adapter 的契约稳定性与第三方 API 变更时的降级。

**设计**
- **契约隔离:** adapter 对外是稳定接口(3.1),第三方 API 细节在 adapter 内;变更只改 adapter,不扩散(R6)。
- **契约测试:** 对每个国产 IdP adapter,用录制的真实响应/沙箱做契约测试(CI);第三方 API 变更致测试红 → 及早发现。
- **监控:** 运行期监控各 IdP 的认证成功率/延迟/错误码;异常突变告警(对接遥测,L1 3.14)。
- **降级:** 某 IdP 临时不可用 → 该租户该 IdP 登录失败并明确报错(不静默放行、不降级安全);已在线会话靠短 TTL 内有效 + 到期后受影响(不伪造延续)。
- **版本:** adapter 跟随第三方 API 版本,锁定 + 计划升级(类比 L1 3.21 选型维护)。

依据:契约隔离 + 契约测试 + 监控把 R6 的维护成本控制在 adapter 层、且变更可观测;降级**绝不放宽安全**(失败即拒)。

**风险** 第三方 API 无沙箱致契约测试失真 → 录制真实响应回放 + 生产监控补足;长尾 IdP 维护负担 → 优先三家(企微/钉钉/飞书)+ 标准 OIDC/SAML 覆盖其余。

**结论** adapter 契约隔离 + 契约测试 + 运行监控 + 失败即拒的降级(不放宽安全);维护成本局部化在 adapter,优先三家国产 + 标准协议兜底。

---

## 四、风险

### RI1:凭证签发私钥泄露=可伪造任意身份
最高危。缓解:签发私钥受 HSM/KMS、不下发 PoP(3.2);短有效期签发密钥 + 轮换;PoP 失陷不持该私钥(L1 3.12)。

### RI2:国产 IdP API 变更致 adapter 失效(R6)
缓解:契约隔离 + 契约测试 + 监控 + 版本锁定(3.8)。

### RI3:撤销不及时(离职/姿态恶化仍可访问)
缓解:SCIM 禁用事件 + 五类触发 → 吊销表独立流快撤(3.6/xDS 3.7);短 TTL 兜底;定期同步。

### RI4:凭证被跨租户/跨用途重用
缓解:`tenant_id`+`aud` 绑定 + PoP 强制校验(3.7);短 TTL + 绑设备(3.4)。

### RI5:凭证声明与策略选择器 schema 漂移(RP7 根因)
缓解:claims 与选择器/条件同源于 `api/proto`(3.3)+ 契约测试(对接编译器 RP7)。

### RI6:在线 introspection 误用破坏 fail-static
缓解:凭证自包含离线验(3.2),明确禁热路径回调控制面。

### RI7:JIT/SCIM 双源致用户/组不一致
缓解:`Group.source` 标明、同组不双源管理;离职靠 SCIM 事件 + 定期同步 + 短 TTL(3.5/3.6)。

---

## 五、结论与衔接

**结论:** `identity` 模块以**统一 adapter 接口**接入 OIDC/SAML/SCIM + 企微/钉钉/飞书,把第三方差异/变更局部化(R6);**IdP 认证 → 控制面自签短 TTL 自包含会话凭证**,IdP 长令牌不下发,PoP 用下发公钥**离线验证**(对接 fail-static),签发私钥不下发 PoP(限爆炸半径);**凭证声明 schema** 与策略编译器 `subject` 选择器/条件**同源**(解 RP7);入网同时签发**短期设备证书(传输身份)+ 短 TTL 凭证(授权)**,职责分离、经 `device` 关联;用户/组用 **SCIM + JIT** 双策略;持续验证靠**静默刷新 + 撤销(吊销表独立流快撤 + 短 TTL 兜底)**;每租户 IdP 隔离、凭证绑租户、IdP 密钥只存 KMS 引用。

**衔接:**
- **策略编译器子 L2:** 凭证 claims = `subject` 选择器/条件输入,同源契约(已解 RP7)。
- **xDS server 子 L2:** `identity` 产 `RevocationTable`(独立高优先流下发)+ 凭证验证公钥(信任材料);`WGPeerSet` 公钥来源之一。
- **PKI(L1 3.5):** 协同签发短期设备证书;凭证签发密钥受 HSM/KMS。
- **数据访问层子 L2:** `IdPConfig`/`User`/`Group` 受 RLS;IdP 密钥经 `secret` 模块存 KMS 引用。
- **客户端 Agent L2(部分待国密 PoC-G):** Agent 持凭证、采姿态、静默刷新——本文只定凭证契约与 posture 字段,取值域待对齐。
- **PoP 单机编排 L2(部分待 PoC-1):** PEP 离线验凭证、校验租户/aud——属 PoP 实现,守本文凭证契约。
- **国密:** 凭证签名算法随 R7/PoC-G 选型(算法敏捷,3.2),机制不依赖具体算法。

搭 monorepo / 写代码须另行授权(设计先行)。

---

## 附录:待确认 / 待客户端 L2 / 待 PoP L2

| # | 项 | 性质 | 去向 |
|---|----|------|------|
| LI1 | 企微/钉钉/飞书的具体认证端点、通讯录 API 字段、扫码/免登流 | 易变细节 | adapter 内部实现 + 契约测试(3.1/3.8) |
| LI2 | 会话凭证 TTL 具体值(建议 ~5min) | 参数 | 待调(权衡撤销兜底 vs 刷新负载) |
| LI3 | 凭证签名算法(SM2/ECDSA) | 选型 | 随 R7/PoC-G(`sase-gm-crypto-selection.md`) |
| LI4 | 凭证字节级编码(JWS/protobuf)与 type | 契约 | `api/proto` 单一来源 + PoP/客户端 L2 |
| LI5 | `posture` 字段取值域与摘要粒度(与 Agent 上报对齐) | 契约 | 客户端 Agent L2 |
| LI6 | `risk` 分来源与取值域(遥测/姿态派生) | 契约 | 与 L1 3.8/3.14、遥测管道子 L2 对齐 |
| LI7 | 凭证验证公钥下发形态:`TrustBundle` 独立资源 vs 并入信任 bundle | 契约 | 与 xDS 子 L2 LX10 一并定 |
| LI8 | SCIM 端点/鉴权与各国产 IdP 通讯录同步映射 | 细节 | adapter + 实施期 |
| LI9 | PoP 时钟同步机制(凭证验证 skew 依赖) | 机制 | 待 PoP L2 |
| LI10 | 撤销条目保留时长 / 时钟 skew 容差(与 TTL 联动) | 参数 | 待调(与 LI2 联动) |

> 说明:本子 L2 定控制面身份逻辑 + 凭证契约,**解了策略编译器子 L2 的 RP7**(凭证声明与 subject 选择器同源);PEP 验凭证、Agent 持凭证/采姿态、凭证签名算法分别留 PoP L2 / 客户端 L2 / 国密 PoC-G。`identity` 核心逻辑不依赖国密(仅签名算法敏捷)。
