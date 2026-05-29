// Command api-server 是控制面模块化单体(单元①)入口。
// Slice 1:接 RLS Postgres(有 DSN 时)或退回桩(无 DSN 时,便于离线冒烟)。
// 装配链:booting(DI/生命周期)→ data.Store → 业务模块 Service → admin 路由。
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	controlpb "github.com/ikuai8/sase/api/proto/sase/control/v1"
	telemetrypb "github.com/ikuai8/sase/api/proto/sase/telemetry/v1"
	"github.com/ikuai8/sase/internal/admin/httpapi"
	"github.com/ikuai8/sase/internal/audit"
	"github.com/ikuai8/sase/internal/authz"
	"github.com/ikuai8/sase/internal/control"
	"github.com/ikuai8/sase/internal/cred"
	"github.com/ikuai8/sase/internal/data"
	"github.com/ikuai8/sase/internal/devpki"
	"github.com/ikuai8/sase/internal/dlp"
	"github.com/ikuai8/sase/internal/enroll"
	"github.com/ikuai8/sase/internal/fw"
	"github.com/ikuai8/sase/internal/identity"
	"github.com/ikuai8/sase/internal/idp"
	"github.com/ikuai8/sase/internal/oidc"
	"github.com/ikuai8/sase/internal/platform"
	"github.com/ikuai8/sase/internal/platformaudit"
	"github.com/ikuai8/sase/internal/platformrbac"
	"github.com/ikuai8/sase/internal/policy"
	"github.com/ikuai8/sase/internal/ratelimit"
	"github.com/ikuai8/sase/internal/resource"
	"github.com/ikuai8/sase/internal/risk"
	"github.com/ikuai8/sase/internal/secret"
	"github.com/ikuai8/sase/internal/site"
	"github.com/ikuai8/sase/internal/swg"
	"github.com/ikuai8/sase/internal/system/booting"
	"github.com/ikuai8/sase/internal/telemetry"
	"github.com/ikuai8/sase/internal/tenant"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("api-server: %v", err)
	}
}

// bootstrapAdminTTL 是引导 platform_admin 令牌的短有效期(够操作员立即取用并签发常规 admin,限泄露窗口)。
const bootstrapAdminTTL = 15 * time.Minute

func run() error {
	ctx, cancel := context.WithCancel(context.Background()) // 进程生命周期:后台 goroutine(限流 janitor 等)随 run 返回退出
	defer cancel()

	// 管理面 HTTPS(单向 TLS:控制台/操作员客户端验服务端,身份由 app 层 RBAC 认证)
	tlsDir := envOr("SASE_TLS_DIR", "./certs")
	adminTLS, err := devpki.LoadServerTLSServerOnly(tlsDir)
	if err != nil {
		return fmt.Errorf("加载管理面 TLS(%s): %w", tlsDir, err)
	}
	app := booting.New("api-server", booting.WithTLS(adminTLS))

	// 数据层:有 DSN 接 RLS Postgres(app_rw/app_ro 分离);无 DSN 退回 Slice 0 桩。
	store := newStore()
	defer store.Close()

	// 签发器 + 验证器(实时通道 hello 验签 + 管理面 RBAC admin 令牌验签共用)
	signer, err := newSigner()
	if err != nil {
		return err
	}
	verifier, err := cred.NewVerifier(signer.Public())
	if err != nil {
		return fmt.Errorf("构造验证器: %w", err)
	}
	hub := control.NewHub(verifier)

	// 依赖装配(模块间只经 Service 接口)
	// secret 模块(L1 3.5 信封加密):dev KEK 从 SASE_DEV_KEK 取 base64 32B,缺则临时随机(进程内有效,见 secret 包注释)。
	// **生产严禁用 DevProvider** —— 生产 KMS/HSM 接入待 R7 选型衍生。
	secretProvider, err := secret.NewDevProvider("SASE_DEV_KEK")
	if err != nil {
		return fmt.Errorf("构造 secret Provider: %w", err)
	}
	secretSvc := secret.NewService(store, secretProvider)
	// tenant Create 同事务建 DEK(建租户+建 DEK 原子)。
	tenantSvc := tenant.NewService(store, tenant.WithKeyCreator(secretSvc))

	// risk 与 identity 互为 call-time 依赖(risk 突变→撤销用 identity;identity 签发→填 risk claim 用 risk),
	// 故 identitySvc 前向声明,两个闭包均在运行期(撤销/签发时)才解引用,无构造期循环。
	var identitySvc identity.Service
	// 信任/风险引擎:聚合信号(姿态/DLP…)派生风险;**升入 critical → 撤销凭证**(吊销表[权威]+实时通道[端提速])。
	riskSvc := risk.NewService(func(tenantID, subject, jti string, a risk.Assessment) {
		if jti == "" {
			return // 无关联会话(如纯 DLP 事件无 jti)→ 不撤销,留待下次带 jti 信号
		}
		if err := identitySvc.RevokeCredential(context.Background(), tenantID, jti, subject, "risk:"+string(a.Level)); err != nil {
			log.Printf("[api-server] 风险突变自适应撤销失败: %v", err)
		} else {
			log.Printf("[api-server] 风险突变撤销 tenant=%s sub=%s score=%d level=%s", tenantID, subject, a.Score, a.Level)
		}
	})
	identitySvc = identity.NewService(store, identity.WithSigner(signer), identity.WithRevocationNotifier(hub),
		identity.WithRiskSource(func(tenantID, subject string) (int, string) { // 签发时取当前风险填 risk claim
			a := riskSvc.Assess(tenantID, subject)
			return a.Score, string(a.Level)
		}))

	// 首个 platform_admin 引导:管理面 token 端点受 RBAC(需已有 admin),首个 admin 无从获得——鸡生蛋。
	// 设 SASE_BOOTSTRAP_PLATFORM_ADMIN=<subject> 则启动时带外签发一枚**短期**(15min)platform_admin 令牌并打印日志,
	// 操作员**立即**取用、凭它建租户/签发常规 admin。⚠️ 令牌进日志:引导期勿开远端日志采集;**取用后立即清除该 env**,
	// 否则**每次重启都会再签发一枚 15min 有效令牌**(本机制非真·一次性,无落库/无去重)。
	if bootSub := os.Getenv("SASE_BOOTSTRAP_PLATFORM_ADMIN"); bootSub != "" {
		if tok, berr := identitySvc.IssueAdminToken(ctx, bootSub, authz.RolePlatformAdmin, "", bootstrapAdminTTL); berr != nil {
			log.Printf("[api-server] 引导 platform_admin 失败: %v", berr)
		} else {
			log.Printf("[api-server] === 引导 platform_admin 令牌(subject=%q,有效 %s,请立即取用并清除 SASE_BOOTSTRAP_PLATFORM_ADMIN)===\n%s\n===", bootSub, bootstrapAdminTTL, tok)
		}
	}
	resourceSvc := resource.NewService(store)
	policySvc := policy.NewService(store, policy.WithAppRegistry(resourceSvc)) // 编译校验策略引用的应用已注册
	auditSvc := audit.NewService(store)
	swgSvc := swg.NewService(store)
	siteSvc := site.NewService(store)
	fwSvc := fw.NewService(store)
	dlpSvc := dlp.NewService(store)

	// ZTP 设备入网:用 dev PKI CA 签发租户绑定证书。缺 ca.key(老证书目录)时降级为不可用,
	// 不阻断服务启动;重生成证书(cmd/devpki)即启用。生产应改 PoP CA + HSM。
	var enrollCA *devpki.CA
	if ca, err := devpki.LoadCA(tlsDir); err != nil {
		log.Printf("[api-server] ZTP 入网暂不可用(加载 CA: %v);重生成证书可启用", err)
	} else {
		enrollCA = ca
	}
	// ZTP 证书签发/续期是安全事件,但设备认证(非 admin principal)不经 admin 审计中间件,故注入钩子单独留痕。
	enrollSvc := enroll.NewService(store, enrollCA, enroll.WithAudit(
		func(actx context.Context, tenantID, actor, action string, result int) {
			if rerr := auditSvc.Record(actx, audit.Entry{
				TenantID: tenantID, ActorSubject: actor, ActorRole: "device", Action: action, Result: result,
			}); rerr != nil {
				log.Printf("[api-server] ZTP 审计记录失败 action=%s tenant=%s: %v", action, tenantID, rerr)
			}
		}))

	// ZTP 公开/设备端点限流(防激活码枚举/续期暴力):按来源 IP 令牌桶,janitor 淘汰空闲桶。
	enrollLimiter := ratelimit.New(0.2, 5) // 兑换:稳态 1/5s、突发 5(单 IP)
	renewLimiter := ratelimit.New(0.1, 3)  // 续期:更低频(正常每设备数小时一次)
	enrollLimiter.StartJanitor(ctx, 10*time.Minute, 30*time.Minute)
	renewLimiter.StartJanitor(ctx, 10*time.Minute, 30*time.Minute)

	// 平台跨租户只读(InPlatformTx,需 SASE_DB_PLATFORM_DSN 配 app_platform_ro)+ 注入 sweep 依赖
	// (适配器把 secret.Service / tenant.Service 的接口收窄到 platform 期望的 narrow interface,避免平台→业务硬依赖)。
	platformSvc := platform.NewService(store,
		platform.WithDEKDestroyer(sweepDestroyer{secretSvc}),
		platform.WithTenantStatusSetter(sweepStatusSetter{tenantSvc}),
	)
	// Slice36 IdPConfig 持久化 + Slice37c Delete 联动淘汰 oidc adapter token cache(wecom/feishu corp/app token)
	idpSvc := idp.NewService(store, secretSvc, idp.WithDeleteHook(func(_, _, kind, clientID string) {
		oidc.InvalidateForIDP(kind, clientID)
	}))
	popReg := buildPopRegistry(store)
	// 平台审计(Slice39):平台 CRUD 操作显式留痕,与 tenant audit_log 对称;无 PLATFORM_RW DSN 时返 nil → 端点 503。
	platformAuditSvc := buildPlatformAudit(store)
	platformRBACSvc := buildPlatformRBAC(store)
	// B4 启动期 RBAC 表空告警(零成本护栏):RBAC 表空 → 端点签发 platform_admin 永远 403,需 bootstrap env 应急通道
	if platformRBACSvc != nil {
		if admins, lerr := platformRBACSvc.List(ctx); lerr == nil && len(admins) == 0 {
			if os.Getenv("SASE_BOOTSTRAP_PLATFORM_ADMIN") == "" {
				log.Printf("[api-server] ⚠️  platform_admins 表为空且未设 SASE_BOOTSTRAP_PLATFORM_ADMIN —— `/platform/admin-tokens` 端点的 platform_admin 路径将永远 403;请设置 bootstrap env 应急通道或经其它通道注入首枚 admin")
			} else {
				log.Printf("[api-server] ℹ️  platform_admins 表为空,bootstrap env 已设;取得 bootstrap token 后请立即 POST /api/v1/platform/admins 登记自己,否则下次启动相同问题")
			}
		}
	}
	httpapi.Register(app.Mux(), tenantSvc, identitySvc, policySvc, resourceSvc, auditSvc, swgSvc, siteSvc, fwSvc, dlpSvc, enrollSvc, platformSvc, popReg, platformAuditSvc, platformRBACSvc, idpSvc, buildOIDCDeps(idpSvc, identitySvc, auditSvc), enrollLimiter, verifier)

	// Slice36(b) 周期 sweep:env-gated SASE_SWEEP_INTERVAL(time.ParseDuration,如 "10m";空/0 不启)。
	// 与 HTTP 端点共用 platform.RunDecommissionSweep——单一编排源,无 drift。
	if iv := sweepInterval(); iv > 0 {
		go runSweepCron(ctx, platformSvc, iv)
		log.Printf("[api-server] 硬删自动清扫 cron 启动:间隔 %s(SASE_SWEEP_INTERVAL)", iv)
	} else {
		log.Printf("[api-server] 硬删自动清扫 cron 未启用(SASE_SWEEP_INTERVAL 未设;运维手动 POST /platform/decommissions/sweep)")
	}

	// 持续自适应:Agent 上报姿态 → 风险引擎(非合规即升 critical → 撤销)。**已端到端连通**(姿态经 hub 到控制面)。
	// 注:DLP 命中(发生在 PoP 数据面)经 risk 闭环的链路 risk 包内已实现+自测(risk 实现 dlp.FindingSink),
	// 但 **PoP→控制面 risk 的跨进程上报未连通**(待遥测管道 单元③);pop-agent 当前用 LogFindingSink 兜底。
	hub.SetPostureHandler(func(tenantID, subject, jti, posture string) {
		riskSvc.ObservePosture(tenantID, subject, jti, posture)
	})

	// 终端实时控制 gRPC 服务(mTLS:设备级 transport 认证 + hello 内凭证验签 app 层身份)
	ctlAddr := envOr("AGENTCTL_ADDR", ":8082")
	ctlTLS, err := devpki.LoadServerTLS(envOr("SASE_TLS_DIR", "./certs"))
	if err != nil {
		return fmt.Errorf("加载控制通道 mTLS: %w", err)
	}
	gs := grpc.NewServer(grpc.Creds(credentials.NewTLS(ctlTLS)))
	controlpb.RegisterAgentControlServer(gs, hub)
	// 遥测 Ingest(单元③):PoP 上报的事件派发给风险引擎——DLP 命中跨进程闭环到 risk(→ 升 critical → 撤销)。
	// 与控制通道同 gRPC server(同 mTLS)。
	// W11 角色门控:SASE_TELEMETRY_REQUIRE_POP_ROLE=1 → 遥测只收 PoP 角色证书(生产必开;dev 默认关,
	// 因 dev 共享证书无角色——开则需 PoP 持 role:pop 证书)。与 revtunnel W9 的 require-cert-tenant 同形态。
	telRequirePoP := truthy(os.Getenv("SASE_TELEMETRY_REQUIRE_POP_ROLE"))
	if telRequirePoP {
		log.Printf("[api-server] 遥测端点:require-pop-role 已开启(仅收 PoP 角色证书,W11)")
	} else {
		log.Printf("[api-server] 遥测端点:require-pop-role 未开启(dev);生产须设 SASE_TELEMETRY_REQUIRE_POP_ROLE=1")
	}
	telemetrypb.RegisterTelemetryServer(gs, telemetry.NewIngest(telRequirePoP, riskTelemetrySink{riskSvc}))
	lis, err := net.Listen("tcp", ctlAddr)
	if err != nil {
		return err
	}
	go func() { _ = gs.Serve(lis) }()
	defer gs.GracefulStop()
	log.Printf("[api-server] 终端实时控制 + 遥测上报 gRPC 监听 %s", ctlAddr)

	// 设备 mTLS 端点(ZTP 证书续期):RequireAndVerifyClientCert,设备出示当前 ZTP 证书,
	// 服务端从已校验证书取 tenant/identity 续期。与管理面(server-only HTTPS)分端口、分信任模型。
	if enrollCA != nil {
		devAddr := envOr("DEVICE_ADDR", ":8444")
		devTLS, derr := devpki.LoadServerTLS(tlsDir)
		if derr != nil {
			return fmt.Errorf("加载设备端点 mTLS: %w", derr)
		}
		devMux := http.NewServeMux()
		httpapi.RegisterDevice(devMux, enrollSvc, renewLimiter)
		devSrv := &http.Server{Handler: devMux, ReadHeaderTimeout: 5 * time.Second}
		ln, lerr := tls.Listen("tcp", devAddr, devTLS) // 产 *tls.Conn,http.Server 自动握手并填 r.TLS
		if lerr != nil {
			return fmt.Errorf("设备端点监听 %s: %w", devAddr, lerr)
		}
		go func() {
			if serr := devSrv.Serve(ln); serr != nil && serr != http.ErrServerClosed {
				log.Printf("[api-server] 设备端点退出: %v", serr)
			}
		}()
		defer devSrv.Close()
		log.Printf("[api-server] 设备 mTLS 端点(ZTP 续期)监听 %s", devAddr)
	}

	return app.Run(envOr("ADMIN_ADDR", ":8443"))
}

// riskTelemetrySink 把遥测事件中的 DLP 命中喂给风险引擎(telemetry.Sink → risk):跨进程闭环 DLP→风险→撤销。
type riskTelemetrySink struct{ risk *risk.Service }

func (s riskTelemetrySink) Handle(e telemetry.Event) {
	if e.Kind != telemetry.KindDLPFinding {
		return
	}
	rule, sev := e.Attrs[telemetry.AttrDLPRule], e.Attrs[telemetry.AttrDLPSeverity]
	if rule == "" || sev == "" {
		log.Printf("[api-server] 丢弃残缺 DLP 遥测事件 tenant=%s rule=%q sev=%q", e.TenantID, rule, sev)
		return // 缺关键 attr → 跳过(可观测),不静默按 medium 兜底(S2)
	}
	// 注:e.JTI 为空的 DLP 事件(如无会话的 SD-WAN/站点流量)会累积进风险态但不触发撤销(MutationFunc jti 空即跳)(S3)。
	s.risk.Report(e.TenantID, e.Subject, e.JTI, dlp.Finding{
		RuleName: rule, Severity: sev, Action: e.Attrs[telemetry.AttrDLPAction],
	})
}

// truthy 判定布尔型环境变量(1/true/yes/on,大小写不敏感)。
func truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// newSigner 构造凭证签发器。SASE_CRED_ALG 选算法(ed25519 默认 | sm2 国密,crypto-agility R7);
// ed25519 且设 SASE_CRED_ED25519_SEED(base64 32 字节)则据种子(重启稳定)。生产应由 KMS/HSM 托管。
func newSigner() (*cred.Signer, error) {
	switch alg := envOr("SASE_CRED_ALG", cred.AlgEd25519); alg {
	case cred.AlgSM2:
		log.Printf("[api-server] 凭证签发算法:国密 SM2(临时密钥)")
		return cred.GenerateSignerSM2()
	case cred.AlgEd25519:
		if seedB64 := os.Getenv("SASE_CRED_ED25519_SEED"); seedB64 != "" {
			seed, err := base64.RawURLEncoding.DecodeString(seedB64)
			if err != nil || len(seed) != ed25519.SeedSize {
				return nil, fmt.Errorf("SASE_CRED_ED25519_SEED 非法(需 base64url 的 %d 字节)", ed25519.SeedSize)
			}
			return cred.NewSigner(ed25519.NewKeyFromSeed(seed)), nil
		}
		log.Printf("[api-server] 凭证签发算法:Ed25519(临时密钥;设 SASE_CRED_ED25519_SEED 可固定)")
		return cred.GenerateSigner()
	default:
		return nil, fmt.Errorf("未知 SASE_CRED_ALG=%q(支持 ed25519|sm2)", alg)
	}
}

func newStore() data.Store {
	cfg, ok := data.ConfigFromEnv()
	if !ok {
		log.Printf("[api-server] 未设 SASE_DB_*_DSN,使用 Slice 0 桩 Store(无 DB)")
		return data.NewStubStore()
	}
	store, err := data.NewPgxStore(context.Background(), cfg)
	if err != nil {
		log.Fatalf("api-server: 接 DB 失败: %v", err)
	}
	log.Printf("[api-server] 已接 RLS Postgres(app_rw/app_ro)")
	return store
}

// sweepDestroyer 适配 secret.Service → platform.DEKDestroyer 接口(narrow);把"无 DEK 行"语义吞掉(老租户),
// 让 sweep 仍能推进它们的 status,不阻塞。
type sweepDestroyer struct{ s secret.Service }

func (d sweepDestroyer) DestroyTenantKey(ctx context.Context, tenantID string) error {
	if err := d.s.DestroyTenantKey(ctx, tenantID); err != nil && !errors.Is(err, secret.ErrNotFound) {
		return err
	}
	return nil
}

// sweepStatusSetter 适配 tenant.Service → platform.TenantStatusSetter 接口(narrow)。
type sweepStatusSetter struct{ s tenant.Service }

func (a sweepStatusSetter) SetStatus(ctx context.Context, tenantID, status string) error {
	_, err := a.s.Update(ctx, tenantID, tenant.Patch{Status: &status})
	return err
}

// platformPathConfigured:平台读写双路径都配齐(B1 修复)——
// PLATFORM_DSN 缺则 List 走 InPlatformTx 返 ErrNoPlatformPath 跑时 500;
// PLATFORM_RW_DSN 缺则 Create/Update + Record 跑时 ErrNoPlatformRWPath 500。
// 要么两个都配(端点真可用),要么都不配(端点 503 fail-loud)——避免 nil 检查通过却跑时 500。
func platformPathConfigured() bool {
	return os.Getenv("SASE_DB_PLATFORM_DSN") != "" && os.Getenv("SASE_DB_PLATFORM_RW_DSN") != ""
}

// buildPlatformRBAC 装配平台 RBAC 服务(Slice38c):平台读写双路径都配齐才暴露;否则 nil → 端点 503。
//   - Service 写经 InPlatformTxRW(app_platform_rw),读经 InPlatformTx(app_platform_ro),复用 Slice38a 池。
//   - `/platform/admin-tokens` 端点签发 role=platform_admin 时必查 IsActive(subject);**bootstrap env 绕过本表**(应急通道)。
func buildPlatformRBAC(store data.Store) platformrbac.Service {
	if !platformPathConfigured() {
		return nil
	}
	return platformrbac.NewService(store)
}

// buildPlatformAudit 装配平台审计服务(Slice39):平台读写双路径都配齐才暴露;否则 nil → 端点 503。
//   - 经 InPlatformTxRW 写、InPlatformTx 读;PoP CRUD handler 经此显式留痕;
//   - DB 触发器 platform_audit_row(挂 pop_nodes 等)同时落 source=data 原子层(双层一致 Slice29)。
func buildPlatformAudit(store data.Store) platformaudit.Service {
	if !platformPathConfigured() {
		return nil
	}
	return platformaudit.NewService(store)
}

// buildPopRegistry 装配 PoP 注册服务(Slice38a):同 buildPlatformAudit,双路径都配齐才暴露。
//
// 注:实际 store 是否带 platform/platformRW 由 data.NewPgxStore 在对应 DSN 非空时建池;
// 这里仅决定**是否暴露 popReg 接口**:DSN 未齐时返 nil → 路由清单仍守 + 端点 503。
func buildPopRegistry(store data.Store) platform.PopRegistry {
	if !platformPathConfigured() {
		return nil
	}
	return platform.NewPopRegistry(store)
}

// buildOIDCDeps 装配 OIDC handler 依赖(Slice37a/Slice37b-1):
//   - SASE_OIDC_CALLBACK_URL 未设 → 返 nil(端点存在但返 503,见 router.oidcLogin/oidcCallback);
//   - 设了 → 装配生产 deps:**DispatchFactory** 按 IdPConfig.Kind 派发(oidc/wecom/dingtalk/feishu),
//     内存 state store,audit 留痕。
//
// 注:内存 state store 是单进程,集群部署改 Redis(接口不变,后续刀)。
func buildOIDCDeps(idpSvc idp.Service, identitySvc identity.Service, auditSvc audit.Service) *oidc.HandlerDeps {
	cb := os.Getenv("SASE_OIDC_CALLBACK_URL")
	if cb == "" {
		return nil
	}
	return &oidc.HandlerDeps{
		IDPSvc:      idpSvc,
		Identity:    identitySvc,
		StateStore:  oidc.NewInMemoryStateStore(),
		Audit:       auditSvc,
		Factory:     oidc.DispatchFactory,
		CallbackURL: cb,
	}
}

// sweepInterval 解析 SASE_SWEEP_INTERVAL(time.ParseDuration 格式,如 "10m"/"1h");空/0/非法 → 0(=不启)。
func sweepInterval() time.Duration {
	v := os.Getenv("SASE_SWEEP_INTERVAL")
	if v == "" {
		return 0
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		log.Printf("[api-server] SASE_SWEEP_INTERVAL=%q 非法(time.ParseDuration),sweep cron 不启用", v)
		return 0
	}
	return d
}

// runSweepCron 周期触发 platform.RunDecommissionSweep,ctx 取消则退出(随进程 graceful shutdown)。
// 失败不中止(单次 sweep 出错→记日志继续下个周期);处理/跳过非零才打日志(噪音控制)。
// 启动即先扫一次(避免重启后等一整个 interval 才处理积压 due 租户);后续按 ticker 周期。
func runSweepCron(ctx context.Context, platformSvc platform.Service, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	doSweep := func() {
		result, err := platformSvc.RunDecommissionSweep(ctx)
		if err != nil {
			log.Printf("[api-server] sweep 失败: %v", err)
			return
		}
		if len(result.Processed) > 0 || len(result.Skipped) > 0 {
			log.Printf("[api-server] sweep: processed=%d skipped=%d", len(result.Processed), len(result.Skipped))
		}
	}
	doSweep() // 启动即一次:重启后立刻清扫积压
	for {
		select {
		case <-ctx.Done():
			log.Printf("[api-server] sweep cron 退出")
			return
		case <-ticker.C:
			doSweep()
		}
	}
}
