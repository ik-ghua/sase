// Command agent 是真 OS 级 ZTNA 端点 Agent(L2 `docs/sase-l2-ztna-agent.md` 子块1 + Linux 壳)。
//
// 默认模式 = 长驻守护进程(internal/agentd.Daemon + 平台壳):入网(激活码 ZTP)→ 会话凭证/实时通道 →
// PoP 选址(RTT)→ tunhandshake 握手 → dptunnel L3 包隧道 → TUN 抓包送进隧道(split-tunnel 白名单)。
// 信号 SIGINT/SIGTERM → ctx 取消 → 干净退出(清理路由,防断网)。
//
// 子命令 `agent probe`(保留旧一次性 CLI 能力,不破坏既有用法):携凭证向 PoP 接入面发一次 GET /access。
//
// 守护进程 env(对齐 cmd/cpe 风格):
//
//	TENANT=<uuid> IDENTITY=<device-cn> [ZTP_CODE=<激活码>]      入网身份(ZTP_CODE 空则用 dev 共享 role:device 证书兜底)
//	[ENROLL_MODE=ztp|idp]  入网方式(默认 ztp 激活码;idp = 真 OS 级 ZTNA per-user IdP 入网,Slice80)
//	idp 模式额外:IDP_ID=<idp-config-uuid>  AGENT_ENROLL_URL=https://host:8443/api/v1/agent/enroll  IDP_AUTHORIZE_URL=<IdP authorize 端点+client_id+scope>
//	SASE_TLS_DIR=./certs  MGMT_URL=https://host:8443  DEVICE_URL=https://host:8444  证书/管理面/续期端点
//	POP_CANDIDATES="bj=10.0.0.1:9443,sh=10.0.0.2:9443"        候选 PoP(RTT 选最近;不硬编码单 IP)
//	SDWAN_TUNNEL_ALG=chacha20poly1305  SDWAN_DATA_ADDR=0.0.0.0:0  [SDWAN_DATA_ADV=<adv>]  数据面
//	INTERNAL_CIDR="10.1.0.0/16,10.2.0.0/16"  [INTERNAL_DNS="corp.example.com"]  split-tunnel / split-DNS
//	[CONTROL_ADDR=host:8082  SESSION_TOKEN=<cred>  SESSION_JTI=<jti>]  实时通道(撤销秒级下推;空则仅短 TTL 兜底)
//	[AGENT_TUN=tun-sase]  [AGENT_MTU=1400]  TUN 名/MTU
//
// probe 子命令 env(向后兼容旧 cmd/agent):POP_URL/SASE_TLS_DIR/TOKEN/APP/PATH_。
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/ikuai8/sase/internal/agent"
	"github.com/ikuai8/sase/internal/agentd"
	"github.com/ikuai8/sase/internal/devpki"
)

// agentVersion 由编译期注入(-ldflags "-X main.agentVersion=...");dev 默认 "dev"。
var agentVersion = "dev"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "probe" {
		runProbe()
		return
	}
	if err := runDaemon(); err != nil {
		log.Fatalf("agent: %v", err)
	}
}

// runDaemon 装配 agentd.Daemon + 平台壳并长驻运行(阻塞到信号/ctx 取消)。
func runDaemon() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cands := parseCandidates(os.Getenv("POP_CANDIDATES"))

	cfg := agentd.Config{
		Tenant:          envMust("TENANT"),
		Identity:        envMust("IDENTITY"),
		ZTPCode:         os.Getenv("ZTP_CODE"),
		EnrollMode:      envOr("ENROLL_MODE", agentd.EnrollModeZTP),
		IDPID:           os.Getenv("IDP_ID"),
		AgentEnrollURL:  os.Getenv("AGENT_ENROLL_URL"),
		IDPAuthorizeURL: os.Getenv("IDP_AUTHORIZE_URL"),
		MgmtURL:         envOr("MGMT_URL", "https://localhost:8443"),
		DeviceURL:       envOr("DEVICE_URL", "https://localhost:8444"),
		ServerName:      envOr("SASE_SERVER_NAME", "localhost"),
		TLSDir:          envOr("SASE_TLS_DIR", "./certs"),
		Alg:             envOr("SDWAN_TUNNEL_ALG", ""),
		DataAddr:        envOr("SDWAN_DATA_ADDR", "0.0.0.0:0"),
		DataAdvAddr:     os.Getenv("SDWAN_DATA_ADV"),
		Candidates:      cands,
		InternalCIDR:    splitCSV(os.Getenv("INTERNAL_CIDR")),
		InternalDNS:     splitCSV(os.Getenv("INTERNAL_DNS")),
		ControlAddr:     os.Getenv("CONTROL_ADDR"),
		SessionTok:      os.Getenv("SESSION_TOKEN"),
		SessionJTI:      os.Getenv("SESSION_JTI"),
		AgentVersion:    agentVersion,
	}

	// 平台壳(Linux=真 TUN/ip route;macOS=真 utun/route;其余=unsupported 桩,Run 会返错退出)。
	ncap, probe, sys := agentd.NewPlatformShells(os.Getenv("AGENT_TUN"), parseMTU(os.Getenv("AGENT_MTU")))
	d := agentd.New(cfg, ncap, probe, sys, nil) // prober=nil → 默认 TCP RTT 探测(不依赖 ICMP)

	log.Printf("[agent] 守护进程启动(version=%s tenant=%s identity=%s 候选PoP=%d)", agentVersion, cfg.Tenant, cfg.Identity, len(cands))
	return d.Run(ctx)
}

// runProbe 是保留的旧一次性 Access CLI(向后兼容):携凭证 GET PoP /access 并打印。
func runProbe() {
	popURL := envOr("POP_URL", "https://127.0.0.1:8081")
	tlsDir := envOr("SASE_TLS_DIR", "./certs")
	token := os.Getenv("TOKEN")
	app := envOr("APP", "app1")
	path := envOr("PATH_", "/")
	if token == "" {
		log.Fatal("agent probe: 须设 TOKEN=<会话凭证>")
	}
	tlsConf, err := devpki.LoadDeviceClientTLS(tlsDir, "localhost") // 边缘设备角色证书(role:device)
	if err != nil {
		log.Fatalf("agent probe: 加载 mTLS(%s): %v", tlsDir, err)
	}
	status, body, err := agent.Access(context.Background(), popURL, tlsConf, token, app, path)
	if err != nil {
		log.Fatalf("agent probe: %v", err)
	}
	log.Printf("[agent] probe app=%s → HTTP %d: %s", app, status, body)
}

// parseCandidates 解析 POP_CANDIDATES="name=host:port,name2=host:port"(去硬编码单 IP,L2 §3.7)。
func parseCandidates(spec string) []agentd.PoPCandidate {
	if strings.TrimSpace(spec) == "" {
		return nil
	}
	parts := strings.Split(spec, ",")
	out := make([]agentd.PoPCandidate, 0, len(parts))
	seen := map[string]bool{}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, addr, ok := strings.Cut(part, "=")
		name, addr = strings.TrimSpace(name), strings.TrimSpace(addr)
		if !ok || name == "" || addr == "" {
			log.Fatalf("agent: POP_CANDIDATES 项 %q 非法,应为 name=host:port", part)
		}
		if seen[name] {
			log.Fatalf("agent: POP_CANDIDATES 名 %q 重复", name)
		}
		seen[name] = true
		out = append(out, agentd.PoPCandidate{Name: name, HandshakeAddr: addr})
	}
	return out
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseMTU(s string) int {
	if v, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && v > 0 {
		return v
	}
	return 0
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envMust(k string) string {
	v := os.Getenv(k)
	if v == "" {
		log.Fatalf("agent: 须设环境变量 %s", k)
	}
	return v
}
