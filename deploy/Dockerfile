# 多阶段 Dockerfile:用与 go.mod 一致的工具链 build 任一 cmd 二进制 → 精简运行镜像。
#
# 用法(由 docker-compose.yml 经 build-arg 选 binary,产出统一的运行镜像):
#   docker build -f deploy/Dockerfile --build-arg CMD=api-server -t sase/api-server .
#   docker build -f deploy/Dockerfile --build-arg CMD=pop-agent  -t sase/pop-agent  .
#   docker build -f deploy/Dockerfile --build-arg CMD=xds-server -t sase/xds-server .
#   docker build -f deploy/Dockerfile --build-arg CMD=devpki     -t sase/devpki     .
#
# 注:go.mod 声明 `go 1.22`(语言目标);用 golang:1.22 镜像即可(新语言特性未用,与本机 go1.26.3
# 编译一致——本机也是用 1.26 工具链编 1.22 语言版本)。GOTOOLCHAIN=local 防 go.mod 触发自动下载工具链。

# ---- build 阶段 ----
FROM golang:1.22 AS build
ARG CMD=api-server
ENV GOTOOLCHAIN=local \
    GOPROXY=https://goproxy.cn,direct \
    CGO_ENABLED=0
WORKDIR /src

# 先拷 go.mod/go.sum 单独下依赖(层缓存:源码改动不重新拉依赖)。
COPY go.mod go.sum ./
RUN go mod download

# 拷全仓源码(.dockerignore 已排除 node_modules/dist/output 等)。
COPY . .

# 编译指定 cmd 为静态二进制(CGO 关 → 可放进 scratch/alpine 无 libc 依赖)。
# -trimpath 去构建机路径;-ldflags "-s -w" 去符号表减体积。
RUN go build -trimpath -ldflags "-s -w" -o /out/app ./cmd/${CMD}

# ---- 运行阶段 ----
# alpine 而非 scratch:需 ca-certificates(虽然内部走自签 mTLS,但保留通用 TLS 根)+ wget/sh
# 供 healthcheck 与 init 容器编排(devpki 容器要写共享 certs volume)。
# iproute2:SD-WAN CPE 容器演示需 `ip` 给 TUN 配 IP/路由(busybox 的 ip 不全;装完整 iproute2)。
FROM alpine:3.20
# iproute2:SD-WAN CPE / ZTNA Agent·PoP 容器给 TUN 配 IP/路由。
# iptables:Slice77 PoP 容器出站 SNAT(MASQUERADE);curl:Agent 容器端到端演示(curl 内部 app)。
RUN apk add --no-cache ca-certificates wget iproute2 iptables curl
WORKDIR /app
COPY --from=build /out/app /app/app
# 默认以 root 运行:devpki init 容器需写 root 拥有的共享 certs volume,且写出的私钥为 0600(仅 owner 可读);
# api/xds/pop 须以同一 owner(root)读这些 0600 私钥。这是 **dev demo 的有意取舍**(单 volume 共享自签 mTLS 私钥)。
# 生产:证书由 PoP CA/KMS 经独立分发(非共享 volume),服务以最小权限非 root 运行(见 deploy/README.md 安全说明)。
ENTRYPOINT ["/app/app"]
