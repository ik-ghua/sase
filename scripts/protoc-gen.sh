#!/bin/sh
# proto 代码生成(一次性,容器内跑)。生成的 *.pb.go 提交入库;构建期不需 protoc(保持 go1.22 纯构建)。
# 跑法(VM 容器):
#   docker run --rm -v ~/sase:/src -w /src -e GOPROXY=https://goproxy.cn,direct \
#     docker.m.daocloud.io/library/golang:1.22 sh scripts/protoc-gen.sh
# 之后 rsync 把 api/proto/**/*.pb.go 同步回源(本机为单一来源)。
set -e

if ! command -v protoc >/dev/null 2>&1; then
  echo ">> 安装 protoc"
  apt-get update -qq && apt-get install -y -qq protobuf-compiler
fi
echo ">> 安装 protoc-gen-go(v1.34.2)+ protoc-gen-go-grpc(v1.5.1),均 go1.22 兼容"
GOFLAGS=-mod=mod go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.34.2
GOFLAGS=-mod=mod go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1
export PATH="$(go env GOPATH)/bin:$PATH"

echo ">> 生成 sase/xds/v1(消息)"
protoc -I api/proto --go_out=api/proto --go_opt=paths=source_relative \
  api/proto/sase/xds/v1/policy.proto

echo ">> 生成 sase/control/v1(消息 + gRPC 服务)"
protoc -I api/proto --go_out=api/proto --go_opt=paths=source_relative \
  --go-grpc_out=api/proto --go-grpc_opt=paths=source_relative \
  api/proto/sase/control/v1/control.proto

echo ">> 生成 sase/telemetry/v1(消息 + gRPC 服务)"
protoc -I api/proto --go_out=api/proto --go_opt=paths=source_relative \
  --go-grpc_out=api/proto --go-grpc_opt=paths=source_relative \
  api/proto/sase/telemetry/v1/telemetry.proto

echo ">> 完成:$(ls api/proto/sase/xds/v1/*.pb.go api/proto/sase/control/v1/*.pb.go api/proto/sase/telemetry/v1/*.pb.go)"
