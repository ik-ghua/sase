// Command devpki 生成开发/测试用 mTLS 材料(CA + server/client 证书)到目录。
// 仅开发用;生产证书由 PoP CA / KMS 托管(L1 3.5)。用法:OUT=./certs devpki
package main

import (
	"log"
	"os"

	"github.com/ikuai8/sase/internal/devpki"
)

func main() {
	out := os.Getenv("OUT")
	if out == "" {
		out = "./certs"
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		log.Fatalf("devpki: 建目录: %v", err)
	}
	ca, err := devpki.NewCA()
	if err != nil {
		log.Fatalf("devpki: 建 CA: %v", err)
	}
	err = ca.WritePEM(out, func(name string, pemBytes []byte) error {
		return os.WriteFile(name, pemBytes, 0o600)
	})
	if err != nil {
		log.Fatalf("devpki: 写证书: %v", err)
	}
	log.Printf("[devpki] 已生成 ca/server/client 证书到 %s", out)
}
