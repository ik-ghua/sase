package devpki

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func parseCert(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	blk, _ := pem.Decode(certPEM)
	if blk == nil {
		t.Fatal("证书 PEM 解析失败")
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatalf("解析证书: %v", err)
	}
	return c
}

// SignCSR → role:device;SignPoP → role:pop;RoleFromCert 正确提取。
func TestSignRoles(t *testing.T) {
	ca, err := NewCA()
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	csr, _, _ := GenerateCSR("web")
	devPEM, err := ca.SignCSR(csr, "t1", "web")
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	if r, ok := RoleFromCert(parseCert(t, devPEM)); !ok || r != RoleDevice {
		t.Fatalf("SignCSR 应 role:device,得 %q(ok=%v)", r, ok)
	}

	popCSR, _, _ := GenerateCSR("pop-1")
	popPEM, err := ca.SignPoP(popCSR, "pop-1")
	if err != nil {
		t.Fatalf("SignPoP: %v", err)
	}
	c := parseCert(t, popPEM)
	if r, ok := RoleFromCert(c); !ok || r != RolePoP {
		t.Fatalf("SignPoP 应 role:pop,得 %q(ok=%v)", r, ok)
	}
	if len(c.Subject.Organization) != 0 { // PoP 无租户绑定
		t.Fatalf("PoP 证书不应有租户(Organization),得 %v", c.Subject.Organization)
	}
}

// WritePEM 产出 role:pop 的 pop.crt;共享 client.crt 无角色;LoadPoPClientTLS 加载到 role:pop 证书。
func TestWritePEMPoPCert(t *testing.T) {
	ca, err := NewCA()
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	dir := t.TempDir()
	if err := ca.WritePEM(dir, func(name string, b []byte) error { return os.WriteFile(name, b, 0o600) }); err != nil {
		t.Fatalf("WritePEM: %v", err)
	}

	popPEM, err := os.ReadFile(filepath.Join(dir, "pop.crt"))
	if err != nil {
		t.Fatalf("读 pop.crt: %v", err)
	}
	if r, ok := RoleFromCert(parseCert(t, popPEM)); !ok || r != RolePoP {
		t.Fatalf("pop.crt 应 role:pop,得 %q(ok=%v)", r, ok)
	}
	// 共享 client.crt 无角色(role-less)→ 遥测门控开启会被拒,故 PoP 须用 pop.crt
	cliPEM, _ := os.ReadFile(filepath.Join(dir, "client.crt"))
	if r, ok := RoleFromCert(parseCert(t, cliPEM)); ok {
		t.Fatalf("client.crt 不应有角色,得 %q", r)
	}
	// LoadPoPClientTLS 能加载 pop 证书
	if _, err := LoadPoPClientTLS(dir, "localhost"); err != nil {
		t.Fatalf("LoadPoPClientTLS: %v", err)
	}

	// 角色拆分:device.crt 为 role:device,LoadDeviceClientTLS 可加载
	devPEM, err := os.ReadFile(filepath.Join(dir, "device.crt"))
	if err != nil {
		t.Fatalf("读 device.crt: %v", err)
	}
	if r, ok := RoleFromCert(parseCert(t, devPEM)); !ok || r != RoleDevice {
		t.Fatalf("device.crt 应 role:device,得 %q(ok=%v)", r, ok)
	}
	if _, err := LoadDeviceClientTLS(dir, "localhost"); err != nil {
		t.Fatalf("LoadDeviceClientTLS: %v", err)
	}
}
