package ztnaterm

import "errors"

// 凭证校验失败原因(统一不向对端泄漏细节,仅本地区分留痕;§3.1)。
var (
	errTenantMismatch = errors.New("ztnaterm: 凭证租户与证书租户不符")
	errRevoked        = errors.New("ztnaterm: 凭证已撤销")
)
