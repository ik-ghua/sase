package xdspb

// GetName 让 PolicyBundleResource 实现 go-control-plane 的 types.ResourceWithName 接口
// （out-of-tree 自定义资源经此暴露 xDS 资源名)。资源名命名空间化为 "tenant/<tenant_id>"
// （xDS server L2 3.1)。方法加在生成代码之外的同包文件,不动 *.pb.go。
func (x *PolicyBundleResource) GetName() string {
	if x == nil {
		return ""
	}
	return "tenant/" + x.GetTenantId()
}

// ResourceName 是 "tenant/<id>" 资源名的构造助手(下发与订阅两侧共用,避免拼写漂移)。
func ResourceName(tenantID string) string { return "tenant/" + tenantID }

// TypeURL 是 PolicyBundleResource 的 xDS type URL(下发/订阅单一来源)。
func TypeURL() string {
	return "type.googleapis.com/" + string((&PolicyBundleResource{}).ProtoReflect().Descriptor().FullName())
}

// GetName 让 RevocationList 实现 types.ResourceWithName(资源名同为 "tenant/<id>")。
func (x *RevocationList) GetName() string {
	if x == nil {
		return ""
	}
	return "tenant/" + x.GetTenantId()
}

// RevocationTypeURL 是 RevocationList 的 xDS type URL。
func RevocationTypeURL() string {
	return "type.googleapis.com/" + string((&RevocationList{}).ProtoReflect().Descriptor().FullName())
}

// GetName 让 SWGRuleSet 实现 types.ResourceWithName(资源名 "tenant/<id>")。
func (x *SWGRuleSet) GetName() string {
	if x == nil {
		return ""
	}
	return "tenant/" + x.GetTenantId()
}

// SWGTypeURL 是 SWGRuleSet 的 xDS type URL。
func SWGTypeURL() string {
	return "type.googleapis.com/" + string((&SWGRuleSet{}).ProtoReflect().Descriptor().FullName())
}

// GetName 让 SiteConfig 实现 types.ResourceWithName(资源名 "tenant/<id>")。
func (x *SiteConfig) GetName() string {
	if x == nil {
		return ""
	}
	return "tenant/" + x.GetTenantId()
}

// SiteConfigTypeURL 是 SiteConfig 的 xDS type URL。
func SiteConfigTypeURL() string {
	return "type.googleapis.com/" + string((&SiteConfig{}).ProtoReflect().Descriptor().FullName())
}

// GetName 让 FWRuleSet 实现 types.ResourceWithName(资源名 "tenant/<id>")。
func (x *FWRuleSet) GetName() string {
	if x == nil {
		return ""
	}
	return "tenant/" + x.GetTenantId()
}

// FWTypeURL 是 FWRuleSet 的 xDS type URL(FWaaS L3/L4 规则集)。
func FWTypeURL() string {
	return "type.googleapis.com/" + string((&FWRuleSet{}).ProtoReflect().Descriptor().FullName())
}

// GetName 让 DLPRuleSet 实现 types.ResourceWithName(资源名 "tenant/<id>")。
func (x *DLPRuleSet) GetName() string {
	if x == nil {
		return ""
	}
	return "tenant/" + x.GetTenantId()
}

// DLPTypeURL 是 DLPRuleSet 的 xDS type URL(CASB-DLP 规则集)。
func DLPTypeURL() string {
	return "type.googleapis.com/" + string((&DLPRuleSet{}).ProtoReflect().Descriptor().FullName())
}
