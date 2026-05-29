package main

import "testing"

func TestParseLinks(t *testing.T) {
	// 正常:按序赋优先级
	links, err := parseLinks("wan0=10.0.0.1:7000, wan1=10.0.1.1:7000")
	if err != nil {
		t.Fatalf("解析应成功: %v", err)
	}
	if len(links) != 2 || links[0].Name != "wan0" || links[0].Priority != 0 || links[1].Priority != 1 {
		t.Fatalf("链路/优先级不符: %+v", links)
	}
	if links[0].Addr != "10.0.0.1:7000" {
		t.Fatalf("addr 解析错: %q", links[0].Addr)
	}

	// 重名:fail-closed
	if _, err := parseLinks("wan0=a:1,wan0=b:2"); err == nil {
		t.Fatal("重名应报错")
	}
	// 非法项
	if _, err := parseLinks("wan0"); err == nil {
		t.Fatal("缺 = 应报错")
	}
	if _, err := parseLinks("=a:1"); err == nil {
		t.Fatal("空名应报错")
	}
	if _, err := parseLinks("wan0="); err == nil {
		t.Fatal("空地址应报错")
	}
	// 全空
	if _, err := parseLinks(" , "); err == nil {
		t.Fatal("空 spec 应报错")
	}
}
