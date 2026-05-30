package resource

// 纯逻辑单测:CreateApp/CreateConnector 的输入校验类错误须包裹 ErrInvalidResource
// (Slice73 错误码治理:handler 经 errors.Is(err, ErrInvalidResource) 分流为 400)。
// 校验在 store 访问之前发生,故缺字段路径不触达 DB,无需真 PG 即可断言。

import (
	"context"
	"errors"
	"testing"
)

func TestCreateValidationWrapsErrInvalidResource(t *testing.T) {
	// store 传 nil:校验失败时在触达 store 前返回,不会解引用 nil。
	svc := NewService(nil)
	ctx := context.Background()

	t.Run("CreateApp 缺 app_key", func(t *testing.T) {
		err := svc.CreateApp(ctx, "t1", &App{Name: "x"})
		if !errors.Is(err, ErrInvalidResource) {
			t.Fatalf("缺 app_key 应包裹 ErrInvalidResource,得 %v", err)
		}
	})
	t.Run("CreateApp 缺 name", func(t *testing.T) {
		err := svc.CreateApp(ctx, "t1", &App{AppKey: "k"})
		if !errors.Is(err, ErrInvalidResource) {
			t.Fatalf("缺 name 应包裹 ErrInvalidResource,得 %v", err)
		}
	})
	t.Run("CreateConnector 缺 app_key", func(t *testing.T) {
		err := svc.CreateConnector(ctx, "t1", &Connector{Name: "n"})
		if !errors.Is(err, ErrInvalidResource) {
			t.Fatalf("缺 app_key 应包裹 ErrInvalidResource,得 %v", err)
		}
	})
	t.Run("CreateConnector 缺 name", func(t *testing.T) {
		err := svc.CreateConnector(ctx, "t1", &Connector{AppKey: "k"})
		if !errors.Is(err, ErrInvalidResource) {
			t.Fatalf("缺 name 应包裹 ErrInvalidResource,得 %v", err)
		}
	})
}
