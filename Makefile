BINARY_DIR := ./output/binary
SERVICES := api-server xds-server telemetry pop-agent

.PHONY: build-all build-single test vet lint clean

## 编译所有已存在的发布单元
build-all:
	@for s in $(SERVICES); do \
	  if [ -d cmd/$$s ]; then echo ">> build $$s"; go build -o $(BINARY_DIR)/$$s ./cmd/$$s || exit 1; fi; \
	done

## 编译单个:make build-single s=api-server
build-single:
	go build -o $(BINARY_DIR)/$(s) ./cmd/$(s)

test:
	go test ./...

vet:
	go vet ./...

lint:
	golangci-lint run ./...

clean:
	rm -rf $(BINARY_DIR)
