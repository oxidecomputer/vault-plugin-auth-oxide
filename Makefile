.PHONY: lint fmt generate test test-integration

lint:
	go tool -modfile tools/go.mod golangci-lint run

fmt:
	go tool -modfile tools/go.mod golangci-lint fmt

generate:
	go generate ./...

test:
	go test -v ./...

test-integration:
	go test -v -tags=integration -count=1 -timeout=60s ./cmd/fetch-platform-root
