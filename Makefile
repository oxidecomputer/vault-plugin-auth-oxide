.PHONY: lint fmt

lint:
	go tool -modfile tools/go.mod golangci-lint run

fmt:
	go tool -modfile tools/go.mod golangci-lint fmt
