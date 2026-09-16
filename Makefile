.PHONY: lint fmt generate test

lint:
	go tool -modfile tools/go.mod golangci-lint run

fmt:
	go tool -modfile tools/go.mod golangci-lint fmt

generate:
	go generate ./...

test:
	go test ./...
