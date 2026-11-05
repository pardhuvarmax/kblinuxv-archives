.PHONY: build install test vet fmt check

build:
	go build -o bin/kblva ./cmd/kblva

install:
	go install ./cmd/kblva

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

# What CI runs.
check:
	test -z "$$(gofmt -l .)"
	go vet ./...
	go test ./...
