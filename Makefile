.PHONY: test validate build

test:
	go vet ./...
	go test ./...

validate:
	go run ./cmd/onion validate

build:
	CGO_ENABLED=0 go build -trimpath -o onion ./cmd/onion
