.PHONY: build css test bench clean
build:
	CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o bin/ghole ./cmd/ghole
css:
	npm ci
	npm run css
test:
	go test -race ./...
	go vet ./...
bench:
	go test ./internal/core -run '^$$' -bench . -benchmem
clean:
	rm -rf bin
