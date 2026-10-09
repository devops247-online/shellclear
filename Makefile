VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT)
FUZZTIME ?= 30s

.PHONY: build test lint fuzz bench generate security hooks snapshot install clean

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/shellclear ./cmd/shellclear

test:
	go test -race -cover ./...

lint:
	golangci-lint run ./...

fuzz:
	@for t in FuzzZshParse FuzzBashParse FuzzFishParse FuzzPowerShellParse FuzzJSONParse FuzzJSONWriter FuzzShellWriters FuzzJSONUnquote; do \
		echo "== $$t"; go test ./internal/history/ -run "^$$" -fuzz "^$$t$$" -fuzztime $(FUZZTIME) || exit 1; \
	done
	@echo "== FuzzFindEquivalence"; go test ./internal/rules/ -run "^$$" -fuzz "^FuzzFindEquivalence$$" -fuzztime $(FUZZTIME)

bench:
	go test ./internal/scan/ ./internal/rules/ ./cmd/shellclear/ -run "^$$" -bench . -benchmem

# Regenerate internal/rules/builtin_rules.go after editing patterns.yaml.
generate:
	go generate ./internal/rules

security:
	scripts/security-scan.sh

hooks:
	pre-commit install --hook-type pre-commit

snapshot:
	goreleaser release --snapshot --clean

install:
	go install -trimpath -ldflags "$(LDFLAGS)" ./cmd/shellclear

clean:
	rm -rf bin dist coverage.out
