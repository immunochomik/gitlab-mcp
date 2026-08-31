BINARY  := gitlab-mcp
CONFIG  ?= config.example.yaml

build:
	go build -o $(BINARY) .

test:
	go test ./... -v

run: build
	GITLAB_TOKEN=$(GITLAB_TOKEN) ./$(BINARY) --config $(CONFIG) --transport http

clean:
	rm -f $(BINARY)

.PHONY: build test run clean
