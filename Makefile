.PHONY: build clean test install

BINARY := secrets
BUILD_DIR := bin

build:
	go build -o $(BUILD_DIR)/$(BINARY) ./cmd/secrets

clean:
	rm -rf $(BUILD_DIR)
	rm -f $(BINARY)

test:
	go test -v ./...

install: build
	cp $(BUILD_DIR)/$(BINARY) $(GOPATH)/bin/$(BINARY)
