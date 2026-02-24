PROJECT := kubeapt
SOURCES := ./cmd/kubeapt
BIN_DIR := bin
PLATFORMS := \
	darwin/amd64 \
	darwin/arm64 \
	linux/amd64 \
	linux/arm64 \
	windows/amd64 \
	windows/arm64

.PHONY: all build clean

all: build

build:
	@mkdir -p $(BIN_DIR)
	@set -e; \
	for platform in $(PLATFORMS); do \
	  os=$${platform%/*}; \
	  arch=$${platform#*/}; \
	  outfile=$(BIN_DIR)/$(PROJECT)-$${os}-$${arch}; \
	  if [ $$os = windows ]; then outfile="$$outfile.exe"; fi; \
	  echo "Building $$outfile"; \
	  GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 go build -o $$outfile $(SOURCES); \
	done
	zip -j $(BIN_DIR)/$(PROJECT)-binaries.zip $(BIN_DIR)/*

clean:
	rm -rf $(BIN_DIR)
