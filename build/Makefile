# Build targets for cross-platform native binaries
# Requires: Docker (for cross-compilation)
#
# Usage:
#   make all          - Build all platforms
#   make linux-amd64  - Build for Linux x86_64
#   make linux-arm64  - Build for Linux aarch64
#   make zipapp       - Build the zipapp (.pyz)
#   make clean        - Remove build artifacts

PROJECT_ROOT := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))/..
DIST := $(PROJECT_ROOT)/data/payloads
VERSION := $(shell python3 -c "import tomllib; print(tomllib.load(open('$(PROJECT_ROOT)/pyproject.toml','rb'))['project']['version'])" 2>/dev/null || echo "1.0.0")

.PHONY: all clean linux-amd64 linux-arm64 windows-amd64 zipapp manifest

all: linux-amd64 linux-arm64 zipapp manifest

$(DIST):
	mkdir -p $(DIST)

# ---------------------------------------------------------------------------
# Native binaries via PyInstaller in Docker
# ---------------------------------------------------------------------------

linux-amd64: $(DIST)
	docker run --rm --platform linux/amd64 \
		-v "$(PROJECT_ROOT):/src:ro" \
		-v "$(DIST):/out" \
		python:3.12-slim sh -c '\
		pip install --quiet pyinstaller && \
		cd /tmp && cp -r /src app && cd app && \
		pyinstaller --onefile --strip --clean \
			--name sectest-linux-amd64 \
			--exclude-module tests \
			--exclude-module tkinter \
			--exclude-module unittest \
			main.py && \
		cp dist/sectest-linux-amd64 /out/ && \
		gzip -9 -c /out/sectest-linux-amd64 > /out/sectest-linux-amd64.gz'
	@echo "Built: $(DIST)/sectest-linux-amd64 ($(shell stat -f%z $(DIST)/sectest-linux-amd64 2>/dev/null || stat -c%s $(DIST)/sectest-linux-amd64) bytes)"

linux-arm64: $(DIST)
	docker run --rm --platform linux/arm64 \
		-v "$(PROJECT_ROOT):/src:ro" \
		-v "$(DIST):/out" \
		python:3.12-slim sh -c '\
		pip install --quiet pyinstaller && \
		cd /tmp && cp -r /src app && cd app && \
		pyinstaller --onefile --strip --clean \
			--name sectest-linux-arm64 \
			--exclude-module tests \
			--exclude-module tkinter \
			--exclude-module unittest \
			main.py && \
		cp dist/sectest-linux-arm64 /out/ && \
		gzip -9 -c /out/sectest-linux-arm64 > /out/sectest-linux-arm64.gz'
	@echo "Built: $(DIST)/sectest-linux-arm64"

windows-amd64: $(DIST)
	@echo "NOTE: Windows cross-compilation requires Wine or a Windows CI runner."
	@echo "Use GitHub Actions with windows-latest for production builds."
	@echo "Skipping windows-amd64 (use 'make ci-windows' in CI)."

# ---------------------------------------------------------------------------
# Zipapp (.pyz)
# ---------------------------------------------------------------------------

zipapp: $(DIST)
	cd "$(PROJECT_ROOT)" && python3 build/build_zipapp.py "$(DIST)/sectest.pyz"
	gzip -9 -k -f "$(DIST)/sectest.pyz"
	@echo "Built: $(DIST)/sectest.pyz ($(shell stat -f%z $(DIST)/sectest.pyz 2>/dev/null || stat -c%s $(DIST)/sectest.pyz) bytes)"

# ---------------------------------------------------------------------------
# Manifest (records hashes + sizes for integrity verification)
# ---------------------------------------------------------------------------

manifest: $(DIST)
	@python3 -c "\
import json, hashlib, pathlib, os; \
d = pathlib.Path('$(DIST)'); \
m = {'version': '$(VERSION)', 'payloads': {}}; \
[m['payloads'].update({f.name: {'size': f.stat().st_size, 'sha256': hashlib.sha256(f.read_bytes()).hexdigest()}}) for f in sorted(d.iterdir()) if f.is_file() and f.name != 'manifest.json']; \
d.joinpath('manifest.json').write_text(json.dumps(m, indent=2))"
	@echo "Updated: $(DIST)/manifest.json"

# ---------------------------------------------------------------------------
# macOS native builds (requires macOS runner or native machine)
# ---------------------------------------------------------------------------

darwin-amd64: $(DIST)
	@echo "Building macOS x86_64 binary (requires macOS host or CI runner)..."
	pip install --quiet pyinstaller && \
	pyinstaller --onefile --strip --clean \
		--name sectest-darwin-amd64 \
		--exclude-module tests \
		--exclude-module tkinter \
		--exclude-module unittest \
		--target-arch x86_64 \
		$(PROJECT_ROOT)/main.py && \
	cp dist/sectest-darwin-amd64 $(DIST)/ && \
	gzip -9 -c $(DIST)/sectest-darwin-amd64 > $(DIST)/sectest-darwin-amd64.gz
	@echo "Built: $(DIST)/sectest-darwin-amd64"

darwin-arm64: $(DIST)
	@echo "Building macOS ARM64 binary (requires Apple Silicon host or CI runner)..."
	pip install --quiet pyinstaller && \
	pyinstaller --onefile --strip --clean \
		--name sectest-darwin-arm64 \
		--exclude-module tests \
		--exclude-module tkinter \
		--exclude-module unittest \
		--target-arch arm64 \
		$(PROJECT_ROOT)/main.py && \
	cp dist/sectest-darwin-arm64 $(DIST)/ && \
	gzip -9 -c $(DIST)/sectest-darwin-arm64 > $(DIST)/sectest-darwin-arm64.gz
	@echo "Built: $(DIST)/sectest-darwin-arm64"

# ---------------------------------------------------------------------------
# Alpine/musl static binary (for containers without glibc)
# ---------------------------------------------------------------------------

linux-musl-amd64: $(DIST)
	docker run --rm --platform linux/amd64 \
		-v "$(PROJECT_ROOT):/src:ro" \
		-v "$(DIST):/out" \
		python:3.12-alpine sh -c '\
		apk add --no-cache binutils gcc musl-dev libffi-dev && \
		pip install --quiet pyinstaller && \
		cd /tmp && cp -r /src app && cd app && \
		pyinstaller --onefile --strip --clean \
			--name sectest-linux-musl-amd64 \
			--exclude-module tests \
			--exclude-module tkinter \
			--exclude-module unittest \
			main.py && \
		cp dist/sectest-linux-musl-amd64 /out/ && \
		gzip -9 -c /out/sectest-linux-musl-amd64 > /out/sectest-linux-musl-amd64.gz'
	@echo "Built: $(DIST)/sectest-linux-musl-amd64 (Alpine/musl compatible)"

linux-musl-arm64: $(DIST)
	docker run --rm --platform linux/arm64 \
		-v "$(PROJECT_ROOT):/src:ro" \
		-v "$(DIST):/out" \
		python:3.12-alpine sh -c '\
		apk add --no-cache binutils gcc musl-dev libffi-dev && \
		pip install --quiet pyinstaller && \
		cd /tmp && cp -r /src app && cd app && \
		pyinstaller --onefile --strip --clean \
			--name sectest-linux-musl-arm64 \
			--exclude-module tests \
			--exclude-module tkinter \
			--exclude-module unittest \
			main.py && \
		cp dist/sectest-linux-musl-arm64 /out/ && \
		gzip -9 -c /out/sectest-linux-musl-arm64 > /out/sectest-linux-musl-arm64.gz'
	@echo "Built: $(DIST)/sectest-linux-musl-arm64 (Alpine/musl compatible)"

# ---------------------------------------------------------------------------
# Clean
# ---------------------------------------------------------------------------

clean:
	rm -rf $(DIST)/sectest-* $(DIST)/sectest.pyz* $(DIST)/manifest.json

# ---------------------------------------------------------------------------
# CI targets (for GitHub Actions)
# ---------------------------------------------------------------------------

ci-linux: linux-amd64 linux-arm64
ci-linux-musl: linux-musl-amd64 linux-musl-arm64
ci-macos:
	@echo "Run on macos-13 (Intel) + macos-14 (Apple Silicon) runners"
ci-windows:
	@echo "Run on windows-latest runner:"
	@echo "  pip install pyinstaller"
	@echo "  pyinstaller --onefile --strip --name sectest-windows-amd64 main.py"
ci-all: ci-linux ci-linux-musl zipapp manifest
