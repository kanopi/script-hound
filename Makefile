# ScriptHound: common tasks. Run `make` (or `make help`) to list targets.
#
# Variables (override on the command line, e.g. `make scan URL=https://example.com/ ARGS="--show-scripts"`):
#   URL      one or more URLs (comma-separated) to scan; passed as --urls
#   SITEMAP  sitemap URL or file for `make sitemap`
#   ARGS     any extra scan.mjs flags (see docs/configuration.md)
#   IMAGE    Docker image name, without a tag (default kanopi/script-hound, the Docker Hub repo)
#   PLATFORM docker-build target architecture, e.g. linux/amd64 (default: this machine's)

IMAGE    ?= kanopi/script-hound
# Version tag for docker-push, from package.json.
VERSION  := $(shell node -p "require('./package.json').version" 2>/dev/null)
# Target architecture for docker-build, e.g. PLATFORM=linux/amd64 on an Apple Silicon Mac to build an
# image for x86 servers/CI. Empty = this machine's architecture.
PLATFORM ?=
# Architectures for docker-push (multi-arch manifest).
PLATFORMS ?= linux/amd64,linux/arm64
URL      ?=
SITEMAP  ?=
ARGS     ?=
# Playwright base image, read from the Dockerfile so it's pinned in one place for these targets.
PW_IMAGE := $(shell sed -n 's/^FROM //p' Dockerfile | head -1)

URL_ARG := $(if $(URL),--urls $(URL),)
# Docker: allocate a TTY only when output is a terminal (colors), mount the current folder as /data.
DOCKER_RUN = docker run --rm $$( [ -t 1 ] && echo -t ) --ipc=host -v "$(CURDIR)":/data

.DEFAULT_GOAL := help
.PHONY: help install test scan crawl sitemap tree rules baseline clean update-vulndb docker-smoke docker-push \
        docker-build docker-test docker-scan docker-shell check-versions validate-ci check

help: ## List targets
	@echo "Usage: make <target> [URL=...] [SITEMAP=...] [ARGS=\"...\"]"
	@echo
	@grep -E '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'
	@echo
	@echo "Examples:"
	@echo "  make scan URL=https://example.com/"
	@echo "  make crawl URL=https://shop.example.com/ ARGS=\"--max-pages 50\""
	@echo "  make docker-scan URL=https://example.com/ ARGS=\"--format console --show-scripts\""

## ---- Local (Node + Playwright on this machine) ----

install: ## Install npm dependencies and Playwright's Chromium
	npm ci
	npx playwright install chromium

test: ## Run the end-to-end test suite locally (needs `make install`)
	npm test

scan: ## Scan: sites.json, or URL=...; extra flags via ARGS=...
	./scan $(URL_ARG) $(ARGS)

crawl: ## Crawl a site from URL=... (same-site links only)
	@test -n "$(URL)" || (echo "Set URL=, e.g. make crawl URL=https://shop.example.com/" && exit 2)
	./scan $(URL_ARG) --mode crawl $(ARGS)

sitemap: ## Scan pages from SITEMAP=... (URL or local file)
	@test -n "$(SITEMAP)" || (echo "Set SITEMAP=, e.g. make sitemap SITEMAP=https://shop.example.com/sitemap.xml" && exit 2)
	./scan --sitemap $(SITEMAP) $(ARGS)

tree: ## Scan URL=... and print the third-party script tree
	@test -n "$(URL)" || (echo "Set URL=, e.g. make tree URL=https://example.com/" && exit 2)
	./scan $(URL_ARG) --show-scripts $(ARGS)

rules: ## List every rule and its effective setting (add ARGS="--site NAME" for one site)
	./scan --list-rules $(ARGS)

baseline: ## Scan sites.json and overwrite baseline.json
	./scan --update-baseline $(ARGS)

## ---- Docker (no local install needed) ----

docker-build: ## Build the image as $(IMAGE) (PLATFORM=linux/amd64|linux/arm64; default: this machine's)
	docker build $(if $(PLATFORM),--platform $(PLATFORM),) --build-arg VERSION=$(VERSION) -t $(IMAGE) .

docker-push: ## Build amd64 + arm64 and push $(IMAGE):<version> and :latest to the registry (docker login first)
	@test -n "$(VERSION)" || (echo "Couldn't read the version from package.json" && exit 2)
	@case "$(IMAGE)" in */*) ;; *) echo "IMAGE must be a registry repo, e.g. kanopi/script-hound" && exit 2;; esac
	@case "$(IMAGE)" in *:*) echo "IMAGE must not include a tag; the version comes from package.json" && exit 2;; esac
	docker buildx build --platform $(PLATFORMS) --build-arg VERSION=$(VERSION) -t $(IMAGE):$(VERSION) -t $(IMAGE):latest --push .
	@echo "Pushed $(IMAGE):$(VERSION) and $(IMAGE):latest ($(PLATFORMS))"

docker-test: ## Run the test suite inside the Playwright image
	docker run --rm --ipc=host -v "$(CURDIR)":/work -w /work $(PW_IMAGE) sh -c "(command -v jq >/dev/null || (apt-get update -qq && apt-get install -y -qq jq >/dev/null)) && npm ci --no-audit --no-fund >/dev/null && npm test"

docker-scan: docker-build ## Scan in Docker: sites.json in this folder, or URL=...; ARGS=...
	$(DOCKER_RUN) $(IMAGE) $(URL_ARG) $(ARGS)

docker-shell: docker-build ## Open a shell in the scanner image with this folder at /data
	docker run --rm -it --ipc=host -v "$(CURDIR)":/data --entrypoint bash $(IMAGE)

## ---- Housekeeping ----

check-versions: ## Check Playwright is pinned to the same version in package.json, Dockerfile and CircleCI
	@node -e ' \
	  const fs = require("fs"); \
	  const pkg = require("./package.json").dependencies.playwright.replace(/^[^0-9]*/, ""); \
	  const tag = (f) => (fs.readFileSync(f, "utf8").match(/playwright:v([0-9.]+)-/) || [])[1]; \
	  const found = { "package.json": pkg, "Dockerfile": tag("Dockerfile"), ".circleci/config.yml": tag(".circleci/config.yml") }; \
	  for (const [f, v] of Object.entries(found)) console.log("  " + f.padEnd(22) + (v || "not found")); \
	  if (new Set(Object.values(found)).size !== 1) { console.error("Playwright versions differ: bump all three together."); process.exit(1); } \
	  console.log("Playwright versions match.");'

validate-ci: ## Validate .circleci/config.yml (needs the circleci CLI)
	@command -v circleci >/dev/null || (echo "circleci CLI not installed: https://circleci.com/docs/local-cli/" && exit 1)
	circleci config validate

update-vulndb: ## Refresh data/retire-jsrepository.json from Retire.js (Apache-2.0)
	curl -fsSL https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository-v4.json -o data/retire-jsrepository.json.tmp
	node -e 'const r=require("./data/retire-jsrepository.json.tmp"); if (!r.jquery) throw new Error("unexpected format")'
	mv data/retire-jsrepository.json.tmp data/retire-jsrepository.json
	sed -i.bak "s/^- Snapshot taken: .*/- Snapshot taken: $$(date +%Y-%m-%d). Refresh with \`make update-vulndb\`./" data/README.md && rm -f data/README.md.bak
	@echo "Updated. Run make check, then commit data/."

docker-smoke: docker-build ## Check the built image runs and has everything it needs (e.g. the vulnerability DB)
	docker run --rm $(IMAGE) --help >/dev/null
	docker run --rm --entrypoint jq $(IMAGE) --version
	docker run --rm --entrypoint sh $(IMAGE) -c 'test -s /app/LICENSE && test -s /app/NOTICE && echo "license files OK"'
	docker run --rm --entrypoint node $(IMAGE) --input-type=module -e "const b = await import('/app/lib/brand.mjs'); if (!b.brandSvg('scripthound-logo-simple-dark')) { console.error('brand SVGs missing from image'); process.exit(1); } console.log('brand OK')"
	docker run --rm --entrypoint node $(IMAGE) --input-type=module -e "const m = await import('/app/lib/vulndb.mjs'); if (!(m.vulnDbInfo().libraries > 0)) { console.error('vulnerability DB missing from image'); process.exit(1); } console.log('image OK:', m.vulnDbInfo().libraries, 'vulnerable-library entries')"

check: check-versions docker-test docker-smoke ## Version check, tests in Docker, image smoke test (run before committing)

clean: ## Remove generated reports (keeps baseline.json and sites.json)
	rm -rf reports test/sample-report
