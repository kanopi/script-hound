# Docker

ScriptHound is published on Docker Hub as [`kanopi/script-hound`](https://hub.docker.com/r/kanopi/script-hound), built for both `linux/amd64` and `linux/arm64`. Docker picks the right one for your machine.

```bash
docker pull kanopi/script-hound            # latest release
docker pull kanopi/script-hound:1.0.0      # a specific version
```

Or build it yourself from this repo, on the official Playwright image (which includes the matching Chromium):

```bash
docker build -t kanopi/script-hound .      # or: make docker-build
```

## Running

Run from the folder that holds `sites.json` and `baseline.json`. Reports land in `./reports`.

```bash
docker run --rm --ipc=host -v "$PWD":/data kanopi/script-hound
docker run --rm --ipc=host -v "$PWD":/data kanopi/script-hound --urls https://example.com/
docker run --rm --ipc=host -v "$PWD":/data -e SCAN_FAIL_ON=high kanopi/script-hound --site "Example Client"
docker run --rm -t --ipc=host -v "$PWD":/data kanopi/script-hound --urls https://example.com/ --show-scripts
```

- **Flags.** The entrypoint is `node scan.mjs`, so any [CLI flag](configuration.md#command-line-reference) can follow the image name. Environment variables go in with `-e`.
- **Paths.** Relative paths (`sites.json`, `baseline.json`, `reports/`, interaction files) resolve against `/data`, which is your mounted folder. `sites.json` is optional when you pass `--urls`.
- **Colors.** Add `-t` for colored console output.
- **Logged-in scans.** Pass secrets with `-e` (`-e SCAN_COOKIES="session_id=$SESSION"`) rather than on the command line. Put storage-state files in the mounted folder (`--storage-state auth.json` resolves to `/data/auth.json`).
- **User.** The container runs as the non-root `pwuser`. On Linux hosts, add `--user "$(id -u):$(id -g)"` so the container can write to your folder.

## Building for other architectures

The Playwright base image is published for `linux/amd64` and `linux/arm64`, and its Chromium runs on both, so the same `Dockerfile` works everywhere. What matters is **where you build**: an image built on an Apple Silicon Mac is `linux/arm64`, and it fails on an x86 server or CI runner with `exec format error`.

```bash
make docker-build                              # this machine's architecture (fine for local use)
make docker-build PLATFORM=linux/amd64         # an x86 image from an ARM Mac (runs under emulation locally)
make docker-push                               # amd64 + arm64, pushed as kanopi/script-hound:<version> and :latest
```

`docker-push` publishes one multi-arch image, so Docker picks the right architecture on each machine. The version tag comes from `package.json`. Run `docker login` first. To push somewhere else, set `IMAGE=registry/name`, without a tag. The CircleCI job doesn't build this image (it runs in the Playwright image directly), so it isn't affected.

## jq in the image

`jq` is included, so the [jq recipes](jq-recipes.md) work without installing anything:

```bash
docker run --rm -v "$PWD":/data --entrypoint jq kanopi/script-hound \
  '[.sites[].pages[].issues[] | select(.severity == "high")] | length' reports/report.json
```

## What's in the image

The image contains only the scanner (`scan.mjs`, `lib/`), the vulnerable-library database (`data/`), production dependencies and `jq`. `make docker-smoke` checks the built image actually has them. Tests, reports, `sites.json` and baselines are excluded (see `.dockerignore`), so one image can be reused across clients.

Keep the `FROM` tag in step with the `playwright` version in `package.json` and the image in `.circleci/config.yml`.
