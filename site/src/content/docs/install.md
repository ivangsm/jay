---
title: Install
description: Docker, Compose, go install, prebuilt binaries or source.
---

Every distribution ships four binaries: the server (`jay`) plus `jay-admin`,
`jay-config` and `jay-rekey`. You need `jay-admin` to create the first token and
`jay-rekey` to rotate the signing secret, so a bundle without them is not
usable.

## Docker

```bash
docker run -d --name jay \
  -p 9000:9000 -p 127.0.0.1:9001:9001 \
  -v jay_data:/data \
  -e JAY_ADMIN_TOKEN=$(openssl rand -base64 32) \
  -e JAY_SIGNING_SECRET=$(openssl rand -base64 32) \
  ghcr.io/ivangsm/jay:latest
```

Images are published for `linux/amd64` and `linux/arm64`. Tags follow the
releases: `latest`, `0.10`, `0.10.0`. The image runs as a non-root user and
declares `/data` as a volume.

## Docker Compose

```bash
curl -O https://raw.githubusercontent.com/ivangsm/jay/main/docker-compose.yml
export JAY_ADMIN_TOKEN=$(openssl rand -base64 32)
export JAY_SIGNING_SECRET=$(openssl rand -base64 32)
docker compose up -d
```

The published compose file publishes the S3 port on all interfaces and keeps the
admin and native listeners on loopback.

## go install

```bash
go install github.com/ivangsm/jay/cmd/jay@latest
go install github.com/ivangsm/jay/cmd/jay-admin@latest
go install github.com/ivangsm/jay/cmd/jay-config@latest
go install github.com/ivangsm/jay/cmd/jay-rekey@latest
```

## Prebuilt binaries

Each [release](https://github.com/ivangsm/jay/releases) ships one archive per
platform — `linux/amd64`, `linux/arm64`, `darwin/arm64` — containing the four
binaries and a `checksums.txt`.

There is no Windows build: Jay uses `syscall.Statfs` for the free-space check
behind the readiness probe, and it does not exist there.

## From source

```bash
git clone https://github.com/ivangsm/jay.git && cd jay
go build -o jay ./cmd/jay
```

Go 1.27 or newer.

## Running the server

```bash
JAY_ADMIN_TOKEN=$(openssl rand -base64 32) \
JAY_SIGNING_SECRET=$(openssl rand -base64 32) \
./jay
```

Jay listens on three ports:

| Port | Purpose | Exposure |
|---|---|---|
| `:9000` | S3-compatible API | The only one meant for untrusted networks |
| `:9001` | Admin API and health probes | Internal — it creates accounts and tokens |
| `:4444` | Native binary protocol | Internal — the token secret travels in the clear |

A deployment that does not use the native protocol turns its listener off with
an empty `JAY_NATIVE_ADDR`; the startup line then reports `"native":"disabled"`.

## The binary is also the client

Any argument that does not start with `-` is a subcommand, and subcommands talk
to a running server over the native protocol. With no arguments, `jay` is the
server. See [the command-line client](/jay/guides/cli/).
