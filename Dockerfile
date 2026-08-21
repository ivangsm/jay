FROM golang:1.27-alpine AS builder

# Version y Commit se inyectan con -ldflags. Sin esto, internal/version
# reportaba siempre "0.7.1/dev" en producción pese a la receta documentada en
# version.go, así que /metrics y los logs mentían sobre qué binario corría.
ARG VERSION=dev
ARG COMMIT=unknown

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build \
      -ldflags "-s -w \
        -X github.com/ivangsm/jay/internal/version.Version=${VERSION} \
        -X github.com/ivangsm/jay/internal/version.Commit=${COMMIT}" \
      -o /out/jay . \
 && CGO_ENABLED=0 go build -ldflags "-s -w" -o /out/ ./cmd/...

FROM alpine:3.24
RUN apk add --no-cache ca-certificates wget
# jay-rekey es la herramienta documentada de recuperación ante desastre y
# jay-admin/jay-config son el plano de gestión: si no están en la imagen, no
# hay forma de usarlas cuando hacen falta (que es justo cuando el contenedor ya
# es lo único que queda).
COPY --from=builder /out/jay /out/jay-admin /out/jay-config /out/jay-rekey /usr/local/bin/

RUN adduser -D -u 1000 jay && mkdir -p /data && chown jay:jay /data
VOLUME /data

ENV JAY_DATA_DIR=/data
ENV JAY_LISTEN_ADDR=:9000
ENV JAY_ADMIN_ADDR=:9001

# Only expose the S3 API port. Admin (9001) and native protocol (4444)
# should be accessed via internal networks only.
EXPOSE 9000

# El healthcheck respeta JAY_ADMIN_ADDR: el despliegue del monorepo corre el
# admin en :4011, no en el :9001 del default upstream, y un healthcheck fijo
# marcaba el contenedor como unhealthy para siempre.
HEALTHCHECK --interval=10s --timeout=5s --retries=3 --start-period=10s \
  CMD wget --no-verbose --tries=1 --spider \
      "http://localhost:${JAY_ADMIN_ADDR##*:}/health/ready" || exit 1

USER jay

ENTRYPOINT ["jay"]
