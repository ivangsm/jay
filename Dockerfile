FROM golang:1.26-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /jay .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=builder /jay /usr/local/bin/jay

RUN mkdir -p /data
VOLUME /data

ENV JAY_DATA_DIR=/data
ENV JAY_LISTEN_ADDR=:9000
ENV JAY_ADMIN_ADDR=:9001

# Only expose the S3 API port. Admin (9001) and native protocol (4444)
# should be accessed via internal networks only.
EXPOSE 9000

HEALTHCHECK --interval=10s --timeout=5s --retries=3 --start-period=10s \
  CMD wget --no-verbose --tries=1 --spider http://localhost:9001/health/ready || exit 1

RUN adduser -D -u 1000 jay
USER jay

ENTRYPOINT ["jay"]
