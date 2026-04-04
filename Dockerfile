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

EXPOSE 9000 9001 4444

ENTRYPOINT ["jay"]
