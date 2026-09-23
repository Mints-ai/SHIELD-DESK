# ==============================================================================
# ShieldDesk Webhooks Service — Multi-Stage Distroless Go Dockerfile
# ==============================================================================

FROM golang:1.22-alpine AS builder
WORKDIR /workspace

COPY shared/ ./shared/
COPY services/webhooks/ ./services/webhooks/

WORKDIR /workspace/services/webhooks
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o /webhooks-service .

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /

COPY --from=builder /webhooks-service /webhooks-service

USER nonroot:nonroot

ENTRYPOINT ["/webhooks-service"]
