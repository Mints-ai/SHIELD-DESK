# ==============================================================================
# ShieldDesk Threat Detection Service — Multi-Stage Distroless Go Dockerfile
# ==============================================================================

# Stage 1: Build binary
FROM golang:1.22-alpine AS builder
WORKDIR /workspace

COPY shared/ ./shared/
COPY services/threat/ ./services/threat/

WORKDIR /workspace/services/threat
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o /threat-service .

# Stage 2: Distroless Static Runtime
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /

COPY --from=builder /threat-service /threat-service
COPY --from=builder /workspace/services/threat/rules /rules

USER nonroot:nonroot

ENTRYPOINT ["/threat-service"]
