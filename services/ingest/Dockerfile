# ==============================================================================
# ShieldDesk Ingest Service — Multi-Stage Distroless Go Dockerfile
# ==============================================================================

# Stage 1: Build binary
FROM golang:1.22-alpine AS builder
WORKDIR /workspace

# Copy shared Go module and Ingest module
COPY shared/ ./shared/
COPY services/ingest/ ./services/ingest/

WORKDIR /workspace/services/ingest
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o /ingest-service .

# Stage 2: Distroless Static Runtime
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /

COPY --from=builder /ingest-service /ingest-service

EXPOSE 50051
USER nonroot:nonroot

ENTRYPOINT ["/ingest-service"]
