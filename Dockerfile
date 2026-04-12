FROM golang:1.25-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s w -buildid=" \
    -o server ./cmd/main.go

FROM gcr.io/distroless/static-debian12
WORKDIR /app
COPY --chown=1001:1001 --from=builder /app/server .
COPY --chown=1001:1001 --from=builder /app/static ./static
USER 1001:1001
EXPOSE 8080
CMD ["./server"]