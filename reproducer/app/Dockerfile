# Build a fat Go binary that embeds ~60 MiB of random data.
# The random payload ensures the data cannot be compressed away by the
# container layer and results in a clearly measurable binary size.

FROM golang:1.22-alpine AS builder
WORKDIR /app

# Generate 60 MiB of random payload to embed inside the binary.
RUN dd if=/dev/urandom of=payload.bin bs=1M count=60

COPY main.go .
# Build natively for the build platform's architecture (works on amd64 and arm64).
RUN go mod init nydus-reproducer && \
    CGO_ENABLED=0 go build -ldflags="-s" -o app .

# Use a minimal base — the single /app binary is the entire image content,
# making it straightforward to locate in the FUSE mount during the test.
FROM scratch
COPY --from=builder /app/app /app
ENTRYPOINT ["/app"]
