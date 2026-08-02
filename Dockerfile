# syntax=docker/dockerfile:1

# Cross-compiled from the build platform: CGO is off, so no emulator is needed
# for the arm64 image.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build

RUN apk add --no-cache ca-certificates

WORKDIR /app
COPY go.mod ./
COPY src ./src

ARG TARGETOS TARGETARCH
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -tags timetzdata -ldflags="-s -w" -o /nothix ./src

# Nothing but the binary. No shell, no package manager, no writable layer.
FROM scratch

LABEL org.opencontainers.image.source=https://github.com/Lovinoes/nothix
LABEL org.opencontainers.image.licenses=MIT

# The panel calls the Datalix API over HTTPS and needs a trust store for it.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /nothix /nothix

ENV PANEL_ADDR=0.0.0.0:8480
EXPOSE 8480
USER 65534:65534
ENTRYPOINT ["/nothix"]
