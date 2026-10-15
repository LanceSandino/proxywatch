# syntax=docker/dockerfile:1
FROM golang:1.25.1-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
# The optional secret is only needed behind a TLS-intercepting build proxy.
# Pass a combined CA bundle; keep the session CA out of image layers.
RUN --mount=type=secret,id=proxy_ca \
    if [ -f /run/secrets/proxy_ca ]; then \
      SSL_CERT_FILE=/run/secrets/proxy_ca go mod download; \
    else go mod download; fi
COPY cmd ./cmd
COPY internal ./internal
RUN --mount=type=secret,id=proxy_ca \
    if [ -f /run/secrets/proxy_ca ]; then \
      SSL_CERT_FILE=/run/secrets/proxy_ca CGO_ENABLED=1 go build -trimpath -ldflags='-s -w' -o /proxywatch ./cmd/proxywatch; \
    else CGO_ENABLED=1 go build -trimpath -ldflags='-s -w' -o /proxywatch ./cmd/proxywatch; fi

FROM debian:bookworm-slim AS runtime
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /proxywatch /usr/local/bin/proxywatch
WORKDIR /app
COPY --chmod=0444 config.example.yaml ./config.example.yaml
RUN mkdir /data && chown 10001:10001 /data
USER 10001:10001
ENV PROXYWATCH_CONFIG=/app/config.example.yaml PROXYWATCH_DB=/data/proxywatch.db
VOLUME ["/data"]
ENTRYPOINT ["/usr/local/bin/proxywatch"]
CMD ["doctor"]
