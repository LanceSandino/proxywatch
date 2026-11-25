# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
FROM golang:1.27.4-trixie@sha256:430985542100b871e108ccc00e8dcc5eef08ca14ee5825e98ebf563d8ffec4ee AS build
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

FROM debian:trixie-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad AS runtime
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
