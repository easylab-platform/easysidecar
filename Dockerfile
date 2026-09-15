ARG REGISTRY=forgejo.develop.10.199.64.20.nip.io/root

FROM ${REGISTRY}/golang:1.26-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /out/easyproxy .

FROM ${REGISTRY}/alpine:3.24
COPY --from=build /out/easyproxy /usr/local/bin/easyproxy
# Spoof mode is the only interception mechanism: the sidecar answers DNS and
# listens on :443/:80 directly. Port 53 needs root (or CAP_NET_BIND_SERVICE);
# running as root keeps the image dependency-free.
USER root
ENTRYPOINT ["/usr/local/bin/easyproxy"]
