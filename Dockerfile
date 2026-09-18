ARG REGISTRY=forgejo.develop.10.199.64.20.nip.io/root

FROM ${REGISTRY}/golang:1.26-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /out/easysidecar ./cmd/easysidecar

FROM ${REGISTRY}/alpine:3.24
# iptables is needed only for the capture-mode init container; spoof mode does
# not use netfilter at all.
RUN apk add --no-cache iptables
COPY --from=build /out/easysidecar /usr/local/bin/easysidecar
# Spoof mode binds :53; capture mode's init container installs iptables rules
# and the sidecar stamps SO_MARK, both needing NET_ADMIN. Running as root keeps
# the image dependency-free.
USER root
ENTRYPOINT ["/usr/local/bin/easysidecar"]
