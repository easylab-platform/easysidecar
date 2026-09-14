FROM golang:1.26-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /out/easyproxy .

FROM alpine:3.20
RUN apk add --no-cache iptables ip6tables
COPY --from=build /out/easyproxy /usr/local/bin/easyproxy
# The same binary serves --mode=init (iptables setup, exits) and --mode=proxy.
USER root
ENTRYPOINT ["/usr/local/bin/easyproxy"]
