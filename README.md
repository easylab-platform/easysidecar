# easysidecar

A lightweight transparent egress proxy for EasyLab workloads (CI builds,
sandboxes, services). It has two interception modes:

- **spoof** (default): no privilege at all — no iptables, no `NET_ADMIN`, no
  init container. The sidecar is the Pod's DNS authority and TLS endpoint:

- it answers the Pod's DNS queries itself: rewrite-matched hostnames resolve to
  the sidecar's own Pod IP, blocked ones return NXDOMAIN, everything else is
  forwarded to the cluster resolver;
- it listens on :443/:80 in the Pod's network namespace, presents a leaf
  certificate for the requested hostname (minted on demand from the injected
  CA), and relays the request to an EasyLab pull-through endpoint.

- **capture**: privileged all-egress interception. An init container installs
  iptables rules that redirect every outbound TCP connection to the sidecar,
  which recovers the real destination with `SO_ORIGINAL_DST`; UDP uses
  `IP_RECVORIGDSTADDR`, and DNS is forced to the sidecar resolver. Web ports
  (`--capture-tcp-ports`, default 80,443) are proxied — TLS is MITM'd, plain
  HTTP and h2c are transparently proxied with per-request audit
  (method/path/status). Other TCP is captured, logged and spliced raw; UDP is
  logged and relayed (or dropped). Costs `NET_ADMIN` on sidecar + init
  container.

The workload sees the real upstream hostnames and unmodified URLs, so an
unmodified `npm`/`pip`/`docker`/... reaches the mirror with no configuration.

## Layout

| package | responsibility |
|---|---|
| `cmd/easysidecar` | process entrypoint (`--mode=proxy`) |
| `server/` | flag parsing + listener wiring |
| `capture/` | iptables install + `SO_ORIGINAL_DST` + `SO_MARK` dialer (capture mode) |
| `rule/` | rule model, matching, decider, built-in default policy |
| `dns/` | DNS-spoof resolver (`:53`, spoofed A / NODATA / NXDOMAIN) |
| `relay/` | spoof (:443/:80) and capture (:15001) faces, SNI/Host classification, MITM relays, raw splice |
| `mitm/` | CA loading + per-host leaf issuance |
| `logging/` | JSON connection audit log + byte relay |
| `testca/` | throwaway CAs for tests (test-only import) |

## Rules

```yaml
rules:
  - match: ["docker.io", "registry-1.docker.io", "production.cloudflare.docker.com"]
    action: rewrite
    target: "easylab-gateway.easylab.svc:8080"
  - match: ["*.npmjs.org"]
    action: rewrite
    target: "easylab-gateway.easylab.svc:8080"
  - match: ["*.evil.example", "malware.example"]
    action: block
  - match: ["*.internal.corp"]
    action: direct
default: direct        # action for unmatched connections
mitm_default: false    # true = decrypt ALL intercepted TLS (opt-in)
```

`match` patterns are exact, `*.suffix`, or bare suffixes (label-bounded).
First match wins; the default applies otherwise.

| action | behavior | TLS |
|---|---|---|
| `block` | DNS NXDOMAIN (the client never connects) | — |
| `direct` | forward to the real destination (via the upstream proxy when set) | not decrypted unless `mitm_default` |
| `rewrite` | MITM, then relay to the rule target with the original Host preserved | always decrypted |

A `rewrite` rule may carry `strip_prefix` / `add_prefix` to map the upstream
path shape onto the gateway's mount (`charts.helm.sh/stable/...` →
`/pkgs/helm/...`). The relay also sets `X-Forwarded-Host`/`-Proto`/`-Prefix`, so
the gateway can reconstruct the real upstream without a per-ecosystem table.

## MITM

Rewrite rules require a CA (`-ca-cert`/`-ca-key`, injected from a K8s Secret
scoped to the namespace): easysidecar terminates the client TLS with a per-host
leaf certificate and connects to the pull-through target. Workloads trust the
CA via `SSL_CERT_FILE` (Go) / `NODE_EXTRA_CA_CERTS` (Node) env, which the k8s
injection sets.

`mitm_default: true` extends decryption to every intercepted TLS connection
(not recommended by default: breaks certificate pinning/mTLS clients and makes
the proxy a full plaintext chokepoint).

## Listeners

Spoof mode (`--mode=proxy --spoof`):

| flag | default | purpose |
|---|---|---|
| `-spoof-dns-addr` | 0.0.0.0:53 | the Pod's resolver (UDP + TCP) |
| `-spoof-tls-addr` | 0.0.0.0:443 | TLS face (MITM for rewrite, splice for direct) |
| `-spoof-http-addr` | 0.0.0.0:80 | plain-HTTP face (Host-header classification) |

Capture mode:

| flag | default | purpose |
|---|---|---|
| `-capture-init` | false | init-container role: install the iptables rules and exit |
| `-capture-addr` | 0.0.0.0:15001 | listener for redirected TCP |
| `-capture-tcp-ports` | 80,443 | destination ports proxied as web (HTTP/h2c) |
| `-capture-udp-addr` | 0.0.0.0:15053 | listener for redirected non-DNS UDP |
| `-capture-udp-allow` | | UDP endpoints that always pass (host[:port]/cidr[:port]) |
| `-capture-udp-mode` | log | policy for non-DNS/h3 UDP: log\|reject |
| `-capture-default-mode` | log | policy for other egress: log\|reject |
| `-capture-exempt-cidrs` | | destinations that always pass |
| `-capture-forward-addr` | | forwarded (VM guest) TCP listener; enables PREROUTING/FORWARD |
| `-upstream-proxy` | | HTTP proxy for DIRECT egress (normalized to host:port) |

The capture init container builds one nat chain (`EASYSIDECAR`) that RETURNs
loopback, the capture port, and packets carrying the sidecar's `SO_MARK`, then
DNATs everything else to the capture listener. The sidecar stamps `SO_MARK` on
its own upstream sockets so its egress is not redirected back into itself.

## Build

```
CGO_ENABLED=0 go build -o easysidecar ./cmd/easysidecar
```

Licensed under MIT.
