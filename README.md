# easyproxy

A lightweight transparent egress proxy for EasyLab workloads (CI builds,
sandboxes, services). It intercepts a Pod's outbound traffic **without any
privilege** — no iptables, no `NET_ADMIN`, no init container — by acting as the
Pod's DNS authority and TLS endpoint:

- it answers the Pod's DNS queries itself: rewrite-matched hostnames resolve to
  the sidecar's own Pod IP, blocked ones return NXDOMAIN, everything else is
  forwarded to the cluster resolver;
- it listens on :443/:80 in the Pod's network namespace, presents a leaf
  certificate for the requested hostname (minted on demand from the injected
  CA), and relays the request to an EasyLab pull-through endpoint.

The workload sees the real upstream hostnames and unmodified URLs, so an
unmodified `npm`/`pip`/`docker`/... reaches the mirror with no configuration.

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
scoped to the namespace): easyproxy terminates the client TLS with a per-host
leaf certificate and connects to the pull-through target. Workloads trust the
CA via `SSL_CERT_FILE` (Go) / `NODE_EXTRA_CA_CERTS` (Node) env, which the k8s
injection sets.

`mitm_default: true` extends decryption to every intercepted TLS connection
(not recommended by default: breaks certificate pinning/mTLS clients and makes
the proxy a full plaintext chokepoint).

## Listeners

| flag | default | purpose |
|---|---|---|
| `-spoof-dns-addr` | 0.0.0.0:53 | the Pod's resolver (UDP + TCP) |
| `-spoof-tls-addr` | 0.0.0.0:443 | TLS face (MITM for rewrite, splice for direct) |
| `-spoof-http-addr` | 0.0.0.0:80 | plain-HTTP face (Host-header classification) |

## Build

```
CGO_ENABLED=0 go build -o easyproxy .
```

Licensed under MIT.
