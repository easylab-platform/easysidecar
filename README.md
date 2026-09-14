# easyproxy

A lightweight transparent egress proxy for EasyLab workloads (CI builds,
sandboxes, services). One image, two roles:

- `--mode=init` — install the Pod-level iptables rules, then exit:
  - outbound TCP 80/443 (or all TCP with `-intercept-all-tcp`) `REDIRECT`ed
    to the proxy listener; cluster CIDRs are `RETURN`ed (bypass)
  - outbound UDP/443 `REJECT`ed (kills QUIC so HTTP3 clients fall back to
    interceptable TCP)
  - outbound UDP/53 `REDIRECT`ed to the DNS hijack listener
- `--mode=proxy` — serve the listeners and classify every connection:

| action | behavior | TLS |
|---|---|---|
| `block` | connection reset immediately (DNS: NXDOMAIN) | not decrypted |
| `direct` | splice to the original destination | passes through unless `mitm_default` |
| `rewrite` | forward to an EasyLab pull-through endpoint (Host preserved) | always decrypted (MITM) |

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

## MITM

Rewrite rules require a CA (`-ca-cert`/`-ca-key`, injected from a K8s
Secret scoped to the namespace): easyproxy terminates the client TLS with a
per-hostname leaf certificate and connects to the pull-through target.
Workloads trust the CA via `SSL_CERT_FILE` (Go) / `NODE_EXTRA_CA_CERTS`
(Node) env, which the k8s injection sets. Byte-for-byte relay keeps OCI
digest verification intact.

`mitm_default: true` extends decryption to every intercepted TLS connection
(not recommended by default: breaks certificate pinning/mTLS clients and
makes the proxy a full plaintext chokepoint).

##Listeners

| flag | default | purpose |
|---|---|---|
| `-redir-addr` | 127.0.0.1:7893 | transparent REDIRECT listener |
| `-dns-addr` | 127.0.0.1:7894 | UDP/53 hijack (blocked → NXDOMAIN) |
| `-connect-addr` | 127.0.0.1:7890 | explicit HTTP CONNECT proxy (HTTP_PROXY env) |

## Build

```
CGO_ENABLED=0 go build -o easyproxy .
```

Licensed under MIT.
