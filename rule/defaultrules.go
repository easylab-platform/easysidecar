package rule

import (
	"github.com/easylab-platform/artifact/targets"
)

// This file provides the built-in default rule set. The hostname table is the
// SINGLE source in artifact/targets (EgressPolicy) so easylab, easysidecar and
// the e2e harness cannot drift; this package only renders it.

// DefaultRulesYAML renders the built-in rule set with the given gateway
// target ("host:port"). Rewrite relays preserve the ORIGINAL Host header, so
// the gateway's protocol adapters route by Host (X-Forwarded-Host when the
// request is re-origin'd). Only mirrors/trees addressed by bare hostname carry
// a path prefix; the relay always preserves the upstream path shape.
func DefaultRulesYAML(gatewayHostPort string) string {
	return targets.RenderEgressYAML(gatewayHostPort, false,
		"easysidecar default egress policy: package-manager upstreams are\nsteered into easylab's pull-through registry; everything else is direct.")
}

// HasUpstreamDomain reports whether a hostname is covered by the default
// rewrite list (used by tests and diagnostics).
func HasUpstreamDomain(host string) bool {
	return targets.EgressCovers(host)
}
