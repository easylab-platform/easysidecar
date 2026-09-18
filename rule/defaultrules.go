package rule

import (
	"fmt"
	"strings"
)

// This file provides the built-in default rule set: every package-manager
// upstream easylab knows is rewritten to the gateway's pull-through
// endpoints, everything else is direct. The target (gateway host:port) is
// parameterized so the caller (easylab k8s injection) fills in the
// namespace-derived Service DNS.

// upstreamDomain describes one package-manager upstream: the domains whose
// traffic must be steered into easylab. The gateway routes by the preserved
// Host header, so no per-ecosystem path is needed here — except for mirrors
// whose path shape differs from the adapter's mount (Strip/Add).
type upstreamDomain struct {
	// Match are the hostname patterns (exact / *.suffix / bare suffix).
	Match []string
	// Strip is a leading path prefix removed before Add is applied (e.g. the
	// Google Maven host serves the repo under /dl/android/maven2).
	Strip string
	// Add is the adapter mount prepended after Strip (e.g. /pkgs/maven).
	Add string
}

// defaultUpstreams mirrors easylab's artifactkit upstream table: one entry
// per package-manager ecosystem. Adding an ecosystem in artifact means
// adding it here so egress policy covers it by default.
var defaultUpstreams = []upstreamDomain{
	// OCI / containers. The public registries a client reaches by name; each
	// is preserved as the Host (and therefore the repository namespace) by the
	// rewrite relay, so ghcr.io/acme/app and docker.io/acme/app stay distinct.
	{Match: []string{"registry-1.docker.io", "docker.io", "index.docker.io"}},
	{Match: []string{"ghcr.io", "quay.io", "gcr.io", "registry.k8s.io",
		"mcr.microsoft.com", "public.ecr.aws", "nvcr.io"}},
	// Container blob CDNs: registries 307-redirect layer downloads here, and
	// artifact follows the redirect itself. Rewriting these to the gateway
	// would hand it a CDN URL it cannot resolve, so they stay direct.
	{Match: []string{"production.cloudflare.docker.com", "*.cloudflarestorage.com"}},
	// Language registries.
	{Match: []string{"registry.npmjs.org", "*.npmjs.org"}},
	// JSR's npm-compatibility registry (deno/bun/npm resolve @jsr/* here).
	{Match: []string{"npm.jsr.io"}, Add: "/pkgs/npm"},
	{Match: []string{"pypi.org", "files.pythonhosted.org"}},
	{Match: []string{"proxy.golang.org", "sum.golang.org"}},
	{Match: []string{"crates.io", "index.crates.io", "static.crates.io"}},
	{Match: []string{"repo.maven.apache.org"}},
	// Maven-layout mirrors: the maven adapter serves them host-driven, so the
	// mirror's path prefix is stripped before the /pkgs/maven mount.
	{Match: []string{"dl.google.com"}, Strip: "/dl/android/maven2", Add: "/pkgs/maven"},
	{Match: []string{"plugins.gradle.org"}, Strip: "/m2", Add: "/pkgs/maven"},
	{Match: []string{"repo.clojars.org"}, Add: "/pkgs/maven"},
	{Match: []string{"repo.spring.io"}, Strip: "/release", Add: "/pkgs/maven"},
	{Match: []string{"jitpack.io"}, Add: "/pkgs/maven"},
	{Match: []string{"api.nuget.org", "azuresearch-usnc.nuget.org"}},
	{Match: []string{"rubygems.org", "index.rubygems.org"}},
	{Match: []string{"repo.packagist.org"}},
	{Match: []string{"repo.hex.pm"}},
	// hex.pm itself is the API host: publish, search and `mix hex.user auth`.
	{Match: []string{"hex.pm", "api.hex.pm"}},
	{Match: []string{"pub.dev"}},
	{Match: []string{"charts.helm.sh"}},
	{Match: []string{"center.conan.io", "center2.conan.io"}},
	{Match: []string{"api.spm.swift.org"}},
	// System packages.
	{Match: []string{"dl-cdn.alpinelinux.org"}},
	{Match: []string{"deb.debian.org", "security.debian.org"}},
	{Match: []string{"archive.ubuntu.com", "security.ubuntu.com"}},
	{Match: []string{"*.elrepo.org", "mirror.stream.centos.org", "dl.fedoraproject.org"}},
	// AI/ML.
	{Match: []string{"huggingface.co", "*.huggingface.co", "cdn-lfs.huggingface.co"}},
	{Match: []string{"repo.anaconda.com", "conda.anaconda.org"}},
	// Nix binary cache.
	{Match: []string{"cache.nixos.org"}},
	// Source mirrors: git smart-HTTP (git protocol) and Ivy repositories.
	{Match: []string{"github.com", "codeload.github.com"}},
	{Match: []string{"repo.scala-sbt.org", "scala.jfrog.io"}},
	// Plain-HTTP package trees (Haskell, R, Perl, Lua) + Julia's package server.
	{Match: []string{"hackage.haskell.org"}},
	{Match: []string{"cran.r-project.org"}},
	{Match: []string{"cpan.metacpan.org"}},
	{Match: []string{"luarocks.org"}},
	{Match: []string{"pkg.julialang.org", "*.pkg.julialang.org"}},
	// Additional plain-HTTP trees (JSR native, opam, Stackage, PECL, Bazel BCR,
	// Jenkins update center).
	{Match: []string{"jsr.io"}, Add: "/pkgs/jsr"},
	{Match: []string{"opam.ocaml.org"}, Add: "/pkgs/opam"},
	{Match: []string{"stackage.org"}, Add: "/pkgs/stackage"},
	{Match: []string{"pecl.php.net"}, Add: "/pkgs/pecl"},
	{Match: []string{"bcr.bazel.build"}, Add: "/pkgs/bazel"},
	{Match: []string{"updates.jenkins.io"}, Add: "/pkgs/jenkins"},
}

// DefaultRulesYAML renders the built-in rule set with the given gateway
// target ("host:port"). Rewrite relays preserve the ORIGINAL Host header, so
// the gateway's protocol adapters route by Host (X-Forwarded-Host when the
// request is re-origin'd). No path rewriting: adapters mount at their own
// prefixes and the relay preserves the upstream path shape.
func DefaultRulesYAML(gatewayHostPort string) string {
	var b strings.Builder
	b.WriteString("# easysidecar default egress policy: package-manager upstreams are\n")
	b.WriteString("# steered into easylab's pull-through registry; everything else is direct.\n")
	b.WriteString("rules:\n")
	for _, u := range defaultUpstreams {
		b.WriteString("  - match: [" + quoteList(u.Match) + "]\n")
		b.WriteString("    action: rewrite\n")
		b.WriteString("    target: \"" + gatewayHostPort + "\"\n")
		if u.Strip != "" {
			b.WriteString("    strip_prefix: \"" + u.Strip + "\"\n")
		}
		if u.Add != "" {
			b.WriteString("    add_prefix: \"" + u.Add + "\"\n")
		}
	}
	b.WriteString("default: direct\n")
	b.WriteString("mitm_default: false\n")
	return b.String()
}

func quoteList(items []string) string {
	quoted := make([]string, 0, len(items))
	for _, i := range items {
		quoted = append(quoted, fmt.Sprintf("%q", i))
	}
	return strings.Join(quoted, ", ")
}

// HasUpstreamDomain reports whether a hostname is covered by the default
// rewrite list (used by tests and diagnostics).
func HasUpstreamDomain(host string) bool {
	for _, u := range defaultUpstreams {
		for _, m := range u.Match {
			if MatchHost(m, host) {
				return true
			}
		}
	}
	return false
}
