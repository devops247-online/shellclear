#!/usr/bin/env bash
# Supply-chain and vulnerability checks, run by CI, by the release workflow
# before anything is built, and locally with `make security`.
#
#   scripts/security-scan.sh              run every check in parallel
#   scripts/security-scan.sh trivy grype  run the named checks in parallel
#   scripts/security-scan.sh --list       print check names and roles
#
# Gates (a failure blocks the build):
#   modverify    go mod verify: module checksums match go.sum
#   govulncheck  known vulnerabilities in code paths the binary really calls
#   grype        independent SCA of go.mod; fixable CRITICAL issues
#   trivy        vulnerabilities, misconfigurations, secrets and licenses;
#                fixable HIGH and CRITICAL issues
# Informational (reported, never blocking):
#   osv          every known vulnerability in go.mod, reachable or not
#   capslock     what the code and its dependencies can do (net, exec, fs, unsafe)
#
# Tool versions are pinned. Go tools are installed with `go install`, so their
# sources are checked against the Go checksum database. Trivy is a prebuilt
# release with a pinned sha256: the TrendSpider mirror build on Linux (as in
# CI) and the upstream Aqua Security build on macOS, where the mirror has none.
set -uo pipefail

GOVULNCHECK_VERSION=v1.8.0
GRYPE_VERSION=v0.119.0
OSV_SCANNER_VERSION=v2.6.0
CAPSLOCK_VERSION=v0.3.3
TRIVY_VERSION=0.74.0
TRIVY_MIRROR=https://github.com/TrendSpider/trivy/releases/download
TRIVY_UPSTREAM=https://github.com/aquasecurity/trivy/releases/download
TRIVY_SHA256_LINUX_AMD64=84e3d7100c9614087ae40773a8213adc0942d99d15f3f84b1be02800164f349c  # mirror
TRIVY_SHA256_LINUX_ARM64=f8640f1e9e450827484dc75722cacd4edf00293b66ba17c8a58945c20c0a6379  # mirror
TRIVY_SHA256_MACOS_AMD64=472816f6888dda689d075c30254d4210b4d1035acf365aa72332f584c2f60485  # upstream
TRIVY_SHA256_MACOS_ARM64=1caada5e0e2091909357c7525d3aa76f4b660b13821bc143b190c7483e31cc11  # upstream
# Tried in order; Trivy falls back to the next one when a registry fails.
TRIVY_DB_REPOSITORIES=public.ecr.aws/aquasecurity/trivy-db:2,mirror.gcr.io/aquasec/trivy-db:2,ghcr.io/aquasecurity/trivy-db:2
INFO_TIMEOUT=300 # seconds; informational tools must never stall a build

GATES=(modverify govulncheck grype trivy)
INFOS=(osv capslock)

cd "$(dirname "$0")/.."
TOOLS_DIR="${TOOLS_DIR:-$PWD/bin/tools}"
mkdir -p "$TOOLS_DIR"

banner() { # tool, version, home page, role
	echo ""
	echo "╔══════════════════════════════════════════════════════════════════════╗"
	printf "║  %-68s║\n" "$1"
	printf "║      version : %-54s║\n" "$2"
	printf "║      home    : %-54s║\n" "$3"
	printf "║      role    : %-54s║\n" "$4"
	echo "╚══════════════════════════════════════════════════════════════════════╝"
	echo ""
}

annotate() { # level, message: GitHub annotation in CI, plain text elsewhere
	if [ -n "${GITHUB_ACTIONS:-}" ]; then echo "::$1::$2"; else echo "$(echo "$1" | tr '[:lower:]' '[:upper:]'): $2"; fi
}

with_timeout() {
	if command -v timeout >/dev/null 2>&1; then
		timeout "$INFO_TIMEOUT" "$@"
	elif command -v gtimeout >/dev/null 2>&1; then
		gtimeout "$INFO_TIMEOUT" "$@"
	else
		"$@"
	fi
}

sha256() {
	if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a 256 "$1"; fi | awk '{print $1}'
}

# go_tool installs a pinned Go tool once; parallel checks install different tools.
go_tool() { # binary name, go package@version
	local bin="$TOOLS_DIR/$1" stamp="$TOOLS_DIR/.$1.version"
	if [ -x "$bin" ] && [ "$(cat "$stamp" 2>/dev/null)" = "$2" ]; then
		return 0
	fi
	echo "installing $2"
	GOBIN="$TOOLS_DIR" go install "$2" && echo "$2" >"$stamp"
}

install_trivy() {
	local bin="$TOOLS_DIR/trivy" stamp="$TOOLS_DIR/.trivy.version"
	if [ -x "$bin" ] && [ "$(cat "$stamp" 2>/dev/null)" = "$TRIVY_VERSION" ]; then
		return 0
	fi
	local base label sum
	case "$(uname -s)/$(uname -m)" in
	Linux/x86_64 | Linux/amd64) base=$TRIVY_MIRROR label=Linux-64bit sum=$TRIVY_SHA256_LINUX_AMD64 ;;
	Linux/aarch64 | Linux/arm64) base=$TRIVY_MIRROR label=Linux-ARM64 sum=$TRIVY_SHA256_LINUX_ARM64 ;;
	Darwin/x86_64) base=$TRIVY_UPSTREAM label=macOS-64bit sum=$TRIVY_SHA256_MACOS_AMD64 ;;
	Darwin/arm64) base=$TRIVY_UPSTREAM label=macOS-ARM64 sum=$TRIVY_SHA256_MACOS_ARM64 ;;
	*)
		echo "no pinned trivy build for $(uname -s)/$(uname -m)"
		return 1
		;;
	esac
	local name="trivy_${TRIVY_VERSION}_${label}.tar.gz"
	local tgz="$TOOLS_DIR/$name"
	echo "downloading $base/v$TRIVY_VERSION/$name"
	curl -fsSL --retry 3 -o "$tgz" "$base/v$TRIVY_VERSION/$name" || return 1
	if [ "$(sha256 "$tgz")" != "$sum" ]; then
		annotate error "trivy archive checksum mismatch"
		rm -f "$tgz"
		return 1
	fi
	tar -xzf "$tgz" -C "$TOOLS_DIR" trivy && rm -f "$tgz" && echo "$TRIVY_VERSION" >"$stamp"
}

# ── checks: each prints its own report and returns non-zero on failure ──

check_modverify() {
	banner "go mod verify" "$(go version | awk '{print $3}')" \
		"https://pkg.go.dev/cmd/go#hdr-Verify_dependencies" "GATE: dependency integrity"
	go mod verify || {
		annotate error "go mod verify: module checksum mismatch (possible tampering)"
		return 1
	}
}

check_govulncheck() {
	go_tool govulncheck "golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION" || return 1
	banner "govulncheck (Go)" "$GOVULNCHECK_VERSION" \
		"https://github.com/golang/vuln" "GATE: reachable vulnerabilities"
	# -show verbose also lists vulnerabilities in modules the code does not
	# call; only reachable ones fail the check.
	"$TOOLS_DIR/govulncheck" -show verbose ./... || {
		annotate error "govulncheck: reachable vulnerabilities found"
		return 1
	}
}

check_grype() {
	go_tool grype "github.com/anchore/grype/cmd/grype@$GRYPE_VERSION" || return 1
	banner "Grype (Anchore)" "$GRYPE_VERSION" \
		"https://github.com/anchore/grype" "GATE: fixable CRITICAL vulnerabilities"
	"$TOOLS_DIR/grype" dir:. --exclude './**/testdata/**' --exclude './bin/**' --exclude './dist/**' \
		--only-fixed --fail-on critical || {
		annotate error "grype: fixable CRITICAL vulnerabilities found"
		return 1
	}
}

check_trivy() {
	install_trivy || {
		annotate error "trivy: installation failed"
		return 1
	}
	banner "Trivy (Aqua Security)" "$TRIVY_VERSION" \
		"https://github.com/aquasecurity/trivy" "GATE: fixable HIGH/CRITICAL, secrets, licenses"
	# Test fixtures contain fake, token-shaped strings on purpose; the secret
	# scanner allows them through trivy-secret.yaml, every other scanner still
	# sees them.
	# An empty DOCKER_CONFIG makes the DB download anonymous, as in CI, so
	# stale registry credentials on a workstation cannot break it.
	local docker_config
	docker_config="$(mktemp -d)"
	DOCKER_CONFIG="$docker_config" "$TOOLS_DIR/trivy" fs . \
		--scanners vuln,misconfig,secret,license --severity HIGH,CRITICAL \
		--ignore-unfixed --license-full --exit-code 3 --no-progress \
		--skip-dirs bin --skip-dirs dist \
		--secret-config trivy-secret.yaml \
		--db-repository "$TRIVY_DB_REPOSITORIES"
	local rc=$?
	rm -rf "$docker_config"
	case $rc in
	0) ;;
	3)
		annotate error "trivy: HIGH or CRITICAL findings"
		return 1
		;;
	*)
		annotate error "trivy: the scan did not complete"
		return 1
		;;
	esac
}

check_osv() {
	go_tool osv-scanner "github.com/google/osv-scanner/v2/cmd/osv-scanner@$OSV_SCANNER_VERSION" || {
		annotate warning "osv-scanner: installation failed (informational)"
		return 0
	}
	banner "osv-scanner (Google OSV)" "$OSV_SCANNER_VERSION" \
		"https://github.com/google/osv-scanner" "INFO: all known vulnerabilities, not blocking"
	with_timeout "$TOOLS_DIR/osv-scanner" scan source --lockfile go.mod ||
		annotate warning "osv-scanner reported vulnerabilities or timed out (informational)"
	return 0
}

check_capslock() {
	go_tool capslock "github.com/google/capslock/cmd/capslock@$CAPSLOCK_VERSION" || {
		annotate warning "capslock: installation failed (informational)"
		return 0
	}
	banner "capslock (Google)" "$CAPSLOCK_VERSION" \
		"https://github.com/google/capslock" "INFO: capability analysis, not blocking"
	with_timeout "$TOOLS_DIR/capslock" -packages ./... ||
		annotate warning "capslock returned non-zero or timed out (informational)"
	return 0
}

# ── driver ──

if [ "${1:-}" = "--list" ]; then
	for c in "${GATES[@]}"; do echo "$c gate"; done
	for c in "${INFOS[@]}"; do echo "$c info"; done
	exit 0
fi

checks=("$@")
[ ${#checks[@]} -eq 0 ] && checks=("${GATES[@]}" "${INFOS[@]}")
for c in "${checks[@]}"; do
	if ! declare -F "check_$c" >/dev/null; then
		echo "unknown check: $c (see --list)" >&2
		exit 2
	fi
done

# A single check runs in the foreground with live output (one CI job each).
if [ ${#checks[@]} -eq 1 ]; then
	"check_${checks[0]}"
	exit $?
fi

# Several checks run in parallel; each writes its own log, printed in order.
logs="$(mktemp -d)"
trap 'rm -rf "$logs"' EXIT
pids=()
for c in "${checks[@]}"; do
	("check_$c" >"$logs/$c.log" 2>&1) &
	pids+=($!)
done

FAILED=()
i=0
for c in "${checks[@]}"; do
	if wait "${pids[$i]}"; then status=0; else status=$?; fi
	i=$((i + 1))
	cat "$logs/$c.log"
	echo "$status" >"$logs/$c.status"
	[ "$status" -ne 0 ] && FAILED+=("$c")
done

echo ""
echo "Summary:"
for c in "${checks[@]}"; do
	if [ "$(cat "$logs/$c.status")" -eq 0 ]; then mark="✅"; else mark="❌"; fi
	printf "  %s %s\n" "$mark" "$c"
done
if [ ${#FAILED[@]} -ne 0 ]; then
	echo "Blocking checks failed: ${FAILED[*]}"
	exit 1
fi
echo "All checks passed."
