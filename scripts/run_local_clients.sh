#!/usr/bin/env bash
#
# Cross-language smoke test for the SCG local interfaces (UDS + SHM).
#
# Builds the gateway, a TLS echo upstream, and the Rust/C/C++ example clients,
# launches the gateway with a temporary config, then drives a send/recv
# round-trip with each client over both UDS and SHM. Exits 0 only when every
# client x transport combination succeeds.
#
# Designed to run unprivileged: the runtime directory is a throwaway temp dir,
# so no chown/root paths are taken. Skips gracefully (exit 0) when a hard
# prerequisite (cargo) is missing; a missing C/C++ toolchain only drops those
# clients, the Rust client still runs.
#
# Usage:
#   scripts/run_local_clients.sh            # debug build
#   PROFILE=release scripts/run_local_clients.sh

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PROFILE="${PROFILE:-debug}"
APP="app-test"
MSG="scg-cross-lang-$$"

skip() { echo "SKIP: $*"; exit 0; }
fail() { echo "FAIL: $*" >&2; exit 1; }

command -v cargo >/dev/null 2>&1 || skip "cargo not found"

CARGO_FLAGS=()
[ "$PROFILE" = "release" ] && CARGO_FLAGS+=(--release)
TARGET="$ROOT/target/$PROFILE"

echo "==> Building gateway + tls_echo example"
cargo build "${CARGO_FLAGS[@]}" -p gateway --bin gateway --example tls_echo \
    || fail "gateway build failed"

echo "==> Building scg-client library + Rust example"
cargo build "${CARGO_FLAGS[@]}" -p scg-client --example rust_roundtrip \
    || fail "scg-client build failed"

# The C/C++ clients are optional: build them only if a toolchain is present.
HAVE_NATIVE=1
for tool in make cc c++; do
    command -v "$tool" >/dev/null 2>&1 || HAVE_NATIVE=0
done
if [ "$HAVE_NATIVE" = 1 ]; then
    echo "==> Building C and C++ example clients"
    make -C crates/scg-client/examples PROFILE="$PROFILE" clean all \
        || fail "C/C++ client build failed"
else
    echo "==> No C/C++ toolchain found; testing the Rust client only"
fi

WORK="$(mktemp -d)"
ECHO_PID=""
GW_PID=""
cleanup() {
    [ -n "$GW_PID" ]   && kill "$GW_PID"   2>/dev/null
    [ -n "$ECHO_PID" ] && kill "$ECHO_PID" 2>/dev/null
    wait 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

# ── TLS echo upstream on an ephemeral port ───────────────────────────────────
ECHO_OUT="$WORK/echo.out"
"$TARGET/examples/tls_echo" "127.0.0.1:0" >"$ECHO_OUT" 2>/dev/null &
ECHO_PID=$!
UPSTREAM=""
for _ in $(seq 1 50); do
    UPSTREAM="$(sed -n 's/^LISTENING //p' "$ECHO_OUT" 2>/dev/null | head -n1)"
    [ -n "$UPSTREAM" ] && break
    sleep 0.1
done
[ -n "$UPSTREAM" ] || fail "tls_echo never reported a listen address"
echo "==> TLS echo upstream listening on $UPSTREAM"

# ── Gateway config ───────────────────────────────────────────────────────────
MGMT="$WORK/mgmt.sock"
UID_NUM="$(id -u)"
cat >"$WORK/gw.json" <<JSON
{
  "log_dir": "$WORK",
  "rules": [
    { "name": "uds-test", "direction": "encrypt", "listen_addr": "unused",
      "listen_proto": "uds", "upstream_addr": "$UPSTREAM", "upstream_proto": "tcp",
      "security_provider": "tls", "traffic_class": "safety", "app_id": "$APP",
      "allowed_uids": [$UID_NUM] },
    { "name": "shm-test", "direction": "encrypt", "listen_addr": "unused",
      "listen_proto": "shm", "upstream_addr": "$UPSTREAM", "upstream_proto": "tcp",
      "security_provider": "tls", "traffic_class": "safety", "app_id": "$APP",
      "allowed_uids": [$UID_NUM] }
  ],
  "api": { "enabled": true, "uds_path": "$MGMT", "runtime_dir": "$WORK/run",
           "shm_ring_capacity": 65536 }
}
JSON

echo "==> Launching gateway"
"$TARGET/gateway" --config "$WORK/gw.json" --log-level warn >"$WORK/gw.log" 2>&1 &
GW_PID=$!

for _ in $(seq 1 50); do [ -S "$MGMT" ] && break; sleep 0.1; done
if [ ! -S "$MGMT" ]; then
    cat "$WORK/gw.log" >&2
    fail "management socket never appeared"
fi

# ── Drive the clients ────────────────────────────────────────────────────────
PASS=0
TOTAL=0

# The success line printed by every example client on a good round-trip.
check_output() { grep -q "recv: traffic_id=1 .*bytes: .*$MSG" "$1"; }

run_rust() {
    local t="$1"
    local out="$WORK/rust_$t.out"
    TOTAL=$((TOTAL + 1))
    if "$TARGET/examples/rust_roundtrip" --app "$APP" --transport "$t" \
            --class safety --mgmt "$MGMT" --message "$MSG" >"$out" 2>&1 \
            && check_output "$out"; then
        echo "  PASS rust/$t"; PASS=$((PASS + 1))
    else
        echo "  FAIL rust/$t"; sed 's/^/    /' "$out" >&2
    fi
}

run_native() {
    local bin="$1" lang="$2" t="$3"
    local out="$WORK/${lang}_$t.out"
    TOTAL=$((TOTAL + 1))
    if LD_LIBRARY_PATH="$TARGET" "$bin" "$APP" "$t" safety "$MGMT" "$MSG" \
            >"$out" 2>&1 && check_output "$out"; then
        echo "  PASS $lang/$t"; PASS=$((PASS + 1))
    else
        echo "  FAIL $lang/$t"; sed 's/^/    /' "$out" >&2
    fi
}

echo "==> Running client round-trips"
for t in uds shm; do
    run_rust "$t"
    if [ "$HAVE_NATIVE" = 1 ]; then
        run_native "crates/scg-client/examples/c_client" c "$t"
        run_native "crates/scg-client/examples/cpp_client" cpp "$t"
    fi
done

echo "==> $PASS/$TOTAL client round-trips passed"
[ "$PASS" -eq "$TOTAL" ] && [ "$TOTAL" -gt 0 ] || fail "some client round-trips failed"
echo "OK"
