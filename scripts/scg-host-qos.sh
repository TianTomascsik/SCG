#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  scg-host-qos.sh apply --dev DEV [--normal-rate RATE] [--normal-burst BYTES] [--normal-latency TIME] [--dry-run]
  scg-host-qos.sh status --dev DEV
  scg-host-qos.sh clear --dev DEV [--dry-run]

Installs host egress QoS for SCG traffic:
  safety sockets: SO_PRIORITY=6 -> prio band 0 (served first)
  normal sockets: SO_PRIORITY=0 -> prio band 1 (served after safety)

Examples:
  sudo ./scripts/scg-host-qos.sh apply --dev eth0 --normal-rate 800mbit
  sudo ./scripts/scg-host-qos.sh status --dev eth0
  sudo ./scripts/scg-host-qos.sh clear --dev eth0
USAGE
}

die() {
  echo "error: $*" >&2
  exit 1
}

run() {
  if [[ "${DRY_RUN}" == "1" ]]; then
    printf '+'
    printf ' %q' "$@"
    printf '\n'
  else
    "$@"
  fi
}

require_root() {
  [[ "${DRY_RUN}" == "1" ]] && return
  [[ "$(id -u)" == "0" ]] || die "apply/clear require root or CAP_NET_ADMIN"
}

ACTION="${1:-}"
shift || true

DEV=""
NORMAL_RATE=""
NORMAL_BURST="256kbit"
NORMAL_LATENCY="50ms"
DRY_RUN=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dev)
      DEV="${2:-}"
      shift 2
      ;;
    --normal-rate)
      NORMAL_RATE="${2:-}"
      shift 2
      ;;
    --normal-burst)
      NORMAL_BURST="${2:-}"
      shift 2
      ;;
    --normal-latency)
      NORMAL_LATENCY="${2:-}"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

[[ -n "${ACTION}" ]] || { usage; exit 1; }
[[ -n "${DEV}" ]] || die "--dev is required"
if [[ "${DRY_RUN}" != "1" ]]; then
  [[ -d "/sys/class/net/${DEV}" ]] || die "network device '${DEV}' does not exist"
fi

# skb priorities 0..15 -> prio bands. Band 0 is highest priority.
# SO_PRIORITY=6 and 7 map to band 0; SO_PRIORITY=0 maps to band 1.
PRIOMAP=(1 2 2 2 1 2 0 0 1 1 1 1 1 1 1 1)

case "${ACTION}" in
  apply)
    require_root
    run tc qdisc replace dev "${DEV}" root handle 1: prio bands 3 priomap "${PRIOMAP[@]}"
    if [[ -n "${NORMAL_RATE}" ]]; then
      run tc qdisc replace dev "${DEV}" parent 1:2 handle 20: tbf \
        rate "${NORMAL_RATE}" burst "${NORMAL_BURST}" latency "${NORMAL_LATENCY}"
    fi
    ;;
  status)
    run tc -s qdisc show dev "${DEV}"
    ;;
  clear)
    require_root
    run tc qdisc del dev "${DEV}" root 2>/dev/null || true
    ;;
  *)
    usage
    exit 1
    ;;
esac
