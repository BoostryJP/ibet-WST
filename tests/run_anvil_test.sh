#!/usr/bin/env bash

set -euo pipefail

ANVIL_HOST="${ANVIL_HOST:-127.0.0.1}"
ANVIL_PORT="${ANVIL_PORT:-8545}"
ANVIL_LOG_FILE="${ANVIL_LOG_FILE:-/tmp/ibet-wst-anvil.log}"
ANVIL_STARTUP_TIMEOUT_SECONDS="${ANVIL_STARTUP_TIMEOUT_SECONDS:-30}"

anvil_cmd=(
  anvil
  --host "$ANVIL_HOST"
  --port "$ANVIL_PORT"
  --chain-id 2025
  --hardfork osaka
  --gas-limit 16777216
  --gas-price 0
  --block-base-fee-per-gas 0
  --steps-tracing
)

cleanup() {
  if [[ -n "${ANVIL_PID:-}" ]]; then
    kill "$ANVIL_PID" >/dev/null 2>&1 || true
    wait "$ANVIL_PID" >/dev/null 2>&1 || true
  fi
}

listener_pid() {
  lsof -tiTCP:"$ANVIL_PORT" -sTCP:LISTEN 2>/dev/null | head -n 1 || true
}

wait_for_port_release() {
  local attempt
  for ((attempt = 1; attempt <= ANVIL_STARTUP_TIMEOUT_SECONDS; attempt++)); do
    if [[ -z "$(listener_pid)" ]]; then
      return 0
    fi

    sleep 1
  done

  return 1
}

wait_for_anvil() {
  local attempt
  for ((attempt = 1; attempt <= ANVIL_STARTUP_TIMEOUT_SECONDS; attempt++)); do
    if nc -z "$ANVIL_HOST" "$ANVIL_PORT" >/dev/null 2>&1; then
      return 0
    fi

    sleep 1
  done

  return 1
}

trap cleanup EXIT INT TERM

existing_pid="$(listener_pid)"
if [[ -n "$existing_pid" ]]; then
  existing_command="$(ps -p "$existing_pid" -o command= 2>/dev/null || true)"
  if [[ "$existing_command" != *anvil* ]]; then
    echo "Port ${ANVIL_PORT} is already in use by a non-anvil process: ${existing_command}" >&2
    exit 1
  fi

  echo "Stopping existing anvil on ${ANVIL_HOST}:${ANVIL_PORT} (pid ${existing_pid})."
  kill "$existing_pid" >/dev/null 2>&1 || true
  wait "$existing_pid" >/dev/null 2>&1 || true

  if ! wait_for_port_release; then
    echo "Anvil on ${ANVIL_HOST}:${ANVIL_PORT} did not stop within ${ANVIL_STARTUP_TIMEOUT_SECONDS}s." >&2
    exit 1
  fi
fi

"${anvil_cmd[@]}" >"$ANVIL_LOG_FILE" 2>&1 &
ANVIL_PID=$!

if ! wait_for_anvil; then
  echo "Anvil did not become ready within ${ANVIL_STARTUP_TIMEOUT_SECONDS}s." >&2
  echo "Last anvil log output:" >&2
  tail -n 50 "$ANVIL_LOG_FILE" >&2 || true
  exit 1
fi

uv run ape test --network ethereum:local:foundry "$@"