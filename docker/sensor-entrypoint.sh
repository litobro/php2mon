#!/bin/sh
set -eu
if [ -n "${TLS_DIR:-}" ]; then
  if [ ! -f "$TLS_DIR/cert.pem" ]; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
      -keyout "$TLS_DIR/key.pem" -out "$TLS_DIR/cert.pem" \
      -subj "/CN=${TLS_CN:-localhost}" >/dev/null 2>&1
  fi
  export SSL_CERTFILE="$TLS_DIR/cert.pem" SSL_KEYFILE="$TLS_DIR/key.pem"
fi
exec python -m php2mon.sensor
