#!/bin/sh
set -e

case "$SERVICE" in
  backend)
    exec python backend_app/app.py
    ;;
  waf)
    exec python waf/app.py
    ;;
  dashboard)
    exec python waf/dashboard.py
    ;;
  *)
    echo "Unknown or unset SERVICE '$SERVICE'. Expected one of: backend, waf, dashboard." >&2
    exit 1
    ;;
esac
