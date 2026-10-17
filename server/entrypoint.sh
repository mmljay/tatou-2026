#!/bin/sh
set -eu

# Flag files are initialized at build time. Never print them or mutate them
# from an application environment variable at process startup.
unset FLAG_2 || true
echo "Starting server..."
exec gunicorn --no-control-socket -b 0.0.0.0:5000 server:app

