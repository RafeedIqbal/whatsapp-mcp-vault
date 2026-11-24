#!/bin/sh
# Container entrypoint.
#
# A mounted data disk usually arrives owned by root, while the server runs as
# the unprivileged user "app". When started as root this script hands the
# store directory to that user and then drops privileges for good; when the
# container is already running as "app" it just starts the server.
set -eu

STORE=/home/app/store

if [ "$(id -u)" = "0" ]; then
	mkdir -p "$STORE"
	chown -R app:app "$STORE"
	chmod 700 "$STORE"
	export HOME=/home/app
	exec setpriv --reuid=app --regid=app --init-groups --no-new-privs \
		whatsapp-mcp -store "$STORE" "$@"
fi

exec whatsapp-mcp -store "$STORE" "$@"
