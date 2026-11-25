#!/bin/sh
# Run a command with SUPPLINE_TEST_POSTGRES_URL pointing at a PostgreSQL
# server. Uses the variable as given when it is already set; otherwise starts
# a throwaway container (data on tmpfs, fsync off) and removes it afterwards.
set -eu

if [ -n "${SUPPLINE_TEST_POSTGRES_URL:-}" ]; then
	exec "$@"
fi

image="${SUPPLINE_TEST_POSTGRES_IMAGE:-postgres:18-alpine}"
container=$(docker run -d --rm \
	-e POSTGRES_USER=suppline -e POSTGRES_PASSWORD=suppline -e POSTGRES_DB=suppline \
	--tmpfs /var/lib/postgresql:rw \
	-p 127.0.0.1::5432 \
	"$image" \
	-c fsync=off -c synchronous_commit=off -c full_page_writes=off -c max_connections=500)
trap 'docker stop "$container" >/dev/null 2>&1 || true' EXIT INT TERM

i=0
until docker exec "$container" pg_isready -U suppline -d suppline -h 127.0.0.1 >/dev/null 2>&1; do
	i=$((i + 1))
	if [ "$i" -gt 60 ]; then
		echo "test postgres did not become ready" >&2
		docker logs "$container" >&2 || true
		exit 1
	fi
	sleep 0.5
done

port=$(docker port "$container" 5432/tcp | head -n1 | sed 's/.*://')
SUPPLINE_TEST_POSTGRES_URL="postgres://suppline:suppline@127.0.0.1:${port}/suppline?sslmode=disable"
export SUPPLINE_TEST_POSTGRES_URL

"$@"
