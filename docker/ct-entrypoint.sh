#!/bin/sh
# Run the named Common Test suites. Arguments are suite names.
set -e

if [ "$#" -eq 0 ]; then
    echo "usage: <suite> [suite...]" >&2
    exit 2
fi

# The socket backend asks for buffers larger than the container default,
# and the kernel silently clamps them; raise the ceiling where the
# container is allowed to, and carry on where it is not.
sysctl -w net.core.rmem_max=16777216 >/dev/null 2>&1 || true
sysctl -w net.core.wmem_max=16777216 >/dev/null 2>&1 || true

SUITES=$(echo "$@" | tr ' ' ',')
exec rebar3 ct --suite="$SUITES"
