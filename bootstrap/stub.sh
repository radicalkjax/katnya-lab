#!/bin/sh
# Katnya bootstrap stub probe (Q-212). POSIX sh; usage: stub.sh URL SHA256 [OUT]
set -eu
url=$1; want=$2; out=${3:-katnya-asset.bin}
if command -v curl >/dev/null 2>&1; then dl=curl; curl -fsSL --proto '=https' --tlsv1.2 -o "$out" "$url"
elif command -v wget >/dev/null 2>&1; then dl=wget; wget -q -O "$out" "$url"
else echo "katnya-bootstrap: need curl or wget" >&2; exit 2; fi
if command -v sha256sum >/dev/null 2>&1; then h=sha256sum; got=$(sha256sum "$out" | cut -d' ' -f1)
elif command -v shasum >/dev/null 2>&1; then h="shasum -a 256"; got=$(shasum -a 256 "$out" | cut -d' ' -f1)
else echo "katnya-bootstrap: need sha256sum or shasum" >&2; exit 2; fi
if [ "$got" != "$want" ]; then
  rm -f "$out"; echo "katnya-bootstrap: SHA-256 mismatch (got $got, want $want)" >&2; exit 1
fi
echo "katnya-bootstrap: OK sha256=$got via $dl + $h"
