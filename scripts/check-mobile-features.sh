#!/usr/bin/env bash
# The controller and the connection registry must never ship in a mobile
# artifact: they hold runtime state per connection, which is the budget a
# phone cannot spare (MOBILE.md).
#
# Two checks, because neither alone is enough.
#
# A symbol check on the built library is not one of them. feature/control-api
# found it unreliable: the mobile artifacts are stripped, and fat LTO removes
# an unreferenced module even when its feature is on, so the check passes
# whether or not the feature was enabled. These guard the source of truth
# instead -- what the build commands ask for, and what cargo resolves from it.
set -euo pipefail
cd "$(dirname "$0")/.."

features='clash-api|control-connections'

# 1. No mobile build script names either feature.
#
#    One file at a time, and only files that exist: `grep` over a missing
#    path exits 2, and an `if` reads that as "no match" however many matches
#    the other files held -- which made this check unable to fail.
found=0
for script in scripts/build-android.sh scripts/build-apple.sh scripts/build-ios.sh; do
    [ -f "$script" ] || continue
    if grep -En -- "$features" "$script"; then
        found=1
    fi
done
if [ "$found" -ne 0 ]; then
    echo "ERROR: a mobile build script enables a controller feature (see above)" >&2
    exit 1
fi

# 2. Nothing the mobile feature sets pull in resolves one either, which is
#    what catches a feature implication added later that a grep cannot see.
#
#    `cargo metadata` rather than `cargo tree -e features`: the latter prints
#    the features of dependencies and never the root crate's own, so a grep
#    over it matches nothing whatever the features are -- a check that cannot
#    fail. This reads the resolved set for the `shoes` package itself.
for set in "control-stats" "ffi,control-stats,network-extension"; do
    resolved="$(cargo metadata --format-version 1 --locked --features "$set" |
        python3 -c '
import json, sys
metadata = json.load(sys.stdin)
for node in metadata["resolve"]["nodes"]:
    if node["id"].split("#")[0].endswith("/shoes") or node["id"].endswith("shoes"):
        print("\n".join(sorted(node["features"])))
        break
')"
    if grep -Eq "^($features)$" <<<"$resolved"; then
        echo "ERROR: the mobile feature set '$set' resolves a controller feature:" >&2
        grep -E "^($features)$" <<<"$resolved" >&2
        exit 1
    fi
done

echo "OK: the mobile builds carry neither the controller nor the connection registry"
