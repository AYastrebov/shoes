#!/bin/sh
# Rebuilds mixed-v4-v6.srs from its JSON source with the sing-box CLI.
# The fixture was generated with sing-box 1.14.2.
set -eu
cd "$(dirname "$0")"
sing-box rule-set compile --output mixed-v4-v6.srs mixed-v4-v6.json
