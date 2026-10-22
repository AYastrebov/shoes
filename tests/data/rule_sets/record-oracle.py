"""Record what sing-box says about the rule-set fixtures, for shoes to match.

Writes oracle.json: for each (fixture, target) case, whether
`sing-box rule-set match -f binary` matched; and for each file under
corrupt/, which this script also writes from mixed-v4-v6.srs, whether
sing-box could load it at all. tests/rule_set_golden.rs reads the result.

    python3 -I tests/data/rule_sets/record-oracle.py /path/to/sing-box

The fixtures were recorded with sing-box 1.14.3.
"""

import json
import os
import subprocess
import sys
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))

CASES = [
    ("geosite-google.srs", "google.com"),
    ("geosite-google.srs", "www.google.com"),
    ("geosite-google.srs", "mail.google.com"),
    ("geosite-google.srs", "notgoogle.com"),
    ("geosite-google.srs", "google.com.example.org"),
    ("geosite-google.srs", "r1---sn-2x3abcde.googlevideo.com"),
    ("geosite-google.srs", "example.org"),
    ("geosite-telegram.srs", "telegram.org"),
    ("geosite-telegram.srs", "web.telegram.org"),
    ("geosite-telegram.srs", "t.me"),
    ("geosite-telegram.srs", "telegram.org.example.org"),
    ("geosite-telegram.srs", "example.org"),
    ("geosite-cloudflare.srs", "cloudflare.com"),
    ("geosite-cloudflare.srs", "dash.cloudflare.com"),
    ("geosite-cloudflare.srs", "notcloudflare.com"),
    ("geosite-cloudflare.srs", "1.1.1.1"),
    ("geosite-category-ads-all.srs", "doubleclick.net"),
    ("geosite-category-ads-all.srs", "ad.doubleclick.net"),
    ("geosite-category-ads-all.srs", "example.org"),
    ("geoip-ru.srs", "77.88.8.8"),
    ("geoip-ru.srs", "8.8.8.8"),
    ("geoip-ru.srs", "2a02:6b8::feed:0ff"),
    ("geoip-ru.srs", "2001:4860:4860::8888"),
    ("geoip-ru.srs", "yandex.ru"),
    ("geoip-us.srs", "8.8.8.8"),
    ("geoip-us.srs", "77.88.8.8"),
    ("geoip-us.srs", "2001:4860:4860::8888"),
    ("mixed-v4-v6.srs", "10.1.2.3"),
    ("mixed-v4-v6.srs", "192.168.7.7"),
    ("mixed-v4-v6.srs", "11.0.0.1"),
    ("mixed-v4-v6.srs", "::1"),
    ("mixed-v4-v6.srs", "::2"),
    ("mixed-v4-v6.srs", "64:ff9b::808:808"),
    ("mixed-v4-v6.srs", "64:ff9c::1"),
]


def corruptions(good):
    """Each a name and the bytes, all from one valid file."""
    body = good[4:]
    yield "bad-magic", b"SRX" + good[3:]
    yield "version-0", good[:3] + b"\x00" + body
    yield "version-255", good[:3] + b"\xff" + body
    yield "truncated-header", good[:3]
    yield "truncated-body", good[: 4 + len(body) // 2]
    yield "no-checksum", good[:-4]
    yield "bad-checksum", good[:-1] + bytes([good[-1] ^ 0x01])
    yield "garbage-body", good[:4] + bytes((i * 37 + 11) & 0xFF for i in range(64))
    # A valid zlib stream whose payload is not a rule list.
    yield "garbage-payload", good[:4] + zlib.compress(b"\xff" * 32)


def matched(sing_box, path, target):
    out = subprocess.run(
        [sing_box, "--disable-color", "rule-set", "match", "-f", "binary", path, target],
        capture_output=True,
        text=True,
    )
    if out.returncode != 0:
        sys.exit(f"sing-box failed on {path} {target}: {out.stderr}")
    # The match line goes to stderr when the output is not a terminal.
    lines = (out.stdout + out.stderr).splitlines()
    return any(line.startswith("match rules.") for line in lines)


def loads(sing_box, path):
    # Any address will do: what is recorded is whether the file loads.
    out = subprocess.run(
        [sing_box, "--disable-color", "rule-set", "match", "-f", "binary", path, "10.1.2.3"],
        capture_output=True,
        text=True,
    )
    return out.returncode == 0


def main():
    sing_box = sys.argv[1]
    version = subprocess.run([sing_box, "version"], capture_output=True, text=True)
    cases = [
        {"file": f, "target": t, "matched": matched(sing_box, os.path.join(HERE, f), t)}
        for f, t in CASES
    ]

    corrupt_dir = os.path.join(HERE, "corrupt")
    os.makedirs(corrupt_dir, exist_ok=True)
    with open(os.path.join(HERE, "mixed-v4-v6.srs"), "rb") as f:
        good = f.read()
    corrupt = []
    for name, data in corruptions(good):
        path = os.path.join(corrupt_dir, name + ".srs")
        with open(path, "wb") as f:
            f.write(data)
        corrupt.append({"file": "corrupt/" + name + ".srs", "loads": loads(sing_box, path)})

    oracle = {
        "source": version.stdout.splitlines()[0] + ": rule-set match -f binary",
        "cases": cases,
        "corrupt": corrupt,
    }
    with open(os.path.join(HERE, "oracle.json"), "w") as f:
        json.dump(oracle, f, indent=2)
        f.write("\n")
    print(f"{len(cases)} cases, {len(corrupt)} corrupt files")


main()
