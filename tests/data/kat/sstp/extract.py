"""Writes vectors.json from sstp-client's own unit-test data.

    python3 -I extract.py <sstp-client>/src

sstp-client (https://gitlab.com/sstp-project/sstp-client, 1.0.20,
dd24312) checks its crypto binding and its MPPE keys against fixed inputs
and expected outputs in two unit tests, `__SSTP_UNIT_TEST_CMAC` in
sstp-cmac.c and `__SSTP_UNIT_TEST_CHAP` in sstp-chap.c. Its EAP-TLS case
was copied from a capture of a Windows 8.1 client against a Windows Server
2019 RAS server, so that one is Windows' own computation. This copies the
numbers, not the code, which is GPL: the arrays are read as data, by name.
"""

import json
import re
import sys

ARRAY = re.compile(r"uint8_t\s+(\w+)\s*\[\s*(\d*)\s*\]\s*=\s*\{(.*?)\};", re.S)
STRING = re.compile(r'sstp_chap_mppe_get\(&ctx,\s*"([^"]*)"')


def function_body(source, name):
    start = source.index(name + "(void)")
    end = source.index("\n}\n", start)
    return source[start:end]


def arrays(body):
    out = {}
    for name, size, values in ARRAY.findall(body):
        values = re.sub(r"/\*.*?\*/", "", values, flags=re.S)
        data = bytes(int(v, 16) for v in re.findall(r"0x[0-9a-fA-F]{2}", values))
        # C zero-fills an array whose initializer is shorter than its size:
        # the EAP-TLS message lists 80 of its 112 bytes, the zeroed MAC
        # field and padding being the rest.
        out[name] = data.ljust(int(size or len(data)), b"\0").hex()
    return out


def main(src):
    cmac = open(f"{src}/sstp-cmac.c").read()
    chap = open(f"{src}/sstp-chap.c").read()

    binding = []
    for function, hash_name, origin in [
        ("sstp_test_sha1", "sha1", "sstp-client's SHA-1 test"),
        ("sstp_test_sha256", "sha256", "sstp-client's SHA-256 test"),
        ("sstp_test_tls", "sha256", "Windows 8.1 client to Windows Server 2019 RAS, EAP-TLS"),
    ]:
        a = arrays(function_body(cmac, "int " + function))
        binding.append(
            {
                "origin": origin,
                "hash": hash_name,
                "call_connected": a["sstp_msg"],
                "send_key": a["mppe_send_key"],
                "recv_key": a["mppe_recv_key"],
                "compound_mac": a["cmac"],
            }
        )

    main_body = chap[chap.index("int main(int argc") :]
    a = arrays(main_body)
    challenge = re.search(r"\.challenge\s*=\s*\{(.*?)\}", main_body, re.S)[1]
    nt_response = re.search(r"\.nt_response\s*=\s*\{(.*?)\}", main_body, re.S)[1]
    mppe = [
        {
            "origin": "sstp-client's MPPE test, client side",
            "password": STRING.search(main_body)[1],
            "challenge": bytes(int(v, 16) for v in re.findall(r"0x[0-9a-fA-F]{2}", challenge)).hex(),
            "nt_response": bytes(int(v, 16) for v in re.findall(r"0x[0-9a-fA-F]{2}", nt_response)).hex(),
            "send_key": a["cmp1"],
            "recv_key": a["cmp2"],
        }
    ]

    with open("vectors.json", "w") as f:
        json.dump(
            {"source": "sstp-client 1.0.20 dd24312", "binding": binding, "mppe": mppe},
            f,
            indent=2,
        )
        f.write("\n")


if __name__ == "__main__":
    main(sys.argv[1])
