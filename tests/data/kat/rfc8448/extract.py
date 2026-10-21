"""Writes vectors.json from RFC 8448 section 3, "Simple 1-RTT Handshake".

    python3 -I extract.py rfc8448.txt

The RFC prints every step of the schedule as a block: a heading such as
`{server}  derive secret "tls13 c hs traffic":` and fields such as
`hash (32 octets):  86 0c ...` wrapped over several lines. Only the
transcript hash for the server's Finished is not printed, so it is the
SHA-256 of the handshake messages the RFC does print.
"""

import hashlib
import json
import re
import sys

HEADING = re.compile(r"^   \{(client|server)\}  (.*?):?$")
FIELD = re.compile(r"^      ([A-Za-z]+(?: [a-z]+)?) \((\d+) octets\):  (.*)$")
PAGE = re.compile(r"^(Thomson .*\[Page \d+\]|\f|RFC 8448 .*)$")


def blocks(text):
    section = text.split("\n3.  Simple 1-RTT Handshake", 1)[1]
    section = section.split("\n4.  Resumed 0-RTT Handshake", 1)[0]
    current, field = None, None
    for line in section.splitlines():
        heading = HEADING.match(line)
        if heading:
            current = {"side": heading[1], "title": heading[2], "fields": {}, "lengths": {}}
            yield current
            field = None
            continue
        match = FIELD.match(line)
        if match and current is not None:
            field = match[1]
            current["fields"][field] = match[3]
            current["lengths"][field] = int(match[2])
        elif field and line.startswith("         ") and re.fullmatch(r"[0-9a-f ]+", line.strip()):
            current["fields"][field] += " " + line.strip()
        elif not line.strip() or PAGE.match(line):
            # A blank line, or the footer and header of a page break, which
            # can fall in the middle of a long field.
            pass
        else:
            field = None


def octets(value):
    return "" if value == "(empty)" else value.replace(" ", "")


def main(path):
    found = list(blocks(open(path).read()))

    def get(side, title, field, nth=0):
        matches = [b for b in found if b["side"] == side and b["title"] == title]
        value = octets(matches[nth]["fields"][field])
        expected = matches[nth]["lengths"][field]
        assert len(value) == 2 * expected, f"{title} {field}: {len(value) // 2} of {expected} octets"
        return value

    messages = [
        get("client", "construct a ClientHello handshake message", "ClientHello"),
        get("server", "construct a ServerHello handshake message", "ServerHello"),
        get("server", "construct an EncryptedExtensions handshake message", "EncryptedExtensions"),
        get("server", "construct a Certificate handshake message", "Certificate"),
        get("server", "construct a CertificateVerify handshake message", "CertificateVerify"),
    ]
    through_certificate_verify = hashlib.sha256(bytes.fromhex("".join(messages))).hexdigest()

    vectors = {
        "source": "RFC 8448 section 3, extracted by extract.py",
        "cipher_suite": "TLS_AES_128_GCM_SHA256",
        "shared_secret": get("server", 'extract secret "handshake"', "IKM"),
        "hello_hash": get("server", 'derive secret "tls13 c hs traffic"', "hash"),
        "client_handshake_traffic_secret": get("server", 'derive secret "tls13 c hs traffic"', "expanded"),
        "server_handshake_traffic_secret": get("server", 'derive secret "tls13 s hs traffic"', "expanded"),
        "master_secret": get("server", 'extract secret "master"', "secret"),
        "server_handshake_key": get("server", "derive write traffic keys for handshake data", "key expanded"),
        "server_handshake_iv": get("server", "derive write traffic keys for handshake data", "iv expanded"),
        "client_handshake_key": get("server", "derive read traffic keys for handshake data", "key expanded"),
        "client_handshake_iv": get("server", "derive read traffic keys for handshake data", "iv expanded"),
        "server_finished_hash": through_certificate_verify,
        "server_finished": get("server", 'calculate finished "tls13 finished"', "finished"),
        "handshake_hash": get("server", 'derive secret "tls13 c ap traffic"', "hash"),
        "client_finished": get("client", 'calculate finished "tls13 finished"', "finished"),
        "client_application_traffic_secret": get("server", 'derive secret "tls13 c ap traffic"', "expanded"),
        "server_application_traffic_secret": get("server", 'derive secret "tls13 s ap traffic"', "expanded"),
        "server_application_key": get("server", "derive write traffic keys for application data", "key expanded"),
        "server_application_iv": get("server", "derive write traffic keys for application data", "iv expanded"),
        "client_application_key": get("client", "derive write traffic keys for application data", "key expanded"),
        "client_application_iv": get("client", "derive write traffic keys for application data", "iv expanded"),
    }
    with open("vectors.json", "w") as out:
        json.dump(vectors, out, indent=2, sort_keys=True)
        out.write("\n")


if __name__ == "__main__":
    main(sys.argv[1])
