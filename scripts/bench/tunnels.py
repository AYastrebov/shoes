#!/usr/bin/env python3
"""Tunnel throughput and latency matrix: shoes against sing-box, over loopback.

One TCP stream (or CONNS of them) goes through a SOCKS5 inbound, across the
tunnel under test, and out to a local sink. Prints Gbps and CPU-seconds per
gigabyte for each process involved, or round-trip latency in mode P.

Environment:
  SHOES   path to the shoes binary       (default: target/release/shoes)
  LAN     address the sink is reached at (default: the first non-loopback one)
  SECS    seconds per run                (default: 6)
  MODES   U,D,P: upload, download, ping  (default: U,D)
  CONNS   connection counts, e.g. 1,8    (default: 1)
  ONLY    substring of a case label, to run just those
  SHOES_CLI_ARGS  extra arguments for the shoes client process, e.g. "-t 2"
  NSTAT   print the kernel's UDP and TCP counters for each run (Linux)
  LOGS    print the last N lines of each shoes process's output at the end
  PERF    record and print a perf profile of each shoes process (Linux);
          PERF_SORT picks the key (symbol, tid, ...), PERF_TOP the rows

The sink address is deliberately not 127.0.0.1: a WireGuard peer's netstack
treats a loopback destination as a martian and drops it.

Needs `sing-box` (with QUIC and WireGuard) and `openssl` on PATH.
"""
import subprocess, time, sys, os, socket, json, tempfile, atexit, shutil

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
SHOES = os.environ.get("SHOES", os.path.join(REPO, "target/release/shoes"))
SINK = 25201


def lan_address():
    if os.environ.get("LAN"):
        return os.environ["LAN"]
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))  # no packet is sent; this only picks a route
        return s.getsockname()[0]
    finally:
        s.close()


LAN = lan_address()
B = tempfile.mkdtemp(prefix="shoes-bench-")
atexit.register(lambda: shutil.rmtree(B, ignore_errors=True) if not os.environ.get("KEEP") else print("kept", B))


def keypair():
    out = subprocess.check_output(["sing-box", "generate", "wg-keypair"]).decode()
    d = dict(l.strip().split(": ") for l in out.splitlines() if ": " in l)
    return d["PrivateKey"], d["PublicKey"]


def write_configs():
    srv, shoes, sb = keypair(), keypair(), keypair()
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                    "-keyout", f"{B}/key.pem", "-out", f"{B}/cert.pem", "-days", "30", "-subj", "/CN=localhost",
                    "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"], check=True, capture_output=True)
    w = lambda name, text: open(f"{B}/{name}", "w").write(text)
    socks = lambda port, chain: f'''- address: "127.0.0.1:{port}"
  protocol:
    type: socks
  rules:
    - masks: "0.0.0.0/0"
      action: allow
{chain}
'''
    hy2 = lambda port, obfs="": f'''      client_chain:
        - address: "127.0.0.1:{port}"
          protocol:
            type: hysteria2
            password: "pw"
{obfs}          quic_settings:
            verify: false
            sni_hostname: "localhost"'''
    OB = '''            obfs:
              type: salamander
              password: "obfspw"
'''
    wg = lambda typ: f'''      client_chain:
        address: "127.0.0.1:25182"
        protocol:
          type: {typ}
          private_key: "{shoes[0]}"
          peer_public_key: "{srv[1]}"
          local_addresses:
            - "10.9.0.2/32"
          allowed_ips:
            - "0.0.0.0/0"
          mtu: 1408
'''
    w("shoes-client.yaml",
      socks(21080, "") + socks(21081, hy2(24431)) + socks(21082, hy2(24432)) + socks(21087, hy2(24433, OB)) + socks(21089, hy2(24434, OB)) + socks(21084, wg("wireguard")))
    srvblk = lambda port, obfs="": f'''- address: "127.0.0.1:{port}"
  transport: quic
  quic_settings:
    cert: {B}/cert.pem
    key: {B}/key.pem
    alpn_protocols:
      - h3
  protocol:
    type: hysteria2
    password: pw
{obfs}'''
    w("shoes-server.yaml", srvblk(24431) + srvblk(24433, "    obfs:\n      type: salamander\n      password: obfspw\n"))
    tls_s = {"enabled": True, "alpn": ["h3"], "certificate_path": f"{B}/cert.pem", "key_path": f"{B}/key.pem"}
    tls_c = {"enabled": True, "insecure": True, "server_name": "localhost", "alpn": ["h3"]}
    json.dump({"log": {"level": "warn"},
               "inbounds": [{"type": "hysteria2", "tag": "hy2-in", "listen": "127.0.0.1", "listen_port": 24432, "users": [{"password": "pw"}], "tls": tls_s},
                            {"type": "hysteria2", "tag": "hy2-obfs-in", "listen": "127.0.0.1", "listen_port": 24434, "users": [{"password": "pw"}], "tls": tls_s,
                             "obfs": {"type": "salamander", "password": "obfspw"}}],
               "endpoints": [{"type": "wireguard", "tag": "wg-srv", "system": False, "mtu": 1408, "address": ["10.9.0.1/24"], "private_key": srv[0], "listen_port": 25182,
                              "peers": [{"public_key": shoes[1], "allowed_ips": ["10.9.0.2/32"]}, {"public_key": sb[1], "allowed_ips": ["10.9.0.3/32"]}]}],
               "outbounds": [{"type": "direct", "tag": "direct"}], "route": {"final": "direct"}}, open(f"{B}/sb-server.json", "w"), indent=1)
    json.dump({"log": {"level": "warn"},
               "inbounds": [{"type": "socks", "tag": t, "listen": "127.0.0.1", "listen_port": p} for t, p in
                            (("s-direct", 21086), ("s-hy2", 21083), ("s-hy2-shoes", 21088), ("s-hy2-obfs-shoes", 21090), ("s-wg", 21085))],
               "endpoints": [{"type": "wireguard", "tag": "wg-cli", "system": False, "mtu": 1408, "address": ["10.9.0.3/32"], "private_key": sb[0],
                              "peers": [{"address": "127.0.0.1", "port": 25182, "public_key": srv[1], "allowed_ips": ["0.0.0.0/0"]}]}],
               "outbounds": [{"type": "direct", "tag": "direct"},
                             {"type": "hysteria2", "tag": "hy2", "server": "127.0.0.1", "server_port": 24432, "password": "pw", "tls": tls_c},
                             {"type": "hysteria2", "tag": "hy2-shoes", "server": "127.0.0.1", "server_port": 24431, "password": "pw", "tls": tls_c},
                             {"type": "hysteria2", "tag": "hy2-obfs-shoes", "server": "127.0.0.1", "server_port": 24433, "password": "pw", "tls": tls_c,
                              "obfs": {"type": "salamander", "password": "obfspw"}}],
               "route": {"rules": [{"inbound": "s-hy2", "outbound": "hy2"}, {"inbound": "s-hy2-shoes", "outbound": "hy2-shoes"}, {"inbound": "s-hy2-obfs-shoes", "outbound": "hy2-obfs-shoes"}, {"inbound": "s-wg", "outbound": "wg-cli"}], "final": "direct"}},
              open(f"{B}/sb-client.json", "w"), indent=1)


write_configs()
procs = {}
def start(name, cmd):
    procs[name] = subprocess.Popen(cmd, stdout=open(f"{B}/{name}.log", "w"), stderr=subprocess.STDOUT)
def cpu(name):
    pid = procs[name].pid
    if sys.platform == "linux":
        f = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
        return (int(f[11]) + int(f[12])) / os.sysconf("SC_CLK_TCK")
    out = subprocess.check_output(["ps", "-o", "cputime=", "-p", str(pid)]).decode().strip()
    m, s = out.split(":"); return int(m) * 60 + float(s)
def rss(name):
    return int(subprocess.check_output(["ps", "-o", "rss=", "-p", str(procs[name].pid)]).decode()) / 1024
def wait_port(p, t=10):
    end = time.time() + t
    while time.time() < end:
        s = socket.socket()
        if s.connect_ex(("127.0.0.1", p)) == 0: s.close(); return True
        s.close(); time.sleep(0.1)
    return False
start("sink", [sys.executable, f"{HERE}/load.py", "server", "--port", str(SINK)])
start("shoes_srv", [SHOES, "--no-reload", f"{B}/shoes-server.yaml"])
start("sb_srv", ["sing-box", "run", "-c", f"{B}/sb-server.json"])
time.sleep(1.5)
start("shoes_cli", [SHOES, "--no-reload"] + os.environ.get("SHOES_CLI_ARGS", "").split() + [f"{B}/shoes-client.yaml"])
start("sb_cli", ["sing-box", "run", "-c", f"{B}/sb-client.json"])
for p in (SINK, 21080, 21086): assert wait_port(p), p
time.sleep(1)
SECS = float(os.environ.get("SECS", "6"))
def run(label, socks, involved, mode, conns=1):
    if os.environ.get("NSTAT"): subprocess.run("nstat -n >/dev/null 2>&1", shell=True)
    before = {n: cpu(n) for n in involved}
    cmd = [sys.executable, f"{HERE}/load.py", "client", "--target", f"{LAN}:{SINK}", "--mode", mode, "--secs", str(SECS), "--conns", str(conns)]
    if socks: cmd += ["--socks", f"127.0.0.1:{socks}"]
    perfs = []
    if os.environ.get("PERF"):
        for n in involved:
            if n.startswith("shoes"):
                perfs.append((n, subprocess.Popen(f"perf record -F 1999 -g -p {procs[n].pid} -o /tmp/perf-{n}.data -- sleep {max(SECS - 1, 1)} >/dev/null 2>&1", shell=True)))
    try: out = subprocess.run(cmd, capture_output=True, text=True, timeout=SECS + 25).stdout.strip()
    except subprocess.TimeoutExpired: out = "TIMEOUT"
    for n, pf in perfs:
        pf.wait()
        rep = subprocess.run(f"perf report -i /tmp/perf-{n}.data {os.environ.get('PERF_REPORT', '--no-children')} --sort {os.environ.get('PERF_SORT', 'symbol')} --stdio -g none 2>/dev/null | grep -v '^#' | grep -v '^$' | {os.environ.get('PERF_GREP', 'cat')} | head -{os.environ.get('PERF_TOP', '14')}", shell=True, capture_output=True, text=True).stdout
        print(f"--- perf {n} ({label}, {mode})\n{rep}", flush=True)
    time.sleep(0.3)
    used = {n: cpu(n) - before[n] for n in involved}
    if os.environ.get("NSTAT"):
        o = subprocess.run("nstat -z UdpInDatagrams UdpOutDatagrams UdpRcvbufErrors UdpSndbufErrors UdpInErrors TcpRetransSegs 2>/dev/null | tail -n +2", shell=True, capture_output=True, text=True).stdout
        print("    " + " ".join(f"{l.split()[0]}={l.split()[1]}" for l in o.splitlines() if l.split()), flush=True)
    try:
        g = float(out); cpus = " ".join(f"{n}={used[n] / (g * SECS / 8):.2f}" for n in involved)  # cpu-seconds per GB
        print(f"{label:<34} {mode} x{conns:<2} {g:7.3f} Gbps   cpu-s/GB: {cpus}", flush=True)
    except ValueError:
        print(f"{label:<34} {mode} x{conns:<2} {out}", flush=True)
cases = [
 ("direct (no proxy)", None, []),
 ("shoes socks->direct", 21080, ["shoes_cli"]),
 ("singbox socks->direct", 21086, ["sb_cli"]),
 ("shoes hy2 -> shoes hy2", 21081, ["shoes_cli", "shoes_srv"]),
 ("shoes hy2+salamander -> shoes", 21087, ["shoes_cli", "shoes_srv"]),
 ("shoes hy2 -> singbox hy2", 21082, ["shoes_cli", "sb_srv"]),
 ("singbox hy2 -> shoes hy2", 21088, ["sb_cli", "shoes_srv"]),
 ("shoes hy2+salamander -> singbox", 21089, ["shoes_cli", "sb_srv"]),
 ("singbox hy2+salamander -> shoes", 21090, ["sb_cli", "shoes_srv"]),
 ("singbox hy2 -> singbox hy2", 21083, ["sb_cli", "sb_srv"]),
 ("shoes wg -> singbox wg", 21084, ["shoes_cli", "sb_srv"]),
 ("singbox wg -> singbox wg", 21085, ["sb_cli", "sb_srv"]),
]
only = os.environ.get("ONLY")
conns_list = [int(x) for x in os.environ.get("CONNS", "1").split(",")]
modes = os.environ.get("MODES", "U,D").split(",")
try:
    for label, socks, inv in cases:
        if only and only not in label: continue
        for c in conns_list:
            for mode in modes:
                run(label, socks, inv, mode, c)
    print("RSS MB: " + " ".join(f"{n}={rss(n):.0f}" for n in procs if n != "sink"))
finally:
    for p in procs.values(): p.kill()
    if os.environ.get("LOGS"):
        for n in procs:
            if n.startswith("shoes"):
                tail = open(f"{B}/{n}.log").read().splitlines()[-int(os.environ["LOGS"]):]
                print(f"--- {n} log\n" + "\n".join(tail), flush=True)
