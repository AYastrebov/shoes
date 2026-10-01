#!/usr/bin/env python3
"""Real TUN benchmark on Linux, the shape of smoltcp's examples/benchmark.rs.

Kernel TCP in a network namespace `cli` -> tun0 -> shoes (main namespace,
holding the descriptor through `device_fd`) -> direct -> a local sink. Needs
root and /dev/net/tun; run-linux.sh runs it in a privileged container.

Environment:
  SHOES   path to the shoes binary (default: /target/release/shoes)
  SECS    seconds per run          (default: 5)
  CASES   base,defaultmtu,mtu,buf,idle,conns,udp
  NCONNS  connection counts for the `conns` case, e.g. 2,4,8
  STATS   print tun0 and TCP counters after each case
  PERF    record and print a perf profile of shoes for each run
"""
import os, fcntl, struct, subprocess, sys, time, socket, re, ctypes
_libc = ctypes.CDLL(None, use_errno=True)
def setns(fd):
    assert _libc.setns(fd, 0x40000000) == 0, os.strerror(ctypes.get_errno())
B = os.path.dirname(os.path.abspath(__file__)); SHOES = os.environ.get("SHOES", "/target/release/shoes")
sh = lambda c, **k: subprocess.run(c, shell=True, check=True, **k)
IP = subprocess.check_output("hostname -i", shell=True).decode().split()[0]
SECS = float(os.environ.get("SECS", "5"))
def cpu(pid):
    f = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
    return (int(f[11]) + int(f[12])) / os.sysconf("SC_CLK_TCK")
def setup(mtu, extra=""):
    subprocess.run("ip netns del cli 2>/dev/null", shell=True)
    sh("ip netns add cli")
    orig = os.open("/proc/self/ns/net", os.O_RDONLY); ns = os.open("/var/run/netns/cli", os.O_RDONLY)
    setns(ns)
    tun = os.open("/dev/net/tun", os.O_RDWR)
    fcntl.ioctl(tun, 0x400454ca, struct.pack("16sH", b"tun0", 0x0001 | 0x1000))
    setns(orig)
    sh(f"ip netns exec cli sh -c 'ip link set lo up; ip addr add 10.0.0.2/24 dev tun0; ip link set tun0 mtu {mtu} up; ip route add default dev tun0'")
    cfg = f"/tmp/tun-{mtu}.yaml"
    mtu_line = "" if os.environ.get("OMIT_MTU") else f"  mtu: {mtu}\n"
    open(cfg, "w").write(f"- device_fd: {tun}\n{mtu_line}  tcp_enabled: true\n  udp_enabled: true\n  icmp_enabled: true\n{extra}  rules:\n    - masks: \"0.0.0.0/0\"\n      action: allow\n      client_chain:\n        - protocol:\n            type: direct\n")
    p = subprocess.Popen([SHOES, "--no-reload", cfg], pass_fds=[tun], stdout=open("/tmp/shoes-tun.log", "w"), stderr=subprocess.STDOUT)
    os.close(tun); time.sleep(1.0); return p
def load(mode, conns=1):
    out = subprocess.run(f"ip netns exec cli python3 {B}/load.py client --target {IP}:25201 --mode {mode} --secs {SECS} --conns {conns}", shell=True, capture_output=True, text=True, timeout=SECS + 30)
    return out.stdout.strip() or out.stderr.strip()[-200:]
def idle_conns(n):
    code = f"import socket,time\ns=[socket.create_connection(('{IP}',25201)) for _ in range({n})]\n[x.sendall(b'P') for x in s]\nprint('ok',flush=True)\ntime.sleep(600)"
    p = subprocess.Popen(["ip", "netns", "exec", "cli", "python3", "-c", code], stdout=subprocess.PIPE, text=True)
    p.stdout.readline(); return p
def case(label, mtu, extra="", conns=1, idle=0, modes=("U", "D")):
    p = setup(mtu, extra); ih = idle_conns(idle) if idle else None
    for m in modes:
        pf = subprocess.Popen(f"perf record -F 1999 -g -p {p.pid} -o /tmp/perf-{m}.data -- sleep {SECS - 1} >/dev/null 2>&1", shell=True) if os.environ.get("PERF") else None
        c0 = cpu(p.pid); g = load(m, conns)
        if pf:
            pf.wait()
            o = subprocess.run(f"perf report -i /tmp/perf-{m}.data --no-children --sort symbol --stdio -g none 2>/dev/null | grep -v '^#' | grep -v '^$' | head -28", shell=True, capture_output=True, text=True).stdout
            print(o[:2600], flush=True)
        try: gg = float(g); print(f"{label:<44} {m} x{conns:<2} {gg:7.3f} Gbps  shoes cpu-s/GB={(cpu(p.pid) - c0) / (gg * SECS / 8):.2f}", flush=True)
        except ValueError: print(f"{label:<44} {m} x{conns:<2} {g}", flush=True)
    if ih: ih.kill()
    if os.environ.get("STATS"):
        o = subprocess.run("ip netns exec cli ip -s link show tun0; ip netns exec cli nstat -az TcpRetransSegs TcpExtTCPLostRetransmit TcpExtTCPSACKReorder TcpExtTCPOFOQueue TcpInSegs TcpExtTCPBacklogDrop TcpExtTCPRcvQDrop; awk '{d+=strtonum(\"0x\"$2)} END{print \"softnet_dropped\", d}' /proc/net/softnet_stat", shell=True, capture_output=True, text=True).stdout
        print("   " + "\n   ".join(l for l in o.splitlines() if any(k in l for k in ("RX", "TX", "Tcp", "softnet")) or l.strip()[:1].isdigit()), flush=True)
    return p
def udp(p, label, rate, size=1200):
    for rev in ("", "-R"):
        c0 = cpu(p.pid)
        o = subprocess.run(f"ip netns exec cli iperf3 -c {IP} -p 25301 -u -b {rate} -l {size} -t 4 {rev}", shell=True, capture_output=True, text=True).stdout
        m = re.search(r"([\d.]+ [MGK]bits/sec)\s+[\d.]+ ms\s+(\d+/\d+ \([\d.e+-]+%\))\s+receiver", o)
        print(f"{label:<44} udp {rate} {'down' if rev else 'up  '} -> {m.group(1) + '  lost ' + m.group(2) if m else o[-300:]}  shoes cpu={cpu(p.pid) - c0:.2f}s", flush=True)
sink = subprocess.Popen([sys.executable, f"{B}/load.py", "server", "--port", "25201"])
ip3 = subprocess.Popen(["iperf3", "-s", "-p", "25301"], stdout=subprocess.DEVNULL)
time.sleep(0.5)
which = os.environ.get("CASES", "base,mtu,buf,idle,conns,udp").split(",")
try:
    if "base" in which:
        o = subprocess.run(f"python3 {B}/load.py client --target {IP}:25201 --mode U --secs 3", shell=True, capture_output=True, text=True).stdout.strip()
        print(f"{'kernel loopback, no TUN (ceiling of the tool)':<44} U x1  {o} Gbps", flush=True)
        case("tun mtu 1500, default buffers", 1500).kill()
    if "defaultmtu" in which:
        # No `mtu` in the config, on a device set to Linux's default of 9000:
        # the stack has to have picked 9000 itself for this to carry anything.
        os.environ["OMIT_MTU"] = "1"
        case("tun, mtu left to the default (device 9000)", 9000).kill()
        del os.environ["OMIT_MTU"]
    if "mtu" in which:
        case("tun mtu 9000, default buffers", 9000).kill()
        case("tun mtu 65535, tcp_buffer 1 MiB", 65535, "  tcp_buffer_size: 1048576\n").kill()
    if "buf" in which:
        case("tun mtu 1500, tcp_buffer 1 MiB", 1500, "  tcp_buffer_size: 1048576\n").kill()
    if "conns" in which:
        for n in [int(x) for x in os.environ.get("NCONNS", "2,4,8").split(",")]:
            case(f"tun mtu 1500, {n} connections", 1500, conns=n, modes=("D",)).kill()
        case("tun mtu 1500, 8 conns, tcp_buffer 1 MiB", 1500, "  tcp_buffer_size: 1048576\n", conns=8, modes=("D",)).kill()
    if "idle" in which:
        for n in [int(x) for x in os.environ.get("NIDLE", "100,500").split(",")]:
            case(f"tun mtu 1500, {n} idle connections", 1500, idle=n).kill()
    if "udp" in which:
        p = setup(1500)
        for r in ("100M", "1G", "0"): udp(p, "tun mtu 1500", r)
        p.kill()
finally:
    sink.kill(); ip3.kill()
    print(open("/tmp/shoes-tun.log").read()[-600:])
