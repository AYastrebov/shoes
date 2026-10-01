#!/usr/bin/env python3
"""Loopback load tool. `server` is a sink and a source; `client` opens N
connections, through a SOCKS5 proxy or directly, and reports Gbit/s.

Modes, chosen by the first byte the client sends:
  U  upload: the client sends, the server discards
  D  download: the server sends, the client discards
  S  upload to a slow destination (the server reads about 10 Mbit/s), which
     is what backs a relay up into its tunnel's flow control
  E  echo: SECS megabytes of random data in uneven writes go out and must
     come back identical; reports intact or CORRUPT
  P  ping-pong: one byte each way, reports round-trip p50 and p99
"""
import socket, sys, time, struct, threading, multiprocessing as mp, argparse
CH = 1 << 18
def serve(port):
    # One socket for both families.
    ls = socket.socket(socket.AF_INET6); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    ls.bind(("::", port)); ls.listen(256)
    def h(c):
        try:
            c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            m = c.recv(1)
            if m == b"U":
                buf = bytearray(CH)
                while c.recv_into(buf): pass
            elif m == b"S":   # a slow destination: about 10 Mbit/s
                buf = bytearray(1 << 16)
                while c.recv_into(buf): time.sleep(0.05)
            elif m == b"D":
                data = bytes(CH)
                while True: c.sendall(data)
            elif m == b"E":   # echo everything back
                buf = bytearray(CH)
                while True:
                    k = c.recv_into(buf)
                    if not k: break
                    c.sendall(memoryview(buf)[:k])
            elif m == b"P":   # ping-pong latency: echo 1 byte
                while True:
                    b = c.recv(1)
                    if not b: break
                    c.sendall(b)
        except OSError: pass
        finally: c.close()
    while True:
        c, _ = ls.accept(); threading.Thread(target=h, args=(c,), daemon=True).start()
def recvn(s, n):
    b = b""
    while len(b) < n:
        d = s.recv(n - len(b))
        if not d: raise OSError("eof")
        b += d
    return b
def connect(socks, target):
    th, tp = target
    if socks is None:
        s = socket.create_connection((th, tp)); return s
    s = socket.create_connection(socks)
    s.sendall(b"\x05\x01\x00"); assert recvn(s, 2) == b"\x05\x00"
    s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(th) + struct.pack(">H", tp))
    r = recvn(s, 4); assert r[1] == 0, f"socks reply {r[1]}"
    recvn(s, {1: 6, 4: 18}[r[3]])
    return s
def worker(socks, target, mode, secs, q):
    try:
        s = connect(socks, target); s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.sendall(mode.encode()); n = 0; t0 = time.time(); end = t0 + secs
        if mode in ("U", "S"):
            data = bytes(CH)
            while time.time() < end: n += s.send(data)
        elif mode == "D":
            buf = bytearray(CH)
            while time.time() < end:
                k = s.recv_into(buf)
                if not k: break
                n += k
        elif mode == "E":
            # Integrity: a stream nothing can guess goes out, comes back, and
            # has to be the same stream. Sizes vary so segments are not all
            # full ones.
            import hashlib, os as _os, random
            total = int(secs * (1 << 20)); sent = hashlib.sha256(); got = hashlib.sha256()
            def reader():
                left = total; buf = bytearray(CH)
                while left:
                    k = s.recv_into(buf, min(left, CH))
                    if not k: break
                    got.update(memoryview(buf)[:k]); left -= k
            t = threading.Thread(target=reader); t.start()
            left = total; rng = random.Random(1)
            while left:
                chunk = _os.urandom(min(left, rng.choice((1, 100, 1400, 9000, 65536, 200000))))
                sent.update(chunk); s.sendall(chunk); left -= len(chunk)
            t.join()
            ok = sent.digest() == got.digest()
            q.put(("V", total if ok else -1, time.time() - t0, 0)); s.close(); return
        elif mode == "P":
            lat = []
            while time.time() < end:
                a = time.perf_counter(); s.sendall(b"x"); recvn(s, 1); lat.append(time.perf_counter() - a)
            lat.sort(); q.put(("P", len(lat), lat[len(lat)//2], lat[int(len(lat)*0.99)])); return
        q.put((mode, n, time.time() - t0, 0)); s.close()
    except Exception as e:
        q.put(("E", repr(e), 0, 0))
if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("role"); ap.add_argument("--port", type=int)
    ap.add_argument("--socks"); ap.add_argument("--target"); ap.add_argument("--mode", default="U")
    ap.add_argument("--secs", type=float, default=8); ap.add_argument("--conns", type=int, default=1)
    a = ap.parse_args()
    if a.role == "server": serve(a.port)
    else:
        socks = None
        if a.socks: h, p = a.socks.split(":"); socks = (h, int(p))
        h, p = a.target.rsplit(":", 1); h = h.strip("[]"); q = mp.Queue()
        ps = [mp.Process(target=worker, args=(socks, (h, int(p)), a.mode, a.secs, q)) for _ in range(a.conns)]
        for p_ in ps: p_.start()
        res = [q.get() for _ in ps]
        for p_ in ps: p_.join()
        errs = [r for r in res if r[0] == "E"]
        if errs: print("ERROR", errs[0][1]); sys.exit(1)
        if a.mode == "E":
            bad = [r for r in res if r[1] < 0]
            print("CORRUPT" if bad else f"intact ({sum(r[1] for r in res) >> 20} MiB echoed)")
        elif a.mode == "P":
            print(f"rtt_p50_us={res[0][2]*1e6:.0f} rtt_p99_us={res[0][3]*1e6:.0f} n={res[0][1]}")
        else:
            gbps = sum(r[1] * 8 / r[2] for r in res) / 1e9
            print(f"{gbps:.3f}")
