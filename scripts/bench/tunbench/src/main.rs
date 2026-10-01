//! Drives shoes' TUN stack through a datagram socketpair, the way smoltcp's
//! examples/benchmark.rs drives a tap device. This side plays the host
//! kernel: a smoltcp interface at 10.0.0.2 opening TCP connections "out".
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address};
use std::os::unix::process::CommandExt;
use std::time::Duration;

struct Fd { fd: i32, mtu: usize, hdr: bool, sent: u64, recvd: u64, enobufs: u64 }
struct Rx(Vec<u8>);
struct Tx<'a>(&'a mut Fd);
impl RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R { f(&self.0) }
}
impl<'a> TxToken for Tx<'a> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let off = if self.0.hdr { 4 } else { 0 };
        let mut buf = vec![0u8; len + off];
        if off == 4 { buf[3] = 2; }
        let r = f(&mut buf[off..]);
        loop {
            let n = unsafe { libc::send(self.0.fd, buf.as_ptr() as *const _, buf.len(), 0) };
            if n >= 0 { self.0.sent += 1; break; }
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if e == libc::ENOBUFS || e == libc::EAGAIN { self.0.enobufs += 1; std::thread::yield_now(); continue; }
            break;
        }
        r
    }
}
impl Device for Fd {
    type RxToken<'a> = Rx; type TxToken<'a> = Tx<'a>;
    fn receive(&mut self, _t: Instant) -> Option<(Rx, Tx<'_>)> {
        let mut buf = vec![0u8; self.mtu + 4];
        let n = unsafe { libc::recv(self.fd, buf.as_mut_ptr() as *mut _, buf.len(), libc::MSG_DONTWAIT) };
        if n <= 0 { return None; }
        self.recvd += 1;
        let off = if self.hdr { 4 } else { 0 };
        buf.truncate(n as usize); buf.drain(..off);
        Some((Rx(buf), Tx(self)))
    }
    fn transmit(&mut self, _t: Instant) -> Option<Tx<'_>> { Some(Tx(self)) }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default(); c.medium = Medium::Ip; c.max_transmission_unit = self.mtu; c
    }
}
fn bufsz(fd: i32) {
    let v: libc::c_int = std::env::var("TUNBENCH_SOCKBUF").ok().and_then(|x| x.parse().ok()).unwrap_or(4 << 20);
    for opt in [libc::SO_SNDBUF, libc::SO_RCVBUF] {
        unsafe { libc::setsockopt(fd, libc::SOL_SOCKET, opt, &v as *const _ as *const _, 4); }
    }
}
fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 7 { eprintln!("usage: tunbench <shoes> <U|D|UDP> <secs> <ip> <port> <conns> [buf_kib] [extra-yaml]"); std::process::exit(2); }
    let (shoes, mode, secs, ip, port, conns) = (&a[1], a[2].as_str(), a[3].parse::<f64>().unwrap(), &a[4], a[5].parse::<u16>().unwrap(), a[6].parse::<usize>().unwrap());
    let buf_kib: usize = a.get(7).and_then(|s| s.parse().ok()).unwrap_or(1024);
    let extra = a.get(8).cloned().unwrap_or_default();
    let mut sv = [0i32; 2];
    assert_eq!(unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, sv.as_mut_ptr()) }, 0);
    bufsz(sv[0]); bufsz(sv[1]);
    let dir = std::env::temp_dir().join(format!("tunbench-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("tun.yaml");
    std::fs::write(&cfg, format!("- device_fd: 9\n  mtu: 1500\n  tcp_enabled: true\n  udp_enabled: true\n  icmp_enabled: true\n{extra}  rules:\n    - masks: \"0.0.0.0/0\"\n      action: allow\n      client_chain:\n        - protocol:\n            type: direct\n")).unwrap();
    let child_fd = sv[1];
    let mut cmd = std::process::Command::new(shoes);
    cmd.arg("--no-reload").arg(&cfg).stdout(std::process::Stdio::null());
    unsafe { cmd.pre_exec(move || { if libc::dup2(child_fd, 9) < 0 { return Err(std::io::Error::last_os_error()); } Ok(()) }); }
    let mut child = cmd.spawn().unwrap();
    unsafe { libc::close(sv[1]); }
    std::thread::sleep(Duration::from_millis(500));

    let mut dev = Fd { fd: sv[0], mtu: 1500, hdr: cfg!(target_os = "macos"), sent: 0, recvd: 0, enobufs: 0 };
    let start = std::time::Instant::now();
    let now = || Instant::from_micros(start.elapsed().as_micros() as i64);
    let mut iface = Interface::new(Config::new(HardwareAddress::Ip), &mut dev, now());
    iface.update_ip_addrs(|x| { x.push(IpCidr::new(IpAddress::v4(10, 0, 0, 2), 24)).unwrap(); });
    iface.routes_mut().add_default_ipv4_route(Ipv4Address::new(10, 0, 0, 1)).unwrap();
    let mut sockets = SocketSet::new(vec![]);
    let dst: IpAddress = ip.parse::<std::net::Ipv4Addr>().unwrap().into();
    let mut total: u64 = 0;
    let mut t_meas: Option<std::time::Instant> = None;
    let chunk = vec![0u8; 1 << 16];

    if mode == "UDP" {
        // conns = payload size here; send as fast as the echo comes back within a window of 256 in flight
        let size = conns.max(16);
        let mk = || udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 2048], vec![0u8; 4 << 20]);
        let h = sockets.add(udp::Socket::new(mk(), mk()));
        sockets.get_mut::<udp::Socket>(h).bind(40000).unwrap();
        let ep = IpEndpoint::new(dst, port);
        let (mut tx, mut rx) = (0u64, 0u64);
        let payload = vec![7u8; size];
        let t0 = std::time::Instant::now();
        while t0.elapsed().as_secs_f64() < secs {
            iface.poll(now(), &mut dev, &mut sockets);
            let s = sockets.get_mut::<udp::Socket>(h);
            while s.can_recv() { let _ = s.recv().map(|_| rx += 1); }
            while tx - rx < 256 && s.can_send() { if s.send_slice(&payload, ep).is_err() { break; } tx += 1; }
            if tx - rx >= 256 {
                let mut p = libc::pollfd { fd: dev.fd, events: libc::POLLIN, revents: 0 };
                unsafe { libc::poll(&mut p, 1, 1); }
                // a lost datagram would stall the window; forgive it after the 1 ms wait
                if p.revents == 0 { tx = rx + 128; }
            }
        }
        let el = t0.elapsed().as_secs_f64();
        println!("udp_echo size={size} sent_pps={:.0} echoed_pps={:.0} echoed_mbps={:.1} loss={:.2}%", tx as f64 / el, rx as f64 / el, rx as f64 * size as f64 * 8.0 / el / 1e6, 100.0 * (1.0 - rx as f64 / tx.max(1) as f64));
    } else {
        let mut hs = vec![];
        let idle: usize = std::env::var("TUNBENCH_IDLE").ok().and_then(|x| x.parse().ok()).unwrap_or(0);
        let mut idle_hs = vec![];
        for i in 0..idle {
            let mut s = tcp::Socket::new(tcp::SocketBuffer::new(vec![0u8; 4096]), tcp::SocketBuffer::new(vec![0u8; 4096]));
            s.connect(iface.context(), (dst, port), 20000 + i as u16).unwrap();
            idle_hs.push((sockets.add(s), false));
        }
        for i in 0..conns {
            let mut s = tcp::Socket::new(tcp::SocketBuffer::new(vec![0u8; buf_kib << 10]), tcp::SocketBuffer::new(vec![0u8; buf_kib << 10]));
            s.set_congestion_control(tcp::CongestionControl::Cubic);
            s.connect(iface.context(), (dst, port), 41000 + i as u16).unwrap();
            hs.push((sockets.add(s), false));
        }
        loop {
            iface.poll(now(), &mut dev, &mut sockets);
            let mut all_up = true;
            for (h, greeted) in idle_hs.iter_mut() {
                let s = sockets.get_mut::<tcp::Socket>(*h);
                if !s.may_send() { all_up = false; continue; }
                if !*greeted { s.send_slice(b"P").unwrap(); *greeted = true; }
            }
            for (h, greeted) in hs.iter_mut() {
                let s = sockets.get_mut::<tcp::Socket>(*h);
                if !s.may_send() { all_up = false; continue; }
                if !*greeted { s.send_slice(mode.as_bytes()).unwrap(); *greeted = true; }
                if mode == "U" {
                    while s.can_send() { let n = s.send_slice(&chunk).unwrap(); if n == 0 { break; } if t_meas.is_some() { total += n as u64; } }
                } else {
                    while s.can_recv() { let n = s.recv(|b| (b.len(), b.len())).unwrap(); if n == 0 { break; } if t_meas.is_some() { total += n as u64; } }
                }
            }
            if all_up && t_meas.is_none() { t_meas = Some(std::time::Instant::now()); }
            if let Some(t) = t_meas { if t.elapsed().as_secs_f64() >= secs { break; } }
            else if start.elapsed().as_secs() > 10 { eprintln!("connect timeout"); break; }
            let d = iface.poll_delay(now(), &sockets).map(|d| d.total_millis() as i32).unwrap_or(50).min(50);
            if d > 0 {
                let mut p = libc::pollfd { fd: dev.fd, events: libc::POLLIN, revents: 0 };
                unsafe { libc::poll(&mut p, 1, d); }
            }
        }
        let el = t_meas.map(|t| t.elapsed().as_secs_f64()).unwrap_or(1.0);
        println!("{:.3} Gbps  (pkts tx={} rx={} enobufs={})", total as f64 * 8.0 / el / 1e9, dev.sent, dev.recvd, dev.enobufs);
    }
    // child CPU
    let out = std::process::Command::new("ps").args(["-o", "cputime=", "-p", &child.id().to_string()]).output().unwrap();
    println!("shoes_cpu={}", String::from_utf8_lossy(&out.stdout).trim());
    let _ = child.kill(); let _ = child.wait();
    let _ = std::fs::remove_dir_all(dir);
}
