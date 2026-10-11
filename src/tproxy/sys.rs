//! The Linux socket calls behind transparent proxying. Everything here is
//! `cfg(target_os = "linux")`; the module exists elsewhere so the paths
//! resolve, and the inbounds are refused at validation there.
//!
//! The option numbers come from `libc`, which mirrors
//! `include/uapi/linux/netfilter_ipv4.h` (`SO_ORIGINAL_DST`),
//! `include/uapi/linux/netfilter_ipv6/ip6_tables.h` (`IP6T_SO_ORIGINAL_DST`),
//! `include/uapi/linux/in.h` (`IP_TRANSPARENT` 19, `IP_ORIGDSTADDR` 20) and
//! `include/uapi/linux/in6.h` (`IPV6_ORIGDSTADDR` 74, `IPV6_TRANSPARENT` 75).
//! The last four are `SOL_IP`/`SOL_IPV6` options, which unlike `SOL_SOCKET`
//! ones have the same numbers on MIPS.

#[cfg(target_os = "linux")]
mod linux {
    use std::mem::MaybeUninit;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
    use std::os::fd::RawFd;

    fn v4(sa: &libc::sockaddr_in) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr)),
            u16::from_be(sa.sin_port),
        ))
    }

    fn v6(sa: &libc::sockaddr_in6) -> SocketAddr {
        SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::from(sa.sin6_addr.s6_addr),
            u16::from_be(sa.sin6_port),
            sa.sin6_flowinfo,
            sa.sin6_scope_id,
        ))
    }

    /// `SO_ORIGINAL_DST`: where a connection was going before NAT `REDIRECT`
    /// sent it to this socket. `None` when conntrack has no entry for the
    /// connection (`ENOENT`) or the option is not supported.
    ///
    /// `Some` does not mean redirected. Wherever conntrack is loaded it
    /// tracks ordinary connections too, and for those the answer is simply
    /// the address the client dialled, which is the socket's own. The caller
    /// that knows the local address makes that comparison: see
    /// `AsyncStream for TcpStream`.
    ///
    /// The IPv6 option is asked first. An IPv4 connection accepted on a
    /// dual-stack listener is an `AF_INET6` socket, and for it the IPv6
    /// option fails and the IPv4 one answers.
    pub fn original_destination(fd: RawFd) -> Option<SocketAddr> {
        // SAFETY: both structs are plain data the kernel fills in. `len`
        // tells it how much room there is, and the family check rejects an
        // answer that is not the struct it was read into.
        unsafe {
            let mut sa6: libc::sockaddr_in6 = std::mem::zeroed();
            let mut len = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
            if libc::getsockopt(
                fd,
                libc::SOL_IPV6,
                libc::IP6T_SO_ORIGINAL_DST,
                &mut sa6 as *mut _ as *mut libc::c_void,
                &mut len,
            ) == 0
                && sa6.sin6_family as libc::c_int == libc::AF_INET6
            {
                return Some(v6(&sa6));
            }

            let mut sa4: libc::sockaddr_in = std::mem::zeroed();
            let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            if libc::getsockopt(
                fd,
                libc::SOL_IP,
                libc::SO_ORIGINAL_DST,
                &mut sa4 as *mut _ as *mut libc::c_void,
                &mut len,
            ) == 0
                && sa4.sin_family as libc::c_int == libc::AF_INET
            {
                return Some(v4(&sa4));
            }
        }
        None
    }

    fn setsockopt_on(fd: RawFd, level: libc::c_int, name: libc::c_int) -> std::io::Result<()> {
        let value: libc::c_int = 1;
        // SAFETY: `value` outlives the call and the length is its size.
        let rc = unsafe {
            libc::setsockopt(
                fd,
                level,
                name,
                &value as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    /// `IP_TRANSPARENT`: the socket may receive datagrams the policy route
    /// delivered for other addresses, and bind an address that is not the
    /// host's. Needs `CAP_NET_ADMIN`, and the error says so: a listener
    /// without it would otherwise be refused with a bare `EPERM`.
    pub fn make_transparent(fd: RawFd, ipv6: bool) -> std::io::Result<()> {
        let (level, name, option) = if ipv6 {
            (libc::SOL_IPV6, libc::IPV6_TRANSPARENT, "IPV6_TRANSPARENT")
        } else {
            (libc::SOL_IP, libc::IP_TRANSPARENT, "IP_TRANSPARENT")
        };
        setsockopt_on(fd, level, name).map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!("{option}: {e} (this needs CAP_NET_ADMIN)"),
            )
        })
    }

    /// `IP_RECVORIGDSTADDR`: each `recvmsg` reports where the datagram was
    /// going. Needs no capability; only `IP_TRANSPARENT` does.
    pub fn receive_original_destination(fd: RawFd, ipv6: bool) -> std::io::Result<()> {
        if ipv6 {
            setsockopt_on(fd, libc::SOL_IPV6, libc::IPV6_RECVORIGDSTADDR)
        } else {
            setsockopt_on(fd, libc::SOL_IP, libc::IP_RECVORIGDSTADDR)
        }
    }

    /// One datagram into `buf`: its length, its source, and its original
    /// destination, which is `None` when the socket was not asked for it.
    ///
    /// A datagram larger than `buf` is an error, not a prefix: a cut
    /// datagram forwarded as if whole is worse than a dropped one.
    pub fn recv_with_original_destination(
        fd: RawFd,
        buf: &mut [MaybeUninit<u8>],
    ) -> std::io::Result<(usize, SocketAddr, Option<SocketAddr>)> {
        // SAFETY: every pointer in `msg` refers to a local, or to `buf`, that
        // outlives the call, with its true length; the kernel only writes
        // through them, so `buf` being uninitialised is fine. The control
        // buffer is u64-aligned, as `cmsghdr` requires. A control message's
        // payload is read with `read_unaligned`, because `CMSG_DATA` promises
        // no alignment for a `sockaddr_in6` and on MIPS an unaligned load
        // traps. Each payload is read only after its level and type say what
        // it holds.
        unsafe {
            let mut source: libc::sockaddr_storage = std::mem::zeroed();
            let mut iov = libc::iovec {
                iov_base: buf.as_mut_ptr() as *mut libc::c_void,
                iov_len: buf.len(),
            };
            let mut control = [0u64; 16];
            let mut msg: libc::msghdr = std::mem::zeroed();
            msg.msg_name = &mut source as *mut _ as *mut libc::c_void;
            msg.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
            msg.msg_controllen = std::mem::size_of_val(&control) as _;

            let n = libc::recvmsg(fd, &mut msg, 0);
            if n < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if msg.msg_flags & libc::MSG_TRUNC != 0 {
                return Err(std::io::Error::other(
                    "datagram larger than the receive buffer; dropped",
                ));
            }

            let source = match source.ss_family as libc::c_int {
                libc::AF_INET => v4(&*(&source as *const _ as *const libc::sockaddr_in)),
                libc::AF_INET6 => v6(&*(&source as *const _ as *const libc::sockaddr_in6)),
                family => {
                    return Err(std::io::Error::other(format!(
                        "datagram from address family {family}"
                    )));
                }
            };

            let mut destination = None;
            let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
            while !cmsg.is_null() {
                let hdr = std::ptr::read_unaligned(cmsg);
                let data = libc::CMSG_DATA(cmsg);
                if hdr.cmsg_level == libc::SOL_IP && hdr.cmsg_type == libc::IP_ORIGDSTADDR {
                    let sa = std::ptr::read_unaligned(data as *const libc::sockaddr_in);
                    destination = Some(v4(&sa));
                } else if hdr.cmsg_level == libc::SOL_IPV6
                    && hdr.cmsg_type == libc::IPV6_ORIGDSTADDR
                {
                    let sa = std::ptr::read_unaligned(data as *const libc::sockaddr_in6);
                    destination = Some(v6(&sa));
                }
                cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
            }
            Ok((n as usize, source, destination))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// The conversions are where a byte-order mistake would hide: the
        /// kernel hands back network order, and a swapped port still looks
        /// like a port.
        #[test]
        fn kernel_sockaddrs_convert_out_of_network_byte_order() {
            // SAFETY: plain data, zero is a valid value for every field.
            let mut sa4: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            sa4.sin_family = libc::AF_INET as libc::sa_family_t;
            sa4.sin_port = 443u16.to_be();
            sa4.sin_addr.s_addr = u32::from(Ipv4Addr::new(93, 184, 216, 34)).to_be();
            assert_eq!(v4(&sa4), "93.184.216.34:443".parse().unwrap());

            // SAFETY: as above.
            let mut sa6: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
            sa6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sa6.sin6_port = 8443u16.to_be();
            sa6.sin6_addr.s6_addr = "2001:db8::1".parse::<Ipv6Addr>().unwrap().octets();
            assert_eq!(v6(&sa6), "[2001:db8::1]:8443".parse().unwrap());
        }

        /// A receiver with `IP_RECVORIGDSTADDR` and no `IP_TRANSPARENT`:
        /// needs no capability, and reports its own address as the original
        /// destination, which is enough to prove the control-message walk.
        fn receiver(bind: &str) -> (std::net::UdpSocket, SocketAddr) {
            use std::os::fd::AsRawFd;
            let socket = std::net::UdpSocket::bind(bind).unwrap();
            let addr = socket.local_addr().unwrap();
            receive_original_destination(socket.as_raw_fd(), addr.is_ipv6()).unwrap();
            (socket, addr)
        }

        fn uninit(len: usize) -> Vec<std::mem::MaybeUninit<u8>> {
            vec![std::mem::MaybeUninit::uninit(); len]
        }

        #[test]
        fn a_datagram_arrives_with_its_source_and_original_destination() {
            use std::os::fd::AsRawFd;
            for bind in ["127.0.0.1:0", "[::1]:0"] {
                let (receiver, receiver_addr) = receiver(bind);
                let sender = std::net::UdpSocket::bind(bind).unwrap();
                sender.send_to(b"query", receiver_addr).unwrap();

                let mut buf = uninit(64);
                let (n, source, destination) =
                    recv_with_original_destination(receiver.as_raw_fd(), &mut buf).unwrap();
                assert_eq!(n, 5, "{bind}");
                // SAFETY: the kernel initialised the first `n` bytes.
                let payload: Vec<u8> = buf[..n]
                    .iter()
                    .map(|b| unsafe { b.assume_init() })
                    .collect();
                assert_eq!(payload, b"query", "{bind}");
                assert_eq!(source, sender.local_addr().unwrap(), "{bind}");
                assert_eq!(destination, Some(receiver_addr), "{bind}");
            }
        }

        /// Reject rather than truncate: a cut datagram forwarded as whole is
        /// worse than a dropped one.
        #[test]
        fn a_datagram_larger_than_the_buffer_is_an_error_not_a_prefix() {
            use std::os::fd::AsRawFd;
            let (receiver, receiver_addr) = receiver("127.0.0.1:0");
            let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            sender.send_to(&[7u8; 100], receiver_addr).unwrap();
            let mut buf = uninit(10);
            assert!(recv_with_original_destination(receiver.as_raw_fd(), &mut buf).is_err());
        }

        /// Without the option the kernel attaches no destination, and the
        /// caller must be told so rather than handed a guess.
        #[test]
        fn without_the_option_there_is_no_original_destination() {
            use std::os::fd::AsRawFd;
            let receiver = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            sender
                .send_to(b"x", receiver.local_addr().unwrap())
                .unwrap();
            let mut buf = uninit(64);
            let (_, _, destination) =
                recv_with_original_destination(receiver.as_raw_fd(), &mut buf).unwrap();
            assert_eq!(destination, None);
        }

        #[test]
        fn a_descriptor_that_is_not_a_socket_has_no_original_destination() {
            assert_eq!(original_destination(-1), None);
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::*;
