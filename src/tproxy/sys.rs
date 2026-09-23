//! The Linux socket calls behind transparent proxying. Everything here is
//! `cfg(target_os = "linux")`; the module exists elsewhere so the paths
//! resolve, and the inbounds are refused at validation there.
//!
//! The option numbers come from `libc`, which mirrors
//! `include/uapi/linux/netfilter_ipv4.h` (`SO_ORIGINAL_DST`) and
//! `include/uapi/linux/netfilter_ipv6/ip6_tables.h` (`IP6T_SO_ORIGINAL_DST`).

#[cfg(target_os = "linux")]
mod linux {
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

        #[test]
        fn a_descriptor_that_is_not_a_socket_has_no_original_destination() {
            assert_eq!(original_destination(-1), None);
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::*;
