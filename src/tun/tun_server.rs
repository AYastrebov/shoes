//! TUN server configuration and device creation.
//!
//! # Platform-Specific Usage
//!
//! ## Linux
//! On Linux, you can create a TUN device by specifying the device name and address:
//! ```ignore
//! let config = TunServerConfig::new()
//!     .tun_name("tun0")
//!     .address("10.0.0.1".parse().unwrap())
//!     .netmask("255.255.255.0".parse().unwrap());
//! ```
//!
//! ## Android
//! On Android, you must provide the FD from `VpnService.Builder.establish()`:
//! ```ignore
//! // In Kotlin/Java:
//! // val fd = vpnService.builder.establish()?.detachFd() ?: return
//!
//! let config = TunServerConfig::new()
//!     .raw_fd(fd)
//!     .mtu(1500);
//! ```
//!
//! ## iOS
//! On iOS, you must provide the FD from `NEPacketTunnelProvider`:
//! ```ignore
//! // In Swift/Objective-C:
//! // let fd = packetFlow.value(forKeyPath: "socket.fileDescriptor") as! Int32
//!
//! let config = TunServerConfig::new()
//!     .raw_fd(fd)
//!     .packet_information(true)  // Set based on how you obtained the FD
//!     .mtu(1500);
//! ```

use std::net::IpAddr;

#[cfg(unix)]
use log::info;
#[cfg(unix)]
use tun::{Configuration as TunConfiguration, Device};

/// Configuration for the TUN server.
///
/// This struct supports all platforms (Linux, Android, iOS) with platform-specific
/// options. See module-level documentation for usage examples.
#[derive(Clone, Debug)]
pub struct TunServerConfig {
    /// MTU size for the TUN interface.
    /// Default: platform-specific (iOS: 4064, Android: 9000, others: 1500)
    pub mtu: u16,
    /// Enable TCP connection handling.
    /// Default: true
    pub tcp_enabled: bool,
    /// Enable UDP packet handling.
    /// Default: true
    pub udp_enabled: bool,
    /// Enable ICMP (ping) handling.
    /// Default: true
    pub icmp_enabled: bool,
    /// TUN device name.
    /// - **Linux**: Used to name the TUN device (e.g., "tun0")
    /// - **macOS**: Must be `utunN`; omit it to let the kernel pick the next
    ///   free unit, which is what the daemon does to avoid racing another
    ///   utun user
    /// - **Android/iOS**: Ignored (device is provided via FD)
    pub tun_name: Option<String>,
    /// TUN device address.
    /// - **Linux**: Sets the device's IP address
    /// - **macOS**: Sets it, and is required together with `netmask` and
    ///   `destination` -- the three are applied as one point-to-point alias
    /// - **Android/iOS**: Informational only (address is set by VPN service)
    pub address: Option<IpAddr>,
    /// TUN device netmask.
    /// - **Linux**: Sets the device's netmask
    /// - **macOS**: Required; see `address`
    /// - **Android/iOS**: Informational only
    pub netmask: Option<IpAddr>,
    /// TUN device destination/gateway.
    /// - **Linux**: Sets the device's destination address
    /// - **macOS**: Required; see `address`
    /// - **Android/iOS**: Not used
    pub destination: Option<IpAddr>,
    /// Raw file descriptor for the TUN device.
    /// - **Linux**: Optional (if not set, creates a new TUN device)
    /// - **Android**: Required (from `VpnService.Builder.establish()`)
    /// - **iOS**: Required (from `NEPacketTunnelProvider.packetFlow`)
    pub raw_fd: Option<i32>,
    /// Whether to close the FD when the device is dropped.
    /// Default: true
    ///
    /// Set to `false` if the FD is owned by the platform (e.g., Android VpnService).
    #[allow(dead_code)] // Used on non-Linux platforms
    pub close_fd_on_drop: bool,
    /// Enable packet information header.
    /// - **iOS**: Set to `true` if using socket FD from `NEPacketTunnelProvider.packetFlow`,
    ///   `false` if using `readPackets`/`writePackets` API
    /// - **Linux/Android**: Not used
    #[allow(dead_code)] // Used on iOS
    pub packet_information: bool,
    /// Bytes of buffering per direction, per TCP connection.
    ///
    /// Four buffers of this size are allocated when a connection is accepted,
    /// so the cost per connection is four times this number. Together with
    /// `max_connections` it sets the stack's memory ceiling, which is what
    /// decides whether an iOS packet-tunnel extension stays under its ~50 MB
    /// jetsam limit.
    ///
    /// Default: 32 KiB on iOS and Android, 64 KiB elsewhere.
    pub tcp_buffer_size: usize,
    /// TCP connections the stack accepts before it starts dropping SYNs.
    ///
    /// Default: 256 on iOS and Android, 1024 elsewhere.
    pub max_connections: usize,
}

impl Default for TunServerConfig {
    fn default() -> Self {
        // Platform-specific MTU defaults based on sing-box research:
        // - iOS Network Extension: 4064 max (4096 - 32 byte UTUN_IF_HEADROOM_SIZE)
        //   Performance drops significantly above this value
        // - Android: 9000 (some devices report ENOBUFS with 65535)
        // - Other platforms: 1500 (standard Ethernet MTU)
        #[cfg(target_os = "ios")]
        let default_mtu = 4064;
        #[cfg(target_os = "android")]
        let default_mtu = 9000;
        #[cfg(not(any(target_os = "ios", target_os = "android")))]
        let default_mtu = 1500;

        // Shared with the AmneziaWG virtual stack, which allocates the same
        // four buffers per connection on the far side of the tunnel. See
        // src/buffer_sizing.rs for what the two of them add up to.
        let default_buffer_size = crate::buffer_sizing::default_local_buffer_size();
        let default_max_connections = crate::buffer_sizing::default_max_connections();

        Self {
            mtu: default_mtu,
            tcp_enabled: true,
            udp_enabled: true,
            icmp_enabled: true,
            tun_name: None,
            address: None,
            netmask: None,
            destination: None,
            raw_fd: None,
            close_fd_on_drop: true,
            packet_information: false,
            tcp_buffer_size: default_buffer_size,
            max_connections: default_max_connections,
        }
    }
}

impl TunServerConfig {
    /// Create a new TunServerConfig with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the MTU.
    pub fn mtu(mut self, mtu: u16) -> Self {
        self.mtu = mtu;
        self
    }

    /// Set the TUN device name (Linux, and macOS where it must be `utunN`).
    pub fn tun_name(mut self, name: impl Into<String>) -> Self {
        self.tun_name = Some(name.into());
        self
    }

    /// Set the TUN device address (Linux, macOS, Android).
    pub fn address(mut self, addr: IpAddr) -> Self {
        self.address = Some(addr);
        self
    }

    /// Set the TUN device netmask (Linux, macOS, Android).
    pub fn netmask(mut self, mask: IpAddr) -> Self {
        self.netmask = Some(mask);
        self
    }

    /// Set the TUN device destination/gateway (Linux, macOS).
    pub fn destination(mut self, dest: IpAddr) -> Self {
        self.destination = Some(dest);
        self
    }

    /// Set a raw file descriptor to use (iOS/Android).
    ///
    /// On iOS, this should be the FD from:
    /// ```objc
    /// int32_t tunFd = [[packetFlow valueForKeyPath:@"socket.fileDescriptor"] intValue];
    /// ```
    ///
    /// On Android, this should be the FD from `VpnService.Builder.establish()`.
    pub fn raw_fd(mut self, fd: i32) -> Self {
        self.raw_fd = Some(fd);
        self
    }

    /// Set whether to close the FD on drop.
    #[allow(dead_code)] // Used on non-Linux platforms
    pub fn close_fd_on_drop(mut self, close: bool) -> Self {
        self.close_fd_on_drop = close;
        self
    }

    /// Set the per-direction, per-connection TCP buffer size in bytes.
    pub fn tcp_buffer_size(mut self, size: usize) -> Self {
        self.tcp_buffer_size = size;
        self
    }

    /// Set the maximum number of concurrent TCP connections.
    pub fn max_connections(mut self, max: usize) -> Self {
        self.max_connections = max;
        self
    }

    /// Set whether packet information header is present (iOS only).
    ///
    /// - `true` if using socket FD from `NEPacketTunnelProvider.packetFlow`
    /// - `false` if using `readPackets`/`writePackets` API
    #[allow(dead_code)] // Used on iOS
    pub fn packet_information(mut self, pi: bool) -> Self {
        self.packet_information = pi;
        self
    }

    /// Enable or disable TCP connection handling.
    pub fn tcp_enabled(mut self, enabled: bool) -> Self {
        self.tcp_enabled = enabled;
        self
    }

    /// Enable or disable UDP packet handling.
    pub fn udp_enabled(mut self, enabled: bool) -> Self {
        self.udp_enabled = enabled;
        self
    }

    /// Enable or disable ICMP (ping) handling.
    pub fn icmp_enabled(mut self, enabled: bool) -> Self {
        self.icmp_enabled = enabled;
        self
    }

    /// Create a synchronous TUN device from this configuration.
    ///
    /// This is used by the direct mode stack which reads/writes directly
    /// from the TUN fd using select() for event-driven I/O. Unix only: the
    /// Windows backend creates a wintun adapter in `wintun_device.rs`
    /// instead, which has no descriptor to hand back.
    #[cfg(unix)]
    pub fn create_sync_device(&self) -> std::io::Result<Device> {
        let mut config = TunConfiguration::default();
        config.mtu(self.mtu);

        #[cfg(target_os = "linux")]
        {
            if let Some(ref name) = self.tun_name {
                config.tun_name(name);
            }
            if let Some(addr) = self.address {
                config.address(addr);
            }
            if let Some(mask) = self.netmask {
                config.netmask(mask);
            }
            if let Some(dest) = self.destination {
                config.destination(dest);
            }
            config.platform_config(|p| {
                p.ensure_root_privileges(true);
            });
            config.up();
        }

        // iOS only, and the difference is which side sets it, not the
        // defaults: the tun crate defaults packet_information to true on
        // BOTH Apple platforms, which is what a descriptor read off
        // NEPacketTunnelProvider.packetFlow carries. On iOS this forwards
        // the value run_tun_from_config sets for fd devices (the same
        // true); on macOS nothing forwards it and the crate default is
        // already right, so the builder field is a no-op there and stays
        // one. Forwarding it on macOS too would be harmless and equally
        // pointless.
        #[cfg(target_os = "ios")]
        {
            config.platform_config(|p| {
                p.packet_information(self.packet_information);
            });
        }

        // macOS creates its own device only for a privileged host that owns it
        // -- the daemon. A Network Extension provider passes raw_fd instead,
        // and `tun::Device::new` returns before any of this is read, so the
        // arm costs that path nothing.
        //
        // Every check here is a backstop for a caller that skipped
        // validate.rs, and it must agree with validate.rs rather than invent
        // looser rules -- the same contract the Windows arm below keeps.
        // Without it the failures are silent, which is the whole problem with
        // this path today:
        //
        // - An interface with no address comes up reachable by nothing, and
        //   the crate reports that no more loudly than it reports success.
        //   (`Device::new` also has an all-three-or-nothing point-to-point
        //   alias step, but `enable_routing(false)` below skips it -- see
        //   validate.rs, where the same reasoning decides that `destination`
        //   is warned about rather than required.)
        // - A name not of the form `utunN` is the crate's opaque
        //   `Error::InvalidName`, and a non-numeric suffix is a bare
        //   `ParseIntError`. Neither says what the rule is.
        #[cfg(target_os = "macos")]
        {
            if self.raw_fd.is_none() {
                if let Some(ref name) = self.tun_name {
                    if name.strip_prefix("utun").is_none_or(|unit| {
                        unit.is_empty() || !unit.bytes().all(|b| b.is_ascii_digit())
                    }) {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            format!(
                                "TUN device_name {name:?} is not valid on macOS: it must be \
                                 'utun' followed by a number, or omitted to let the kernel \
                                 pick the next free unit"
                            ),
                        ));
                    }
                    config.tun_name(name);
                }

                match (self.address, self.netmask) {
                    (Some(addr), Some(mask)) => {
                        config.address(addr);
                        config.netmask(mask);
                    }
                    _ => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "TUN on macOS requires 'address' and 'netmask'; without them \
                             the interface comes up reachable by nothing",
                        ));
                    }
                }
                if let Some(dest) = self.destination {
                    config.destination(dest);
                }

                // The daemon owns every route it will later have to revert, so
                // the crate must not add one behind it: `enable_routing`
                // defaults to true and makes `set_alias` shell out to `route`.
                //
                // Note that the flag guards the whole of `set_alias`, not just
                // that call, so this also drops the `SIOCAIFADDR` alias --
                // `configure()` still applies address, destination, netmask and
                // MTU through the individual ioctls, and `up()` below still
                // brings the interface up. See the open decision in
                // docs/plans/2026-09-04-macos-privileged-daemon.md.
                config.platform_config(|p| {
                    p.enable_routing(false);
                });
                config.up();
            }
        }

        #[cfg(target_os = "android")]
        {
            // Android requires raw_fd from VpnService.Builder.establish()
            if self.raw_fd.is_none() {
                return Err(std::io::Error::other(
                    "Android requires raw_fd from VpnService.Builder.establish()",
                ));
            }
            if let Some(addr) = self.address {
                config.address(addr);
            }
            if let Some(mask) = self.netmask {
                config.netmask(mask);
            }
        }

        if let Some(fd) = self.raw_fd {
            info!("Creating TUN device from raw FD: {}", fd);
            config.raw_fd(fd);
            config.close_fd_on_drop(self.close_fd_on_drop);
        }

        tun::create(&config)
            .map_err(|e| std::io::Error::other(format!("Failed to create TUN device: {}", e)))
    }
}
