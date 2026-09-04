//! DNS through `SCDynamicStore`.
//!
//! Not `networksetup`, which is what wg-quick uses. Two reasons, and the
//! second decides it. `networksetup` addresses a service by its display name,
//! and Clash Nyanpasu's DNS has been broken that way since macOS 14.3
//! (libnyanpasu/nyanpasu-service#26); `SCDynamicStore` addresses it by id. And
//! wg-quick keeps its saved resolvers in shell variables, so a killed process
//! can never restore them -- a daemon that must survive `kill -9` needs the
//! backup on disk regardless of which API writes it, which is what
//! `AppliedState` is for.
//!
//! Both the `State:` and `Setup:` keys are written. `State:` is what the
//! resolver reads now; `Setup:` is what the system re-derives `State:` from
//! when the network changes underneath. Writing only the first works until the
//! Wi-Fi flaps.

use std::net::IpAddr;

use core_foundation::array::CFArray;
use core_foundation::base::{TCFType, ToVoid};
use core_foundation::dictionary::CFDictionary;
use core_foundation::propertylist::CFPropertyList;
use core_foundation::string::{CFString, CFStringRef};
use system_configuration::dynamic_store::{SCDynamicStore, SCDynamicStoreBuilder};
use system_configuration::sys::schema_definitions::{
    kSCDynamicStorePropNetPrimaryService, kSCPropNetDNSServerAddresses,
};

/// A handle on the dynamic store.
pub struct DnsStore {
    store: SCDynamicStore,
}

impl DnsStore {
    pub fn open() -> std::io::Result<Self> {
        let store = SCDynamicStoreBuilder::new("shoesd")
            .build()
            .ok_or_else(|| {
                std::io::Error::other("could not open the system configuration store")
            })?;
        Ok(Self { store })
    }

    /// The id of the service DNS should be set on.
    ///
    /// The `PrimaryService` of the global IPv4 state, which is the service
    /// carrying the default route -- the one whose resolvers are actually
    /// consulted.
    pub fn primary_service(&self) -> std::io::Result<String> {
        let global = self
            .store
            .get("State:/Network/Global/IPv4")
            .and_then(CFPropertyList::downcast_into::<CFDictionary>)
            .ok_or_else(|| {
                std::io::Error::other(
                    "no primary IPv4 service: the machine has no active network connection",
                )
            })?;

        // SAFETY: `kSCDynamicStorePropNetPrimaryService` is a static CFString
        // constant from SystemConfiguration; `find` returns a borrowed pointer
        // into the dictionary, which outlives the `wrap_under_get_rule` that
        // copies it out.
        let value = global
            .find(unsafe { kSCDynamicStorePropNetPrimaryService }.to_void())
            .ok_or_else(|| {
                std::io::Error::other("the global IPv4 state names no PrimaryService")
            })?;
        let service = unsafe { CFString::wrap_under_get_rule(*value as CFStringRef) };

        Ok(service.to_string())
    }

    /// The resolvers configured on a service right now.
    ///
    /// An absent key is an empty list rather than an error: a service with no
    /// explicit resolvers is the ordinary case on DHCP, and restoring "none"
    /// is what puts it back.
    pub fn read(&self, service: &str) -> std::io::Result<Vec<IpAddr>> {
        let Some(dictionary) = self
            .store
            .get(state_key(service).as_str())
            .and_then(CFPropertyList::downcast_into::<CFDictionary>)
        else {
            return Ok(Vec::new());
        };

        // SAFETY: as above -- a static constant as the key, and a borrowed
        // pointer copied out before the dictionary is dropped.
        let Some(value) = dictionary.find(unsafe { kSCPropNetDNSServerAddresses }.to_void()) else {
            return Ok(Vec::new());
        };
        let addresses = unsafe {
            CFArray::<CFString>::wrap_under_get_rule(*value as core_foundation::array::CFArrayRef)
        };

        // Anything that will not parse is dropped rather than failing the
        // read. This list is a backup to restore later, and one unparseable
        // entry -- a stale IPv6 scope, something a configuration profile
        // wrote -- must not make the whole session refuse to start.
        Ok(addresses
            .iter()
            .filter_map(|address| address.to_string().parse().ok())
            .collect())
    }

    /// Set the resolvers on a service, on both keys.
    ///
    /// An empty list removes the override, which is how a service that had no
    /// explicit resolvers is restored.
    pub fn write(&self, service: &str, servers: &[IpAddr]) -> std::io::Result<()> {
        for key in [state_key(service), setup_key(service)] {
            let succeeded = if servers.is_empty() {
                // `remove` rather than an empty array: an empty
                // ServerAddresses list is a service configured to have no
                // resolvers, which resolves nothing. Removing the key is what
                // hands the question back to DHCP.
                //
                // A key that is not there is success, not failure. `remove`
                // answers `false` for both, and revert has to be idempotent --
                // `recover()` re-runs against a record whose revert may
                // already have partly succeeded. Treating "already gone" as an
                // error would leave a machine that had no explicit resolvers
                // permanently unable to start: every retry would fail on the
                // same absent key.
                self.store.get(key.as_str()).is_none() || self.store.remove(key.as_str())
            } else {
                self.store.set(key.as_str(), dns_dictionary(servers))
            };

            // Both APIs answer with a bool rather than a Result, so an
            // unchecked call is a silent failure -- and a silent failure here
            // means the tunnel is up and DNS is still the host's, which is the
            // leak the dns block exists to close.
            if !succeeded {
                return Err(std::io::Error::other(format!(
                    "the system configuration store refused a write to {key}"
                )));
            }
        }
        Ok(())
    }
}

fn state_key(service: &str) -> String {
    format!("State:/Network/Service/{service}/DNS")
}

fn setup_key(service: &str) -> String {
    format!("Setup:/Network/Service/{service}/DNS")
}

/// `{ ServerAddresses: [...] }`.
fn dns_dictionary(servers: &[IpAddr]) -> CFDictionary {
    let addresses: Vec<CFString> = servers
        .iter()
        .map(|address| CFString::new(&address.to_string()))
        .collect();

    // SAFETY: a static constant from SystemConfiguration, borrowed for the
    // lifetime of the dictionary built from it.
    let key = unsafe { CFString::wrap_under_get_rule(kSCPropNetDNSServerAddresses) };
    let typed = CFDictionary::from_CFType_pairs(&[(key, CFArray::from_CFTypes(&addresses))]);

    // The typed dictionary has to be laundered into an untyped one to satisfy
    // `CFPropertyListSubClass`, which is what `set` takes. This is what the
    // crate's own `set_dns` example does.
    // SAFETY: `typed` is a valid CFDictionary and the wrap takes a +0
    // reference to the same object, which is retained by the new wrapper.
    unsafe { CFDictionary::wrap_under_get_rule(typed.as_concrete_TypeRef()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both keys, and the service id in each. `State:` is what the resolver
    /// reads now; `Setup:` is what the system re-derives it from when the
    /// network changes. Writing only one works until the Wi-Fi flaps.
    #[test]
    fn both_keys_name_the_service_by_id() {
        assert_eq!(
            state_key("2BFF3B4D-0D0A"),
            "State:/Network/Service/2BFF3B4D-0D0A/DNS"
        );
        assert_eq!(
            setup_key("2BFF3B4D-0D0A"),
            "Setup:/Network/Service/2BFF3B4D-0D0A/DNS"
        );
    }

    /// The store is real, and opening it must work for any user -- the daemon
    /// runs as root, but the tests do not, and a failure here would be the
    /// first thing a live run tripped over.
    #[test]
    fn the_store_opens() {
        DnsStore::open().expect("the dynamic store is available to any process");
    }

    /// Reading the machine's own primary service, which exercises the whole
    /// downcast-and-borrow path against real CoreFoundation objects rather
    /// than a fixture. Skipped where there is no network, since then there is
    /// correctly no primary service.
    #[test]
    fn the_primary_service_is_a_plausible_id() {
        let store = DnsStore::open().unwrap();
        let Ok(service) = store.primary_service() else {
            return;
        };
        assert!(!service.is_empty());

        // And reading its resolvers must not fail, whatever they are -- this
        // is the call whose result becomes the restore-on-stop backup.
        let servers = store.read(&service).expect("reading resolvers");
        for address in &servers {
            assert!(!address.is_unspecified(), "got {address}");
        }
    }
}
