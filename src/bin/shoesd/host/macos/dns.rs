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
//!
//! And both are put back exactly, each from its own [`StoreKeys`] snapshot,
//! never from the parsed servers: the two keys hold different things, and a
//! dictionary holds more than its servers. See [`DnsState::store_keys`].
//!
//! [`DnsState::store_keys`]: super::super::DnsState::store_keys

use std::net::IpAddr;

use core_foundation::array::CFArray;
use core_foundation::base::{TCFType, ToVoid};
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::propertylist::{
    self, CFPropertyList, kCFPropertyListImmutable, kCFPropertyListXMLFormat_v1_0,
};
use core_foundation::string::{CFString, CFStringRef};
use system_configuration::dynamic_store::{SCDynamicStore, SCDynamicStoreBuilder};
use system_configuration::sys::schema_definitions::{
    kSCDynamicStorePropNetPrimaryService, kSCPropNetDNSServerAddresses,
};

use super::super::StoreKeys;

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
        // SAFETY: `value` points into `global`, which is alive; the get rule
        // retains a reference for the CFString it returns.
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
        // SAFETY: `value` points into `dictionary`, alive here; the get rule
        // retains the array it returns.
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

    /// Both keys of a service exactly as they are now -- what a revert puts
    /// back. A key that is not there is recorded as absent, not as empty.
    pub fn snapshot(&self, service: &str) -> std::io::Result<StoreKeys> {
        Ok(StoreKeys {
            state: self.snapshot_key(&state_key(service))?,
            setup: self.snapshot_key(&setup_key(service))?,
        })
    }

    fn snapshot_key(&self, key: &str) -> std::io::Result<Option<String>> {
        self.store.get(key).map(|value| to_xml(&value)).transpose()
    }

    /// Put both keys back exactly as [`DnsStore::snapshot`] found them: the
    /// saved dictionary where there was one, and no key where there was none.
    ///
    /// Idempotent, for the reason [`DnsStore::write`] gives: an absent key
    /// that is already gone is success.
    pub fn restore(&self, service: &str, keys: &StoreKeys) -> std::io::Result<()> {
        for (key, saved) in [
            (state_key(service), &keys.state),
            (setup_key(service), &keys.setup),
        ] {
            let succeeded = match saved {
                Some(xml) => self.store.set_raw(key.as_str(), &from_xml(xml)?),
                None => self.store.get(key.as_str()).is_none() || self.store.remove(key.as_str()),
            };
            if !succeeded {
                return Err(std::io::Error::other(format!(
                    "the system configuration store refused to restore {key}"
                )));
            }
        }
        Ok(())
    }
}

/// A property list as XML, the form a revert record carries it in: every
/// type a dictionary can hold survives it, and the record stays readable.
fn to_xml(value: &CFPropertyList) -> std::io::Result<String> {
    let data =
        propertylist::create_data(value.as_concrete_TypeRef(), kCFPropertyListXMLFormat_v1_0)
            .map_err(|e| std::io::Error::other(format!("could not serialise a DNS key: {e}")))?;
    String::from_utf8(data.bytes().to_vec())
        .map_err(|e| std::io::Error::other(format!("a serialised DNS key is not UTF-8: {e}")))
}

/// The inverse of [`to_xml`].
fn from_xml(xml: &str) -> std::io::Result<CFPropertyList> {
    let (value, _format) = propertylist::create_with_data(
        CFData::from_buffer(xml.as_bytes()),
        kCFPropertyListImmutable,
    )
    .map_err(|e| {
        std::io::Error::other(format!(
            "the revert record holds an unreadable DNS key: {e}"
        ))
    })?;
    // SAFETY: `create_with_data` returns a new, non-null property list on
    // success, owned by the caller: the create rule takes that ownership.
    Ok(unsafe { CFPropertyList::wrap_under_create_rule(value) })
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
    use core_foundation::propertylist::CFPropertyListSubClass;

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

    /// A DHCP service's dictionary, the shape the live run found: servers and
    /// the lease's domain. Whatever else a key holds must survive the record
    /// too, so the fixture carries an empty array beside them.
    fn lease_dictionary() -> CFPropertyList {
        let servers =
            CFArray::from_CFTypes(&[CFString::new("172.29.5.17"), CFString::new("172.22.2.17")]);
        let domain = CFString::new("corp.example");
        let none: CFArray<CFString> = CFArray::from_CFTypes(&[]);
        let dictionary = CFDictionary::from_CFType_pairs(&[
            (CFString::new("ServerAddresses"), servers.as_CFType()),
            (CFString::new("DomainName"), domain.as_CFType()),
            (CFString::new("SearchDomains"), none.as_CFType()),
        ]);
        dictionary.to_untyped().to_CFPropertyList()
    }

    /// The whole dictionary goes into the record and comes back out equal --
    /// not just `ServerAddresses`, which is all 0.8.1 kept.
    #[test]
    fn a_dns_key_survives_the_record_whole() {
        let original = lease_dictionary();
        let xml = to_xml(&original).unwrap();
        assert!(xml.contains("<string>corp.example</string>"), "{xml}");

        let back = from_xml(&xml).unwrap();
        assert_eq!(back, original);
        assert_eq!(to_xml(&back).unwrap(), xml, "a second trip changes nothing");
    }

    /// A damaged record is an error the revert reports, not a key silently
    /// written as nothing.
    #[test]
    fn an_unreadable_saved_key_is_an_error() {
        let error = from_xml("not a property list").unwrap_err();
        assert!(error.to_string().contains("unreadable DNS key"), "{error}");
    }

    /// A key that is not there is recorded as absent -- restored by removing
    /// it -- rather than as an empty dictionary, which would be a service
    /// configured to resolve nothing.
    #[test]
    fn a_service_without_keys_snapshots_as_absent() {
        let store = DnsStore::open().unwrap();
        let keys = store
            .snapshot("00000000-0000-0000-0000-NOT-A-SERVICE")
            .unwrap();
        assert_eq!(
            keys,
            StoreKeys {
                state: None,
                setup: None
            }
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
