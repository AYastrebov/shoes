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
//! For the same reason applying changes only `ServerAddresses` in each key
//! and keeps the rest of its dictionary: a lease's `DomainName` and a user's
//! `SearchDomains` stay in force while the tunnel's resolvers answer.
//!
//! [`DnsState::store_keys`]: super::super::DnsState::store_keys

use std::net::IpAddr;

use core_foundation::array::CFArray;
use core_foundation::base::{TCFType, ToVoid};
use core_foundation::data::CFData;
use core_foundation::dictionary::{CFDictionary, CFMutableDictionary};
use core_foundation::propertylist::{
    self, CFPropertyList, CFPropertyListSubClass, kCFPropertyListImmutable,
    kCFPropertyListXMLFormat_v1_0,
};
use core_foundation::string::{CFString, CFStringRef};
use system_configuration::dynamic_store::{SCDynamicStore, SCDynamicStoreBuilder};
use system_configuration::sys::schema_definitions::{
    kSCDynamicStorePropNetPrimaryService, kSCPropNetDNSServerAddresses, kSCPropNetDNSServerPort,
};

use super::super::StoreKeys;

/// What the dynamic store is to this module: keys holding property lists,
/// whose writes answer with a bool. [`SCDynamicStore`] is the real one. The
/// tests keep one in a map, because the real store refuses every write from
/// a process that is not root, and the restore path is the part that must
/// be tested -- 0.8.1 shipped it wrong with every read path tested.
pub trait Store {
    fn get(&self, key: &str) -> Option<CFPropertyList>;
    /// `true` on success, as `SCDynamicStoreSetValue` answers.
    fn set(&self, key: &str, value: &CFPropertyList) -> bool;
    /// `true` on success; `false` for a key that is not there, as
    /// `SCDynamicStoreRemoveValue` answers.
    fn remove(&self, key: &str) -> bool;
}

impl Store for SCDynamicStore {
    fn get(&self, key: &str) -> Option<CFPropertyList> {
        SCDynamicStore::get(self, key)
    }

    fn set(&self, key: &str, value: &CFPropertyList) -> bool {
        self.set_raw(key, value)
    }

    fn remove(&self, key: &str) -> bool {
        SCDynamicStore::remove(self, key)
    }
}

/// A handle on the dynamic store.
pub struct DnsStore<S: Store = SCDynamicStore> {
    store: S,
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
}

impl<S: Store> DnsStore<S> {
    /// Over a store that is not the system's; the tests' way in.
    #[cfg(test)]
    pub fn with_store(store: S) -> Self {
        Self { store }
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
    /// Only the resolvers: each key keeps the rest of its dictionary.
    /// Writing `{ ServerAddresses }` alone, as every release through 0.9.0
    /// did, dropped a lease's `DomainName` and a user's `SearchDomains` for
    /// the life of a session, so a bare hostname that resolved through the
    /// search list before did not resolve through the tunnel. The re-apply
    /// after a network change comes through here too, and so merges into
    /// whatever the new network's lease wrote.
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
                let merged = dns_dictionary(self.store.get(key.as_str()), servers);
                self.store.set(key.as_str(), &merged)
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
                Some(xml) => self.store.set(key.as_str(), &from_xml(xml)?),
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

/// `existing` with its `ServerAddresses` set to `servers`, its `ServerPort`
/// removed, and everything else in it kept; `{ ServerAddresses: [...] }`
/// where there is no dictionary to keep.
fn dns_dictionary(existing: Option<CFPropertyList>, servers: &[IpAddr]) -> CFPropertyList {
    let addresses: Vec<CFString> = servers
        .iter()
        .map(|address| CFString::new(&address.to_string()))
        .collect();
    let addresses = CFArray::from_CFTypes(&addresses);

    // SAFETY: a static constant from SystemConfiguration, borrowed for the
    // lifetime of the dictionary built from it.
    let key = unsafe { CFString::wrap_under_get_rule(kSCPropNetDNSServerAddresses) };

    // A copy, never the store's own dictionary: the store hands out an
    // immutable one. Untyped, because the values are of every type a
    // property list holds.
    let mut merged: CFMutableDictionary =
        match existing.and_then(CFPropertyList::downcast_into::<CFDictionary>) {
            Some(dictionary) => CFMutableDictionary::from(&dictionary),
            None => CFMutableDictionary::new(),
        };
    // The dictionary retains both, so they may drop after this.
    merged.set(key.as_CFTypeRef(), addresses.as_CFTypeRef());

    // The port belongs to the resolvers being replaced: kept, it would send
    // the tunnel's resolvers queries on a port they do not listen on, where
    // the tunnel's DNS answers on 53. The revert's snapshot still has it.
    // SAFETY: as for `key`.
    let port = unsafe { CFString::wrap_under_get_rule(kSCPropNetDNSServerPort) };
    merged.remove(port.as_CFTypeRef());

    merged.to_immutable().into_CFPropertyList()
}

/// The doubles the host's tests share with this module's.
#[cfg(test)]
pub mod testing {
    use super::*;
    use core_foundation::base::CFType;
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::rc::Rc;

    /// A [`Store`] in a map, answering as the real one does: a write
    /// succeeds, and removing a key that is not there is `false`. Cloning
    /// shares the map, so a test keeps a handle on what a host writes.
    #[derive(Clone, Default)]
    pub struct MapStore(Rc<RefCell<BTreeMap<String, CFPropertyList>>>);

    impl Store for MapStore {
        fn get(&self, key: &str) -> Option<CFPropertyList> {
            self.0.borrow().get(key).cloned()
        }

        fn set(&self, key: &str, value: &CFPropertyList) -> bool {
            self.0.borrow_mut().insert(key.to_string(), value.clone());
            true
        }

        fn remove(&self, key: &str) -> bool {
            self.0.borrow_mut().remove(key).is_some()
        }
    }

    /// The `State:` key of a service, as the system names it.
    pub fn state_key(service: &str) -> String {
        super::state_key(service)
    }

    /// The `Setup:` key of a service.
    pub fn setup_key(service: &str) -> String {
        super::setup_key(service)
    }

    /// A DHCP service's dictionary, the shape the live run found: servers and
    /// the lease's domain. Whatever else a key holds must survive the record
    /// too, so the fixture carries an empty array beside them.
    pub fn lease_dictionary() -> CFPropertyList {
        lease_dictionary_with(&["172.29.5.17", "172.22.2.17"].map(|a| a.parse().unwrap()))
    }

    /// What a user types into Network Settings: their own resolver and a
    /// search domain, in `Setup:`, which overrides the lease.
    pub fn user_dictionary() -> CFPropertyList {
        user_dictionary_with(&["192.0.2.53".parse().unwrap()])
    }

    /// `{}`: a service configured to resolve nothing, which is not the same
    /// thing as a service with no key.
    pub fn empty_dictionary() -> CFPropertyList {
        dictionary(&[])
    }

    /// What applying writes where a key had nothing: the servers alone.
    pub fn servers_dictionary(servers: &[IpAddr]) -> CFPropertyList {
        dns_dictionary(None, servers)
    }

    /// [`lease_dictionary`] with the tunnel's resolvers: what applying
    /// writes over a lease, its `DomainName` kept.
    pub fn lease_dictionary_with(servers: &[IpAddr]) -> CFPropertyList {
        let domain = CFString::new("corp.example");
        let none: CFArray<CFString> = CFArray::from_CFTypes(&[]);
        dictionary(&[
            ("ServerAddresses", addresses(servers).as_CFType()),
            ("DomainName", domain.as_CFType()),
            ("SearchDomains", none.as_CFType()),
        ])
    }

    /// [`user_dictionary`] with the tunnel's resolvers, its `SearchDomains`
    /// kept.
    pub fn user_dictionary_with(servers: &[IpAddr]) -> CFPropertyList {
        let search = CFArray::from_CFTypes(&[CFString::new("home.example")]);
        dictionary(&[
            ("ServerAddresses", addresses(servers).as_CFType()),
            ("SearchDomains", search.as_CFType()),
        ])
    }

    fn addresses(servers: &[IpAddr]) -> CFArray<CFString> {
        let servers: Vec<CFString> = servers
            .iter()
            .map(|address| CFString::new(&address.to_string()))
            .collect();
        CFArray::from_CFTypes(&servers)
    }

    /// A dictionary of the given entries, for a fixture the ones above do
    /// not cover.
    pub fn dictionary(pairs: &[(&str, CFType)]) -> CFPropertyList {
        let pairs: Vec<(CFString, CFType)> = pairs
            .iter()
            .map(|(key, value)| (CFString::new(key), value.clone()))
            .collect();
        CFDictionary::from_CFType_pairs(&pairs)
            .to_untyped()
            .into_CFPropertyList()
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{MapStore, lease_dictionary};
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

    /// The parsed servers are read from `State:` alone, whatever `Setup:`
    /// holds -- `State:` is what the resolver consults.
    #[test]
    fn the_servers_are_read_from_the_state_key() {
        let map = MapStore::default();
        map.set(&state_key("S"), &lease_dictionary());
        map.set(&setup_key("S"), &testing::user_dictionary());
        let store = DnsStore::with_store(map);

        let servers: Vec<IpAddr> = store.read("S").unwrap();
        assert_eq!(
            servers,
            ["172.29.5.17", "172.22.2.17"].map(|s| s.parse::<IpAddr>().unwrap())
        );
    }

    /// A network change is macOS putting the new lease back in `State:`,
    /// and the re-apply that follows writes the tunnel's resolvers over it.
    /// The lease's domain is the new network's, and it is kept: replacing
    /// the dictionary, as every release through 0.9.0 did, dropped it for as
    /// long as the session lasted.
    #[test]
    fn a_reapply_over_a_new_lease_keeps_its_domain() {
        let map = MapStore::default();
        let store = DnsStore::with_store(map.clone());
        let tunnel: [IpAddr; 1] = ["10.99.0.1".parse().unwrap()];

        store.write("S", &tunnel).unwrap();
        assert_eq!(
            map.get(&state_key("S")),
            Some(testing::servers_dictionary(&tunnel)),
            "no key before: the servers alone"
        );

        map.set(&state_key("S"), &lease_dictionary());
        store.write("S", &tunnel).unwrap();
        assert_eq!(
            map.get(&state_key("S")),
            Some(testing::lease_dictionary_with(&tunnel))
        );
    }

    /// A resolver on a port of its own: the tunnel's resolvers replace it
    /// on 53, so its `ServerPort` goes with its addresses, and the domain
    /// beside them stays.
    #[test]
    fn applying_drops_the_old_resolvers_port() {
        use core_foundation::number::CFNumber;
        let old = CFArray::from_CFTypes(&[CFString::new("192.0.2.53")]);
        let domain = CFString::new("corp.example");
        let map = MapStore::default();
        map.set(
            &state_key("S"),
            &testing::dictionary(&[
                ("ServerAddresses", old.as_CFType()),
                ("ServerPort", CFNumber::from(5353).as_CFType()),
                ("DomainName", domain.as_CFType()),
            ]),
        );
        let store = DnsStore::with_store(map.clone());
        let tunnel: [IpAddr; 1] = ["10.99.0.1".parse().unwrap()];

        store.write("S", &tunnel).unwrap();

        let tunnel_addresses = CFArray::from_CFTypes(&[CFString::new("10.99.0.1")]);
        assert_eq!(
            map.get(&state_key("S")),
            Some(testing::dictionary(&[
                ("ServerAddresses", tunnel_addresses.as_CFType()),
                ("DomainName", domain.as_CFType()),
            ]))
        );
    }

    /// Removing a key that is already gone is success, on the real store's
    /// word that `remove` answers `false` for it: `recover()` re-runs a
    /// revert that may have partly succeeded.
    #[test]
    fn restoring_an_absent_key_that_is_already_absent_succeeds() {
        let map = MapStore::default();
        let store = DnsStore::with_store(map.clone());
        let keys = StoreKeys {
            state: None,
            setup: None,
        };

        store.restore("S", &keys).unwrap();
        store.restore("S", &keys).unwrap();
        assert!(map.get(&state_key("S")).is_none());
        assert!(map.get(&setup_key("S")).is_none());
    }

    /// A store that refuses the write is an error, not a revert reported
    /// clean with DNS still the tunnel's.
    #[test]
    fn a_refused_restore_is_an_error_naming_the_key() {
        struct Refusing;
        impl Store for Refusing {
            fn get(&self, _key: &str) -> Option<CFPropertyList> {
                None
            }
            fn set(&self, _key: &str, _value: &CFPropertyList) -> bool {
                false
            }
            fn remove(&self, _key: &str) -> bool {
                false
            }
        }
        let store = DnsStore::with_store(Refusing);
        let keys = StoreKeys {
            state: Some(to_xml(&lease_dictionary()).unwrap()),
            setup: None,
        };

        let error = store.restore("S", &keys).unwrap_err();
        assert!(
            error.to_string().contains("State:/Network/Service/S/DNS"),
            "{error}"
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
