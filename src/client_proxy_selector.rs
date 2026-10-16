#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "predates the lint; see the [lints] note in Cargo.toml"
)]

use log::{debug, error};
use lru::LruCache;
use parking_lot::RwLock;
use std::hash::Hash;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroUsize;
use std::sync::Arc;

use crate::address::{Address, NetLocation, ResolvedLocation};
use crate::address::{AddressMask, NetLocationMask};
use crate::client_proxy_chain::ClientChainGroup;
use crate::resolver::{Resolver, resolve_location};
use crate::rule_set::{MatchTarget, RuleSet, normalize_domain};

/// Cache key for routing decisions.
/// We cache based on the destination address and port.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum RoutingCacheKey {
    /// Hostname destination (e.g., "example.com:443")
    Hostname { hostname: String, port: u16 },
    /// IPv4 destination
    Ipv4 { addr: Ipv4Addr, port: u16 },
    /// IPv6 destination
    Ipv6 { addr: Ipv6Addr, port: u16 },
}

impl RoutingCacheKey {
    fn from_location(location: &NetLocation) -> Self {
        match location.address() {
            Address::Hostname(hostname) => RoutingCacheKey::Hostname {
                hostname: hostname.to_lowercase(),
                port: location.port(),
            },
            Address::Ipv4(addr) => RoutingCacheKey::Ipv4 {
                addr: *addr,
                port: location.port(),
            },
            Address::Ipv6(addr) => RoutingCacheKey::Ipv6 {
                addr: *addr,
                port: location.port(),
            },
        }
    }
}

/// Cached routing decision.
#[derive(Debug, Clone, Copy)]
pub(crate) enum CachedDecision {
    /// Index into the rules Vec for an Allow decision
    Allow(usize),
    /// Block decision
    Block,
}

/// LRU cache for routing decisions.
/// Uses RwLock for concurrent access - reads use peek() which doesn't require mutable access.
pub struct RoutingCache {
    inner: RwLock<LruCache<RoutingCacheKey, CachedDecision>>,
}

impl std::fmt::Debug for RoutingCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let cache = self.inner.read();
        f.debug_struct("RoutingCache")
            .field("len", &cache.len())
            .field("cap", &cache.cap())
            .finish()
    }
}

impl RoutingCache {
    /// Default cache capacity
    pub const DEFAULT_CAPACITY: usize = 10_000;

    /// Create a new routing cache with the specified capacity.
    pub fn new(capacity: usize) -> Self {
        let cap = NonZeroUsize::new(capacity).unwrap_or(NonZeroUsize::new(1).unwrap());
        Self {
            inner: RwLock::new(LruCache::new(cap)),
        }
    }

    /// Look up a cached decision.
    /// Uses peek() which doesn't update LRU order (avoids write lock).
    #[inline]
    pub fn get(&self, location: &NetLocation) -> Option<CachedDecision> {
        let key = RoutingCacheKey::from_location(location);
        self.inner.read().peek(&key).copied()
    }

    /// Insert a decision into the cache.
    #[inline]
    pub fn insert(&self, location: &NetLocation, decision: CachedDecision) {
        let key = RoutingCacheKey::from_location(location);
        self.inner.write().put(key, decision);
    }

    #[cfg(test)]
    fn clear(&self) {
        self.inner.write().clear();
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner.read().len()
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.inner.read().is_empty()
    }
}

#[derive(Debug)]
pub struct ConnectRule {
    pub masks: Vec<NetLocationMask>,
    /// Consulted only when no mask on this rule matched.
    pub rule_sets: Vec<Arc<RuleSet>>,
    pub action: ConnectAction,
}

impl ConnectRule {
    pub fn new(
        masks: Vec<NetLocationMask>,
        rule_sets: Vec<Arc<RuleSet>>,
        action: ConnectAction,
    ) -> Self {
        Self {
            masks,
            rule_sets,
            action,
        }
    }
}

#[derive(Debug)]
pub enum ConnectAction {
    Allow {
        override_address: Option<NetLocation>,
        /// The chain group for this rule - multiple chains for round-robin selection.
        chain_group: ClientChainGroup,
    },
    Block,
}

impl ConnectAction {
    pub fn new_allow(override_address: Option<NetLocation>, chain_group: ClientChainGroup) -> Self {
        ConnectAction::Allow {
            override_address,
            chain_group,
        }
    }

    pub fn new_block() -> Self {
        ConnectAction::Block
    }

    /// Convert this action to a decision.
    ///
    /// Takes ownership of the location. If there's an override_address, a new
    /// ResolvedLocation is created (the resolved_addr doesn't apply to a different
    /// destination). Otherwise, the original location is passed through, preserving
    /// any resolution that was done during rule matching.
    pub fn to_decision(&self, location: ResolvedLocation) -> ConnectDecision<'_> {
        match self {
            ConnectAction::Allow {
                override_address,
                chain_group,
            } => {
                let remote_location = match override_address {
                    Some(l) => {
                        // Override address - create fresh location (resolved_addr doesn't apply)
                        let new_loc = if l.port() > 0 {
                            l.clone()
                        } else {
                            // If port of 0 is specified, take the requested port.
                            NetLocation::new(l.address().clone(), location.location().port())
                        };
                        new_loc.into()
                    }
                    None => {
                        // No override - pass through with any resolution intact
                        location
                    }
                };
                ConnectDecision::Allow {
                    chain_group,
                    remote_location,
                }
            }
            ConnectAction::Block => ConnectDecision::Block,
        }
    }
}

/// Threshold for enabling cache based on rule count.
/// If rule count exceeds this value, caching is enabled even without DNS resolution.
const CACHE_RULE_THRESHOLD: usize = 16;

// TODO: Replace linear rule matching with radix set/trie
#[derive(Debug)]
pub struct ClientProxySelector {
    rules: Vec<ConnectRule>,
    /// If false, hostname rules will not trigger DNS resolution to match against IP-based
    /// destinations. This is useful when a huge blocklist or rule list is provided.
    /// However, this means that the user needs to make sure DNS resolutions are not done
    /// manually before hitting the server. Default is false (don't resolve).
    resolve_rule_hostnames: bool,
    /// LRU cache for routing decisions. Speeds up repeated lookups for the same destination.
    /// None if caching is disabled (few rules and no DNS resolution).
    cache: Option<RoutingCache>,
}

#[derive(Debug)]
pub enum ConnectDecision<'a> {
    Allow {
        chain_group: &'a ClientChainGroup,
        remote_location: ResolvedLocation,
    },
    Block,
}

impl ClientProxySelector {
    pub fn new(rules: Vec<ConnectRule>) -> Self {
        Self::with_options(rules, false)
    }

    /// Create a new ClientProxySelector with configurable hostname resolution behavior.
    ///
    /// # Arguments
    /// * `rules` - The list of routing rules
    /// * `resolve_rule_hostnames` - If true, hostname rules will be resolved via DNS to match
    ///   against IP-based destinations. If false (default), hostname rules only match hostname
    ///   destinations directly. Setting this to false is more performant for large rule sets.
    pub fn with_options(rules: Vec<ConnectRule>, resolve_rule_hostnames: bool) -> Self {
        Self::with_options_and_cache_size(
            rules,
            resolve_rule_hostnames,
            RoutingCache::DEFAULT_CAPACITY,
        )
    }

    /// Create a new ClientProxySelector with configurable hostname resolution and cache size.
    ///
    /// # Arguments
    /// * `rules` - The list of routing rules
    /// * `resolve_rule_hostnames` - If true, hostname rules will be resolved via DNS to match
    ///   against IP-based destinations. If false (default), hostname rules only match hostname
    ///   destinations directly.
    /// * `cache_capacity` - Maximum number of routing decisions to cache. Set to 0 to disable caching.
    ///
    /// # Caching behavior
    /// Caching is automatically enabled when:
    /// - `resolve_rule_hostnames` is true (DNS lookups are expensive), OR
    /// - Rule count exceeds `CACHE_RULE_THRESHOLD` (16)
    ///
    /// For simple configurations with few rules and no DNS resolution, caching is disabled
    /// as the overhead of cache key construction exceeds the cost of linear rule matching.
    pub fn with_options_and_cache_size(
        rules: Vec<ConnectRule>,
        resolve_rule_hostnames: bool,
        cache_capacity: usize,
    ) -> Self {
        // Enable caching if:
        // 1. DNS resolution is enabled (expensive operation), OR
        // 2. Many rules (linear scan becomes expensive), OR
        // 3. Any rule carries a rule-set, which is unconditionally more
        //    expensive to evaluate than a handful of masks.
        let has_rule_sets = rules.iter().any(|rule| !rule.rule_sets.is_empty());
        let cache = if resolve_rule_hostnames || rules.len() > CACHE_RULE_THRESHOLD || has_rule_sets
        {
            Some(RoutingCache::new(cache_capacity.max(1)))
        } else {
            None
        };

        Self {
            rules,
            resolve_rule_hostnames,
            cache,
        }
    }

    /// Judge a connection request, using the cache for faster repeated lookups.
    ///
    /// Takes ownership of `location` because:
    /// 1. Rule matching may resolve the hostname and cache it in the location
    /// 2. Rules may override the destination entirely
    ///
    /// The returned `ConnectDecision` contains the (possibly resolved/modified) location.
    ///
    /// Note: Caching is only enabled when `resolve_rule_hostnames` is true or there are
    /// more than 16 rules. For simple configurations, direct rule matching is faster.
    #[inline]
    pub async fn judge<'a>(
        &'a self,
        location: ResolvedLocation,
        resolver: &Arc<dyn Resolver>,
    ) -> std::io::Result<ConnectDecision<'a>> {
        // Derive resolved_ip from any pre-resolved address
        let resolved_ip = location.resolved_addr().map(|addr| ip_to_u128(addr.ip()));

        // If caching is disabled, go directly to rule matching
        let cache = match &self.cache {
            Some(c) => c,
            None => {
                return self.judge_uncached(location, resolved_ip, resolver).await;
            }
        };

        // Fast path: check cache first
        // Note: cached decisions don't include resolved_addr, so we pass through the location
        if let Some(cached) = cache.get(location.location()) {
            return Ok(self.cached_to_decision(cached, location));
        }

        // Slow path: full rule matching (may resolve and update the location)
        let mut location = location;
        match match_rule(
            &self.rules,
            &mut location,
            resolved_ip,
            resolver,
            self.resolve_rule_hostnames,
        )
        .await?
        {
            Some(rule_index) => {
                // Cache the result
                cache.insert(location.location(), CachedDecision::Allow(rule_index));
                Ok(self.rules[rule_index].action.to_decision(location))
            }
            None => {
                // Cache the block decision
                cache.insert(location.location(), CachedDecision::Block);
                Ok(ConnectDecision::Block)
            }
        }
    }

    /// Judge without using the cache. Useful for testing or when cache bypass is needed.
    #[inline]
    pub async fn judge_uncached<'a>(
        &'a self,
        location: ResolvedLocation,
        resolved_ip: Option<u128>,
        resolver: &Arc<dyn Resolver>,
    ) -> std::io::Result<ConnectDecision<'a>> {
        let mut location = location;
        match match_rule(
            &self.rules,
            &mut location,
            resolved_ip,
            resolver,
            self.resolve_rule_hostnames,
        )
        .await?
        {
            Some(rule_index) => Ok(self.rules[rule_index].action.to_decision(location)),
            None => Ok(ConnectDecision::Block),
        }
    }

    /// Convert a cached decision back to a ConnectDecision.
    #[inline]
    fn cached_to_decision(
        &self,
        cached: CachedDecision,
        location: ResolvedLocation,
    ) -> ConnectDecision<'_> {
        match cached {
            CachedDecision::Allow(rule_index) => {
                self.rules[rule_index].action.to_decision(location)
            }
            CachedDecision::Block => ConnectDecision::Block,
        }
    }

    #[cfg(test)]
    fn cache_size(&self) -> usize {
        self.cache.as_ref().map_or(0, |c| c.len())
    }

    #[cfg(test)]
    fn clear_cache(&self) {
        if let Some(cache) = &self.cache {
            cache.clear();
        }
    }

    #[cfg(test)]
    fn is_cache_enabled(&self) -> bool {
        self.cache.is_some()
    }
}

#[inline]
fn ip_to_u128(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(addr) => ipv4_to_u128(addr),
        IpAddr::V6(addr) => ipv6_to_u128(addr),
    }
}

#[inline]
fn ipv4_to_u128(ip: Ipv4Addr) -> u128 {
    ipv6_to_u128(ip.to_ipv6_mapped())
}

#[inline]
fn ipv6_to_u128(ip: Ipv6Addr) -> u128 {
    u128::from(ip)
}

#[inline]
fn matches_domain(base_domain: &str, hostname: &str) -> bool {
    if hostname.ends_with(base_domain) {
        let hostname_len = hostname.len();
        let base_domain_len = base_domain.len();
        if hostname_len == base_domain_len {
            true
        } else {
            // hostname_len > base_domain_len since hostname ends with base_domain.
            hostname.as_bytes()[hostname_len - base_domain_len - 1] == b'.'
        }
    } else {
        false
    }
}

/// Returns the index of the matching rule.
/// During matching, may resolve the location's address and cache it in `location`.
#[inline]
async fn match_rule(
    rules: &[ConnectRule],
    location: &mut ResolvedLocation,
    mut resolved_ip: Option<u128>,
    resolver: &Arc<dyn Resolver>,
    resolve_rule_hostnames: bool,
) -> std::io::Result<Option<usize>> {
    for (rule_index, rule) in rules.iter().enumerate() {
        for mask in rule.masks.iter() {
            match match_mask(
                mask,
                location,
                &mut resolved_ip,
                resolver,
                resolve_rule_hostnames,
            )
            .await
            {
                Ok(is_match) => {
                    if is_match {
                        debug!(
                            "Found matching mask for {} -> {mask:?}",
                            location.location()
                        );
                        return Ok(Some(rule_index));
                    }
                }
                Err(MatchMaskError::Fatal(e)) => {
                    return Err(std::io::Error::other(format!(
                        "fatal error while matching mask for {}: {e}",
                        location.location()
                    )));
                }
                Err(MatchMaskError::NonFatal(e)) => {
                    error!(
                        "Non-fatal error while trying to match mask for {}: {e}",
                        location.location()
                    );
                }
            }
        }

        if !rule.rule_sets.is_empty()
            && match_rule_sets(
                &rule.rule_sets,
                location,
                &mut resolved_ip,
                resolver,
                resolve_rule_hostnames,
            )
            .await?
        {
            debug!(
                "Found matching rule-set for {} in rule {rule_index}",
                location.location()
            );
            return Ok(Some(rule_index));
        }
    }
    Ok(None)
}

/// Match a rule's rule-sets against the location.
///
/// Masks are tried first by the caller because they are cheaper and usually
/// more specific. Resolution obeys `resolve_rule_hostnames`, the same flag the
/// mask path uses, so a rule-set behaves like another mask rather than like a
/// subsystem with its own rules.
async fn match_rule_sets(
    rule_sets: &[Arc<RuleSet>],
    location: &mut ResolvedLocation,
    resolved_ip: &mut Option<u128>,
    resolver: &Arc<dyn Resolver>,
    resolve_rule_hostnames: bool,
) -> std::io::Result<bool> {
    // Taken by value so the immutable borrow of `location` ends before the
    // resolution below needs it mutably. The allocation only happens on a
    // RoutingCache miss.
    let domain: Option<String> = match location.location().address() {
        Address::Hostname(hostname) => Some(normalize_domain(hostname).into_owned()),
        _ => None,
    };

    let literal_ip = match location.location().address() {
        Address::Ipv4(addr) => Some(ipv4_to_u128(*addr)),
        Address::Ipv6(addr) => Some(ipv6_to_u128(*addr)),
        Address::Hostname(_) => None,
    };

    let ip = match literal_ip {
        Some(ip) => Some(ip),
        None => match *resolved_ip {
            Some(ip) => Some(ip),
            None if resolve_rule_hostnames => {
                let socket_addr = resolve_location(location, resolver).await?;
                let ip = ip_to_u128(socket_addr.ip());
                resolved_ip.replace(ip);
                Some(ip)
            }
            None => None,
        },
    };

    let target = MatchTarget {
        domain: domain.as_deref(),
        ip,
    };
    Ok(rule_sets.iter().any(|rule_set| rule_set.matches(&target)))
}

enum MatchMaskError {
    NonFatal(std::io::Error),
    Fatal(std::io::Error),
}

// Helper function for testing - exposed for unit tests
#[cfg(test)]
pub fn matches_domain_for_test(base_domain: &str, hostname: &str) -> bool {
    matches_domain(base_domain, hostname)
}

/// Match a single mask against the location.
/// Updates `resolved_ip` and `location.resolved_addr` if DNS resolution is performed.
#[inline]
async fn match_mask(
    location_mask: &NetLocationMask,
    location: &mut ResolvedLocation,
    resolved_ip: &mut Option<u128>,
    resolver: &Arc<dyn Resolver>,
    resolve_rule_hostnames: bool,
) -> std::result::Result<bool, MatchMaskError> {
    let NetLocationMask {
        address_mask: AddressMask { address, netmask },
        port,
    } = location_mask;

    let netmask = *netmask;
    let port = *port;

    if port > 0 && port != location.location().port() {
        return Ok(false);
    }

    if netmask == 0 {
        return Ok(true);
    }

    if let Some(hostname) = address.hostname() {
        if let Some(remote_hostname) = location.location().address().hostname() {
            return Ok(matches_domain(hostname, remote_hostname));
        }

        // We don't care about netmasks when hostnames are provided, so we can do direct matching
        // without resolving when both the remote location and the provided rule address are hostnames,
        // and simply return if it doesn't match.
        if !resolve_rule_hostnames {
            return Ok(false);
        }
    }

    // Need to get resolved IP for matching
    let masked_ip = match resolved_ip {
        Some(ip) => *ip,
        None => {
            // Resolve the destination lazily - this caches in `location`
            let socket_addr = resolve_location(location, resolver)
                .await
                .map_err(MatchMaskError::Fatal)?;
            let ip = ip_to_u128(socket_addr.ip());
            resolved_ip.replace(ip);
            ip
        }
    } & netmask;

    match address {
        Address::Ipv4(ip_addr) => {
            let mask = ipv4_to_u128(*ip_addr) & netmask;
            if mask == masked_ip {
                return Ok(true);
            }
        }
        Address::Ipv6(ip_addr) => {
            let mask = ipv6_to_u128(*ip_addr) & netmask;
            if mask == masked_ip {
                return Ok(true);
            }
        }
        Address::Hostname(_) => {
            // non-fatal error when the rule address cannot be resolved.
            // TODO: could this be cached?
            let socket_addrs = resolver
                .resolve_location(&NetLocation::new(address.clone(), port))
                .await
                .map_err(MatchMaskError::NonFatal)?;
            for socket_addr in socket_addrs {
                let mask = ip_to_u128(socket_addr.ip()) & netmask;
                if mask == masked_ip {
                    return Ok(true);
                }
            }
        }
    }

    Ok(false)
}

#[cfg(test)]
mod tests;
