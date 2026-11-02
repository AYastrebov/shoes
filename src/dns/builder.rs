//! DNS resolver builder and registry.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "predates the lint; see the [lints] note in Cargo.toml"
)]

use std::sync::Arc;
use std::time::Duration;

use rustc_hash::FxHashMap;

use crate::config::{DnsBootstrap, DnsConfig, ExpandedDnsGroup, ExpandedDnsSpec};
use crate::dns::composite_resolver::CompositeResolver;
use crate::dns::hickory_resolver::{HickoryResolver, HickoryResolverOptions};
use crate::dns::parsed::{ParsedDnsServer, ParsedDnsServerEntry, ParsedDnsUrl};
use crate::option_util::NoneOrSome;
use crate::resolver::{
    CachingNativeResolver, NativeResolver, RefreshPolicy, RefreshingResolver, Resolver,
    ResolverFactory, TimeoutResolver,
};
use crate::tcp::chain_builder::{build_client_chain_group, build_direct_chain_group};

/// Registry of resolved DNS groups with lazy default resolver.
pub struct DnsRegistry {
    groups: FxHashMap<String, Arc<dyn Resolver>>,
    /// Default resolver, created lazily only if needed.
    default_resolver: Option<Arc<dyn Resolver>>,
    /// The fake IP responder of each group that has one, shared by every
    /// listener naming the group. Kept apart from `groups` so a group used
    /// as another's bootstrap is the plain resolver.
    fake_ips: FxHashMap<String, Arc<crate::dns::fake_ip::FakeIpResponder>>,
    /// One responder per inline `fake_ip`, under the context name validation
    /// gave the `dns:` block: the same object however often the block's
    /// resolver is asked for.
    inline_fake_ips: FxHashMap<String, Arc<crate::dns::fake_ip::FakeIpResponder>>,
}

impl DnsRegistry {
    /// Creates a new empty registry.
    pub fn new() -> Self {
        Self {
            groups: FxHashMap::default(),
            default_resolver: None,
            fake_ips: FxHashMap::default(),
            inline_fake_ips: FxHashMap::default(),
        }
    }

    /// Register a DNS group.
    pub fn register(&mut self, name: String, resolver: Arc<dyn Resolver>) {
        self.groups.insert(name, resolver);
    }

    /// Get a resolver by group name, returns None if not found.
    pub fn get_by_name(&self, name: &str) -> Option<Arc<dyn Resolver>> {
        self.groups.get(name).cloned()
    }

    /// Get or create the default resolver (CachingNativeResolver).
    /// Used when a server has no `dns` field configured.
    pub fn get_or_create_default(&mut self) -> Arc<dyn Resolver> {
        self.default_resolver
            .get_or_insert_with(|| Arc::new(CachingNativeResolver::new()))
            .clone()
    }

    /// Get the resolver for a TUN entry's dns field.
    ///
    /// Unlike listeners, a TUN without a `dns:` block gets a FRESH system
    /// resolver rather than the caching default. The honoured-dns change
    /// promised "without the block nothing changes", and the caching
    /// default's flat age (record TTLs ignored; 60 seconds) would break it:
    /// a WireGuard/AmneziaWG tunnel rebuild would resolve a failed-over
    /// endpoint hostname to its dead pre-failover address for that long,
    /// where the old in-place resolver followed the provider on the next
    /// lookup.
    ///
    /// Nor does it share lookups in flight: a lookup begun on a network
    /// that has just gone away can hang until the OS gives up, and a flow
    /// or tunnel rebuild after a Wi-Fi/cellular switch that joined it would
    /// inherit the failure instead of asking the new network.
    pub fn get_for_tun(&mut self, dns: Option<&DnsConfig>) -> Arc<dyn Resolver> {
        match dns.and_then(|c| c.resolved_group()) {
            Some(_) => self.get_for_server(dns),
            // The plain system resolver, as before `dns:` blocks; wrapped
            // when the TUN's own fake_ip gives it a pool.
            None => self.with_fake_ip(Arc::new(NativeResolver::new()), dns),
        }
    }

    /// The responder `dns` names: its own context, else its group's.
    fn responder_for(
        &self,
        dns: Option<&DnsConfig>,
    ) -> Option<Arc<crate::dns::fake_ip::FakeIpResponder>> {
        let dns = dns?;
        if let Some(context) = &dns.fake_ip_context {
            return Some(
                self.inline_fake_ips
                    .get(context)
                    .cloned()
                    .expect("inline fake_ip context should be built (validated)"),
            );
        }
        dns.resolved_group()
            .and_then(|group_name| self.fake_ips.get(group_name).cloned())
    }

    fn with_fake_ip(
        &self,
        resolver: Arc<dyn Resolver>,
        dns: Option<&DnsConfig>,
    ) -> Arc<dyn Resolver> {
        match self.responder_for(dns) {
            Some(responder) => Arc::new(crate::dns::fake_ip::FakeIpResolver::new(
                resolver, responder,
            )),
            None => resolver,
        }
    }

    /// Get resolver for a server config's dns field.
    /// After validation, dns.servers should be a single group name or None.
    ///
    /// With fake IP on, the resolver comes wrapped in a `FakeIpResolver`
    /// carrying the block's own context, else the named group's shared one.
    pub fn get_for_server(&mut self, dns: Option<&DnsConfig>) -> Arc<dyn Resolver> {
        let resolver = match dns.and_then(|c| c.resolved_group()) {
            Some(group_name) => self
                .groups
                .get(group_name)
                .cloned()
                .expect("dns group should exist (validated)"),
            None => self.get_or_create_default(),
        };
        self.with_fake_ip(resolver, dns)
    }
}

impl Default for DnsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Wrap a resolver with optional timeout and return as Arc<dyn Resolver>.
/// Wraps in TimeoutResolver before Arc to avoid double indirection.
fn wrap_resolver<T: Resolver + 'static>(resolver: T, timeout_secs: u32) -> Arc<dyn Resolver> {
    if timeout_secs > 0 {
        Arc::new(TimeoutResolver::with_timeout(
            resolver,
            Duration::from_secs(timeout_secs as u64),
        ))
    } else {
        Arc::new(resolver)
    }
}

/// Cloneable build plan that can reconstruct a fresh hickory resolver.
/// Used as the factory for RefreshingResolver so that refresh discards
/// the old hickory connection pool entirely.
#[derive(Clone)]
struct HickoryResolverPlan {
    parsed_url: ParsedDnsUrl,
    chain_group: Arc<crate::client_proxy_chain::ClientChainGroup>,
    bootstrap_resolver: Arc<dyn Resolver>,
    chain_key: String,
    bootstrap_key: Option<String>,
    options: HickoryResolverOptions,
    timeout_secs: u32,
    connect_timeout_secs: u32,
    native_cache_secs: u32,
    description: String,
}

impl HickoryResolverPlan {
    fn is_system(&self) -> bool {
        matches!(self.parsed_url, ParsedDnsUrl::System)
    }

    /// The entry this plan describes, its server's name resolved now through
    /// the bootstrap, so that a rebuild follows a server that has moved
    /// (DN-D2). A `system` plan's entry needs no lookup.
    async fn entry(&self) -> std::io::Result<ParsedDnsServerEntry> {
        let resolved_ip = match self.parsed_url.hostname() {
            Some(hostname) => {
                let location = crate::address::NetLocation::new(
                    crate::address::Address::Hostname(hostname.to_string()),
                    0,
                );
                let addrs = self
                    .bootstrap_resolver
                    .resolve_location(&location)
                    .await
                    .map_err(|e| {
                        std::io::Error::other(format!(
                            "failed to resolve DNS server hostname '{}': {}",
                            hostname, e
                        ))
                    })?;
                // A lookup can succeed with nothing in it (an answer of only
                // unspecified addresses is filtered to none). On a rebuild
                // that is an error the refreshing resolver keeps the working
                // resolver over, not an index to panic on.
                let first = addrs.first().ok_or_else(|| {
                    std::io::Error::other(format!(
                        "bootstrap lookup returned no addresses for '{hostname}'"
                    ))
                })?;
                Some(first.ip())
            }
            None => None,
        };
        let server = self
            .parsed_url
            .to_parsed_server(resolved_ip)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        let entry = ParsedDnsServerEntry::new(
            server,
            self.chain_group.clone(),
            self.bootstrap_resolver.clone(),
            self.options.ip_strategy,
            self.timeout_secs,
            self.connect_timeout_secs,
            self.options.attempts,
            self.native_cache_secs,
        );
        Ok(entry)
    }

    fn is_pool_compatible_with(&self, other: &Self) -> bool {
        self.chain_key == other.chain_key
            && self.bootstrap_key == other.bootstrap_key
            && self.options == other.options
    }

    async fn resolved_name_server_pairs(
        &self,
    ) -> std::io::Result<Vec<(std::net::IpAddr, hickory_resolver::config::ConnectionConfig)>> {
        let resolved_ips = match self.parsed_url.hostname() {
            Some(hostname) => {
                let location = crate::address::NetLocation::new(
                    crate::address::Address::Hostname(hostname.to_string()),
                    0,
                );
                let addrs = self
                    .bootstrap_resolver
                    .resolve_location(&location)
                    .await
                    .map_err(|e| {
                        std::io::Error::other(format!(
                            "failed to resolve DNS server hostname '{}': {}",
                            hostname, e
                        ))
                    })?;
                if addrs.is_empty() {
                    return Err(std::io::Error::other(format!(
                        "bootstrap lookup returned no addresses for '{}'",
                        hostname
                    )));
                }

                let mut ips = Vec::with_capacity(addrs.len());
                for ip in addrs.into_iter().map(|addr| addr.ip()) {
                    if !ips.contains(&ip) {
                        ips.push(ip);
                    }
                }

                log::debug!(
                    "HickoryResolverPlan ({}): resolved {} to {:?}",
                    self.description,
                    hostname,
                    ips
                );
                ips
            }
            None => vec![],
        };

        if resolved_ips.is_empty() {
            let server = self
                .parsed_url
                .to_parsed_server(None)
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            return server_to_ns_config(&server)
                .map(|pair| vec![pair])
                .ok_or_else(|| {
                    std::io::Error::other(format!(
                        "resolver plan '{}' did not produce a nameserver config",
                        self.description
                    ))
                });
        }

        let mut ns_pairs = Vec::with_capacity(resolved_ips.len());
        for ip in resolved_ips {
            let server = self
                .parsed_url
                .to_parsed_server(Some(ip))
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            let pair = server_to_ns_config(&server).ok_or_else(|| {
                std::io::Error::other(format!(
                    "resolver plan '{}' did not produce a nameserver config",
                    self.description
                ))
            })?;
            ns_pairs.push(pair);
        }

        Ok(ns_pairs)
    }

    /// Build a fresh resolver, re-resolving hostname upstreams if needed.
    /// When a hostname resolves to multiple IPs, all are expanded into
    /// nameserver configs inside a single pooled hickory resolver.
    async fn build(&self) -> std::io::Result<Arc<dyn Resolver>> {
        let ns_pairs = self.resolved_name_server_pairs().await?;

        if ns_pairs.len() > 1 {
            let resolver = HickoryResolver::build_pooled(
                ns_pairs,
                self.chain_group.clone(),
                self.bootstrap_resolver.clone(),
                self.options,
                self.description.clone(),
            )?;
            return Ok(Arc::new(resolver));
        }

        // Single IP or IP-literal upstream: build normally.
        let resolved_ip = ns_pairs.first().map(|(ip, _)| *ip);
        let server = self
            .parsed_url
            .to_parsed_server(resolved_ip)
            .map_err(|e| std::io::Error::other(e.to_string()))?;

        build_hickory_from_server(
            server,
            self.chain_group.clone(),
            self.bootstrap_resolver.clone(),
            self.options,
        )
    }
}

async fn try_build_hickory_pool_from_plans(
    plans: &[HickoryResolverPlan],
) -> std::io::Result<Option<Arc<dyn Resolver>>> {
    if plans.len() < 2 {
        return Ok(None);
    }

    let first = &plans[0];
    if plans
        .iter()
        .skip(1)
        .any(|plan| !plan.is_pool_compatible_with(first))
    {
        return Ok(None);
    }

    let mut ns_pairs = Vec::new();
    for plan in plans {
        ns_pairs.extend(plan.resolved_name_server_pairs().await?);
    }

    if ns_pairs.len() < 2 {
        return Ok(None);
    }

    let descriptions: Vec<String> = plans.iter().map(|plan| plan.description.clone()).collect();
    let description = format!("pool[{}]", descriptions.join(", "));
    let resolver = HickoryResolver::build_pooled(
        ns_pairs,
        first.chain_group.clone(),
        first.bootstrap_resolver.clone(),
        first.options,
        description,
    )?;
    Ok(Some(Arc::new(resolver)))
}

async fn build_hickory_resolver_group(
    plans: &[HickoryResolverPlan],
) -> std::io::Result<Arc<dyn Resolver>> {
    if plans.is_empty() {
        return Err(std::io::Error::other(
            "no hickory resolver plans configured",
        ));
    }

    if let Some(pooled) = try_build_hickory_pool_from_plans(plans).await? {
        return Ok(pooled);
    }

    let mut resolvers = Vec::with_capacity(plans.len());
    for plan in plans {
        resolvers.push(plan.build().await?);
    }

    if resolvers.len() == 1 {
        Ok(resolvers.pop().unwrap())
    } else {
        Ok(Arc::new(CompositeResolver::new(resolvers)))
    }
}

/// Construct a single HickoryResolver from a ParsedDnsServer.
fn build_hickory_from_server(
    server: ParsedDnsServer,
    chain: Arc<crate::client_proxy_chain::ClientChainGroup>,
    bootstrap: Arc<dyn Resolver>,
    options: HickoryResolverOptions,
) -> std::io::Result<Arc<dyn Resolver>> {
    Ok(match server {
        ParsedDnsServer::System => {
            unreachable!("system resolver should not use hickory build path")
        }
        ParsedDnsServer::Udp { addr } => {
            Arc::new(HickoryResolver::udp(addr, chain, bootstrap, options)?)
        }
        ParsedDnsServer::Tcp { addr } => {
            Arc::new(HickoryResolver::tcp(addr, chain, bootstrap, options)?)
        }
        ParsedDnsServer::Tls { addr, server_name } => Arc::new(HickoryResolver::tls(
            addr,
            server_name,
            chain,
            bootstrap,
            options,
        )?),
        ParsedDnsServer::Https {
            addr,
            server_name,
            path,
        } => Arc::new(HickoryResolver::https(
            addr,
            server_name,
            path,
            chain,
            bootstrap,
            options,
        )?),
        ParsedDnsServer::H3 {
            addr,
            server_name,
            path,
        } => Arc::new(HickoryResolver::h3(
            addr,
            server_name,
            path,
            chain,
            bootstrap,
            options,
        )?),
    })
}

/// Convert a ParsedDnsServer to (IpAddr, ConnectionConfig) for pooling.
/// Returns None for System resolvers (cannot be pooled).
fn server_to_ns_config(
    server: &ParsedDnsServer,
) -> Option<(std::net::IpAddr, hickory_resolver::config::ConnectionConfig)> {
    use hickory_resolver::config::{ConnectionConfig, ProtocolConfig};

    match server {
        ParsedDnsServer::System => None,
        ParsedDnsServer::Udp { addr } => {
            let mut cc = ConnectionConfig::udp();
            cc.port = addr.port();
            Some((addr.ip(), cc))
        }
        ParsedDnsServer::Tcp { addr } => {
            let mut cc = ConnectionConfig::tcp();
            cc.port = addr.port();
            Some((addr.ip(), cc))
        }
        ParsedDnsServer::Tls { addr, server_name } => {
            let mut cc = ConnectionConfig::tls(server_name.clone());
            cc.port = addr.port();
            Some((addr.ip(), cc))
        }
        ParsedDnsServer::Https {
            addr,
            server_name,
            path,
        } => {
            let mut cc = ConnectionConfig::https(server_name.clone(), Some(path.clone()));
            cc.port = addr.port();
            Some((addr.ip(), cc))
        }
        ParsedDnsServer::H3 {
            addr,
            server_name,
            path,
        } => {
            let protocol = ProtocolConfig::H3 {
                server_name: server_name.clone(),
                path: path.clone(),
                disable_grease: true,
            };
            let mut cc = ConnectionConfig::new(protocol);
            cc.port = addr.port();
            Some((addr.ip(), cc))
        }
    }
}

/// Build a resolver from parsed DNS server entries.
/// When all entries are hickory-backed with compatible settings, pools them
/// into a single hickory resolver instead of using CompositeResolver.
pub fn build_resolver(entries: Vec<ParsedDnsServerEntry>) -> std::io::Result<Arc<dyn Resolver>> {
    if entries.is_empty() {
        return Err(std::io::Error::other("no DNS servers configured"));
    }

    // Try to pool all hickory-backed entries into one resolver.
    if let Some(pooled) = try_build_hickory_pool(&entries)? {
        return Ok(pooled);
    }

    // Fallback: build individual resolvers and composite them.
    let mut resolvers: Vec<Arc<dyn Resolver>> = Vec::with_capacity(entries.len());

    for entry in entries {
        let timeout_secs = entry.timeout_secs;

        let options = HickoryResolverOptions {
            ip_strategy: entry.ip_strategy,
            request_timeout: (timeout_secs > 0).then(|| Duration::from_secs(timeout_secs as u64)),
            connect_timeout: Duration::from_secs(entry.connect_timeout_secs as u64),
            attempts: entry.attempts,
        };

        let resolver: Arc<dyn Resolver> = match entry.server {
            // An explicit `system` asks the OS each time unless the config
            // sets an age (upstream cfal/shoes#227); the implicit default
            // is the 60-second CachingNativeResolver.
            ParsedDnsServer::System if entry.native_cache_secs > 0 => wrap_resolver(
                CachingNativeResolver::with_timeout(entry.native_cache_secs.into()),
                timeout_secs,
            ),
            ParsedDnsServer::System => wrap_resolver(NativeResolver::new(), timeout_secs),
            server => build_hickory_from_server(
                server,
                entry.client_chain,
                entry.bootstrap_resolver,
                options,
            )?,
        };

        resolvers.push(resolver);
    }

    if resolvers.len() == 1 {
        Ok(resolvers.pop().unwrap())
    } else {
        Ok(Arc::new(CompositeResolver::new(resolvers)))
    }
}

/// Attempt to build a single pooled hickory resolver from all entries.
/// Returns None if entries contain system resolvers, or if entries have
/// heterogeneous settings (different chains, bootstraps, timeouts, etc.).
/// Pooling is only safe when all entries share the same runtime config,
/// since a single hickory resolver applies one set of options to all its
/// nameservers.
fn try_build_hickory_pool(
    entries: &[ParsedDnsServerEntry],
) -> std::io::Result<Option<Arc<dyn Resolver>>> {
    if entries.is_empty() || entries.len() < 2 {
        return Ok(None);
    }

    let first = &entries[0];

    // All entries must be hickory-backed (no system resolvers) and share
    // the same chain group, bootstrap, and tuning options.
    let mut ns_pairs = Vec::with_capacity(entries.len());
    for entry in entries {
        match server_to_ns_config(&entry.server) {
            Some(pair) => ns_pairs.push(pair),
            None => return Ok(None),
        }

        if !Arc::ptr_eq(&entry.client_chain, &first.client_chain) {
            return Ok(None);
        }
        if !Arc::ptr_eq(&entry.bootstrap_resolver, &first.bootstrap_resolver) {
            return Ok(None);
        }
        if entry.timeout_secs != first.timeout_secs
            || entry.connect_timeout_secs != first.connect_timeout_secs
            || entry.attempts != first.attempts
            || entry.ip_strategy != first.ip_strategy
        {
            return Ok(None);
        }
    }

    let timeout_secs = first.timeout_secs;
    let options = HickoryResolverOptions {
        ip_strategy: first.ip_strategy,
        request_timeout: (timeout_secs > 0).then(|| Duration::from_secs(timeout_secs as u64)),
        connect_timeout: Duration::from_secs(first.connect_timeout_secs as u64),
        attempts: first.attempts,
    };

    let descriptions: Vec<String> = entries.iter().map(|e| format!("{:?}", e.server)).collect();
    let description = format!("pool[{}]", descriptions.join(", "));

    let resolver = HickoryResolver::build_pooled(
        ns_pairs,
        first.client_chain.clone(),
        first.bootstrap_resolver.clone(),
        options,
        description,
    )?;

    Ok(Some(Arc::new(resolver)))
}

/// Build DnsRegistry from expanded DNS groups.
///
/// Groups must be in topological order (bootstrap dependencies first).
/// This function:
/// - Builds client chain groups from expanded client chains
/// - Resolves hostnames in DNS URLs using bootstrap resolvers
/// - Creates HickoryResolver instances
pub async fn build_dns_registry(
    groups: Vec<ExpandedDnsGroup>,
    inline_fake_ips: Vec<(String, crate::config::FakeIpConfig)>,
) -> std::io::Result<DnsRegistry> {
    let mut registry = DnsRegistry::new();

    for (context, config) in inline_fake_ips {
        let responder = crate::dns::fake_ip::responder_from_config(&config, &context)?;
        registry.inline_fake_ips.insert(context, responder);
    }

    for group in groups {
        let resolver = build_resolver_from_specs(&group.specs, &registry, &group.name).await?;
        if let Some(config) = &group.fake_ip {
            let responder = crate::dns::fake_ip::responder_from_config(
                config,
                &format!("dns_group '{}'", group.name),
            )?;
            registry.fake_ips.insert(group.name.clone(), responder);
        }
        registry.register(group.name, resolver);
    }

    Ok(registry)
}

/// Build a resolver from expanded DNS specs, wrapping hickory-backed groups
/// in RefreshingResolver for stale connection mitigation.
async fn build_resolver_from_specs(
    specs: &[ExpandedDnsSpec],
    registry: &DnsRegistry,
    group_name: &str,
) -> std::io::Result<Arc<dyn Resolver>> {
    if specs.is_empty() {
        return Err(std::io::Error::other("no DNS servers configured"));
    }

    let mut entries: Vec<ParsedDnsServerEntry> = Vec::with_capacity(specs.len());
    let mut plans: Vec<HickoryResolverPlan> = Vec::with_capacity(specs.len());

    for spec in specs {
        let (entry, plan) = build_entry_and_plan(spec, registry).await?;
        plans.push(plan);
        entries.push(entry);
    }

    // A group with no hickory-backed resolver has nothing to rebuild.
    if plans.iter().all(HickoryResolverPlan::is_system) {
        return build_resolver(entries);
    }

    // Rebuilt by a RefreshingResolver on its policy, asking the bootstrap
    // again each time (DN-D2). A group of hickory resolvers alone is
    // rebuilt from its plans, which pools them; one with a system resolver
    // among them is rebuilt entry by entry, since the system resolver
    // cannot be pooled. Mixed groups used to be built once and kept.
    let factory: ResolverFactory = if plans.iter().any(HickoryResolverPlan::is_system) {
        Arc::new(move || {
            let plans = plans.clone();
            Box::pin(async move {
                let mut entries = Vec::with_capacity(plans.len());
                for plan in &plans {
                    entries.push(plan.entry().await?);
                }
                build_resolver(entries)
            })
        })
    } else {
        Arc::new(move || {
            let plans = plans.clone();
            Box::pin(async move { build_hickory_resolver_group(&plans).await })
        })
    };

    let policy = RefreshPolicy {
        max_idle: Duration::from_secs(60),
        max_age: Duration::from_secs(10 * 60),
        retry_after_failure: Duration::from_secs(30),
        retry_once_after_refresh: true,
    };

    let refreshing = RefreshingResolver::new(factory, policy, group_name.to_string()).await?;
    Ok(Arc::new(refreshing))
}

/// Build a ParsedDnsServerEntry and the HickoryResolverPlan that can rebuild
/// it on refresh from an expanded spec.
async fn build_entry_and_plan(
    spec: &ExpandedDnsSpec,
    registry: &DnsRegistry,
) -> std::io::Result<(ParsedDnsServerEntry, HickoryResolverPlan)> {
    // Parsed during config expansion.
    let parsed_url = spec.parsed_url.clone();

    // Build client chain group
    let chain_resolver = Arc::new(NativeResolver::new());
    let chain_group = if spec.client_chains.is_empty() {
        Arc::new(build_direct_chain_group(chain_resolver))
    } else {
        let chains = if spec.client_chains.len() == 1 {
            NoneOrSome::One(spec.client_chains[0].clone())
        } else {
            NoneOrSome::Some(spec.client_chains.clone())
        };
        Arc::new(build_client_chain_group(chains, chain_resolver))
    };

    // Build or get bootstrap resolver
    let bootstrap_resolver: Arc<dyn Resolver> = match &spec.bootstrap {
        // Built before this one: groups are in bootstrap-dependency order.
        Some(DnsBootstrap::Group(name)) => registry.get_by_name(name).ok_or_else(|| {
            std::io::Error::other(format!("bootstrap dns group '{name}' was not built"))
        })?,
        Some(DnsBootstrap::Url {
            parsed: bootstrap_parsed,
            ..
        }) => {
            let bootstrap_server = bootstrap_parsed
                .to_parsed_server(None)
                .map_err(|e| std::io::Error::other(e.to_string()))?;

            let native = Arc::new(NativeResolver::new());
            let direct_chain = Arc::new(build_direct_chain_group(native.clone()));
            // Bootstrap resolvers use default timeout (10s) and 2 attempts
            let bootstrap_entry = ParsedDnsServerEntry::new(
                bootstrap_server,
                direct_chain,
                native,
                super::IpStrategy::default(),
                10, // Default timeout for bootstrap
                5,  // Default connect timeout for bootstrap
                2,  // Default attempts for bootstrap,
                0,
            );
            build_resolver(vec![bootstrap_entry])?
        }
        None => Arc::new(NativeResolver::new()),
    };

    let timeout_secs = spec.timeout_secs;
    let options = HickoryResolverOptions {
        ip_strategy: spec.ip_strategy,
        request_timeout: (timeout_secs > 0).then(|| Duration::from_secs(timeout_secs as u64)),
        connect_timeout: Duration::from_secs(spec.connect_timeout_secs as u64),
        attempts: spec.attempts,
    };

    let plan = HickoryResolverPlan {
        parsed_url,
        chain_group,
        bootstrap_resolver,
        chain_key: serde_yaml::to_string(&spec.client_chains).map_err(|e| {
            std::io::Error::other(format!("failed to serialize client_chains: {e}"))
        })?,
        bootstrap_key: spec.bootstrap.as_ref().map(|b| b.as_str().to_string()),
        options,
        timeout_secs: spec.timeout_secs,
        connect_timeout_secs: spec.connect_timeout_secs,
        native_cache_secs: spec.native_cache_secs,
        description: spec.url.clone(),
    };

    let entry = plan.entry().await?;
    Ok((entry, plan))
}

#[cfg(test)]
mod tests {
    /// The no-dns TUN default must be the plain system resolver: the caching
    /// default's flat age would pin a failed-over WG/AWG endpoint to its dead
    /// address across rebuilds, and sharing lookups in flight would hand a
    /// lookup stranded by a network change to every flow after it.
    #[test]
    fn a_tun_without_dns_gets_a_fresh_uncached_resolver() {
        let mut registry = super::DnsRegistry::new();
        let default = registry.get_or_create_default();
        let tun = registry.get_for_tun(None);
        assert!(
            !std::sync::Arc::ptr_eq(&default, &tun),
            "the TUN default must not be the caching default"
        );
        assert!(
            format!("{tun:?}").contains("NativeResolver")
                && !format!("{tun:?}").contains("Caching"),
            "the TUN default is the plain system resolver: {tun:?}"
        );
    }

    use super::*;
    use crate::config::ExpandedDnsSpec;

    /// Which native resolver each DNS shape gets: no block or an empty one,
    /// the shared 60-second cache; an explicit `system`, no cache unless it
    /// names an age. Adapted from upstream cfal/shoes#227.
    #[tokio::test]
    async fn native_cache_policy_distinguishes_implicit_and_explicit_system() {
        for (dns, window) in [
            ("", Some(60)),
            ("dns: {servers: system}", None),
            ("dns: {servers: {url: system}}", None),
            ("dns: {servers: {url: system, native_cache_secs: 0}}", None),
            (
                "dns: {servers: {url: system, native_cache_secs: 7}}",
                Some(7),
            ),
        ] {
            let yaml =
                format!("- address: '127.0.0.1:1080'\n  protocol: {{type: socks}}\n  {dns}\n");
            let configs =
                crate::config::create_server_configs(serde_yaml::from_str(&yaml).unwrap()).unwrap();
            let mut registry = build_dns_registry(configs.dns_groups, configs.inline_fake_ips)
                .await
                .unwrap();
            let crate::config::Config::Server(server) = &configs.configs[0] else {
                panic!("expected a server")
            };
            let resolver = registry.get_for_server(server.dns.as_ref());
            let debug = format!("{resolver:?}");
            match window {
                Some(seconds) => assert!(
                    debug.contains(&format!(
                        "CachingNativeResolver {{ result_timeout_secs: {seconds} }}"
                    )),
                    "{dns}: {debug}"
                ),
                None => assert!(!debug.contains("CachingNativeResolver"), "{dns}: {debug}"),
            }
        }
    }

    /// Listeners naming a group with `fake_ip` share its pool; a listener's
    /// own `fake_ip` gets a pool of its own; a group without one gives none.
    #[tokio::test]
    async fn fake_ip_pools_are_shared_by_group_and_private_inline() {
        let yaml = "\
- dns_group: fake
  dns_servers: system
  fake_ip: {network: 198.18.0.0/16}
- address: '127.0.0.1:1080'
  protocol: {type: socks}
  dns: {servers: fake}
- address: '127.0.0.1:1081'
  protocol: {type: socks}
  dns: {servers: fake}
- address: '127.0.0.1:1082'
  protocol: {type: socks}
  dns: {servers: system, fake_ip: {network: 198.19.0.0/16}}
- address: '127.0.0.1:1083'
  protocol: {type: socks}
  dns: {servers: system}
";
        let configs =
            crate::config::create_server_configs(serde_yaml::from_str(yaml).unwrap()).unwrap();
        let mut registry = build_dns_registry(configs.dns_groups, configs.inline_fake_ips)
            .await
            .unwrap();
        let responders: Vec<_> = configs
            .configs
            .iter()
            .map(|config| {
                let crate::config::Config::Server(server) = config else {
                    panic!("expected a server")
                };
                registry
                    .get_for_server(server.dns.as_ref())
                    .fake_ip()
                    .cloned()
            })
            .collect();
        let shared_a = responders[0].as_ref().expect("the group's pool");
        let shared_b = responders[1].as_ref().expect("the group's pool");
        assert!(Arc::ptr_eq(shared_a, shared_b), "one pool for the group");
        let private = responders[2].as_ref().expect("its own pool");
        assert!(!Arc::ptr_eq(shared_a, private));
        assert!(responders[3].is_none(), "no fake_ip, no pool");
    }

    /// A one-item list naming a group is that group: it shares the group's
    /// pool, and a TUN naming a fake-IP group that way shares it too.
    #[tokio::test]
    async fn a_one_item_list_naming_a_group_is_that_group() {
        let yaml = "\
- dns_group: fake
  dns_servers: system
  fake_ip: {}
- address: '127.0.0.1:1080'
  protocol: {type: socks}
  dns: {servers: fake}
- address: '127.0.0.1:1081'
  protocol: {type: socks}
  dns: {servers: [fake]}
";
        let configs =
            crate::config::create_server_configs(serde_yaml::from_str(yaml).unwrap()).unwrap();
        let mut registry = build_dns_registry(configs.dns_groups, configs.inline_fake_ips)
            .await
            .unwrap();
        let pools: Vec<_> = configs
            .configs
            .iter()
            .map(|config| {
                let crate::config::Config::Server(server) = config else {
                    panic!("expected a server")
                };
                registry
                    .get_for_server(server.dns.as_ref())
                    .fake_ip()
                    .cloned()
                    .unwrap()
            })
            .collect();
        assert!(Arc::ptr_eq(&pools[0], &pools[1]));
    }

    /// A TUN's top-level `fake_ip` is its dns block's: the registry builds
    /// one context for the session, the same object on every ask; naming a
    /// group with a pool shares the group's; set in both places is refused.
    #[tokio::test]
    async fn a_tun_shares_or_owns_a_pool_like_a_listener() {
        let device = if cfg!(target_os = "macos") {
            "utun99"
        } else {
            "shoestest0"
        };
        let yaml = format!(
            "- dns_group: fake\n  dns_servers: udp://1.1.1.1\n  fake_ip: {{}}\n\
             - address: '127.0.0.1:1080'\n  protocol: {{type: socks}}\n  dns: {{servers: fake}}\n\
             - device_name: {device}\n  address: 10.0.0.1\n  netmask: 255.255.255.0\n  \
             udp_enabled: true\n  dns: {{servers: [fake]}}\n\
             - device_name: {device}\n  address: 10.0.0.2\n  netmask: 255.255.255.0\n  \
             udp_enabled: true\n  fake_ip: {{network: 198.19.0.0/16}}\n"
        );
        let configs =
            crate::config::create_server_configs(serde_yaml::from_str(&yaml).unwrap()).unwrap();
        assert_eq!(
            configs.inline_fake_ips.len(),
            1,
            "one inline context, the second TUN's"
        );
        let mut registry = build_dns_registry(configs.dns_groups, configs.inline_fake_ips)
            .await
            .unwrap();
        let mut responders = Vec::new();
        for config in &configs.configs {
            let resolver = match config {
                crate::config::Config::Server(server) => {
                    registry.get_for_server(server.dns.as_ref())
                }
                crate::config::Config::TunServer(tun) => {
                    assert!(tun.fake_ip.is_none(), "moved onto the dns block");
                    registry.get_for_tun(tun.dns.as_ref())
                }
                _ => panic!("unexpected config"),
            };
            responders.push(resolver.fake_ip().cloned().expect("a pool"));
        }
        assert!(
            Arc::ptr_eq(&responders[0], &responders[1]),
            "the group's pool, shared"
        );
        assert!(
            !Arc::ptr_eq(&responders[0], &responders[2]),
            "the TUN's own pool"
        );
        let crate::config::Config::TunServer(own) = &configs.configs[2] else {
            panic!()
        };
        let again = registry
            .get_for_tun(own.dns.as_ref())
            .fake_ip()
            .cloned()
            .unwrap();
        assert!(
            Arc::ptr_eq(&responders[2], &again),
            "the same context on a second ask"
        );

        let twice = format!(
            "- device_name: {device}\n  address: 10.0.0.1\n  netmask: 255.255.255.0\n  \
             udp_enabled: true\n  fake_ip: {{}}\n  dns: {{fake_ip: {{}}}}\n"
        );
        let err = crate::config::create_server_configs(serde_yaml::from_str(&twice).unwrap())
            .err()
            .expect("refused");
        assert!(err.to_string().contains("set it once"), "{err}");
    }

    /// A group with fake_ip named inside a longer list, or listed by another
    /// group, would lose its pool silently: refused, with the group named.
    #[test]
    fn a_fake_ip_group_composed_into_another_is_refused() {
        for (yaml, needle) in [
            (
                "- dns_group: fake\n  dns_servers: udp://1.1.1.1\n  fake_ip: {}\n\
                 - address: '127.0.0.1:1080'\n  protocol: {type: socks}\n  \
                 dns: {servers: [fake, udp://9.9.9.9]}\n",
                "name it alone",
            ),
            (
                "- dns_group: fake\n  dns_servers: udp://1.1.1.1\n  fake_ip: {}\n\
                 - dns_group: outer\n  dns_servers: [fake]\n\
                 - address: '127.0.0.1:1080'\n  protocol: {type: socks}\n  dns: {servers: outer}\n",
                "cannot be composed",
            ),
        ] {
            let err = crate::config::create_server_configs(serde_yaml::from_str(yaml).unwrap())
                .err()
                .unwrap_or_else(|| panic!("accepted:\n{yaml}"));
            assert!(err.to_string().contains(needle), "{err}");
            assert!(err.to_string().contains("'fake'"), "{err}");
        }
    }

    /// AnyTLS and NaiveProxy carry their streams and UDP outside the paths
    /// that answer port 53: fake IP on them would never hand out an address,
    /// an option accepted and not implemented, so it is refused, bare or
    /// inside the TLS, Reality or WebSocket that carries them in practice.
    #[test]
    fn fake_ip_on_anytls_and_naiveproxy_listeners_is_refused() {
        const ANYTLS: &str = "{type: anytls, users: [{name: u, password: p}]}";
        const NAIVE: &str = "{type: naiveproxy, users: [{username: u, password: p}]}";
        let in_tls = |inner: &str| {
            format!(
                "{{type: tls, tls_targets: {{a.test: {{cert: c, key: k, protocol: {inner}}}}}}}"
            )
        };
        let in_reality = |inner: &str| {
            format!(
                "{{type: tls, reality_targets: {{a.test: {{private_key: k, short_ids: [''], \
                 dest: 'a.test:443', protocol: {inner}}}}}}}"
            )
        };
        let in_ws = |inner: &str| format!("{{type: ws, targets: [{{protocol: {inner}}}]}}");
        for (protocol, needle) in [
            (ANYTLS.to_string(), "an AnyTLS listener"),
            (NAIVE.to_string(), "a NaiveProxy listener"),
            (in_tls(ANYTLS), "an AnyTLS listener"),
            (in_tls(NAIVE), "a NaiveProxy listener"),
            (in_reality(NAIVE), "a NaiveProxy listener"),
            (in_tls(&in_ws(ANYTLS)), "an AnyTLS listener"),
        ] {
            let yaml = format!(
                "- address: '127.0.0.1:4443'\n  protocol: {protocol}\n  \
                 dns: {{servers: udp://1.1.1.1, fake_ip: {{}}}}\n"
            );
            let err = crate::config::create_server_configs(serde_yaml::from_str(&yaml).unwrap())
                .err()
                .unwrap_or_else(|| panic!("accepted:\n{yaml}"));
            assert!(err.to_string().contains(needle), "{err}");
        }
    }

    /// A tproxy listener's UDP session is keyed by the fake address and
    /// refreshes its mapping at most once a minute: with fake IP on, an idle
    /// timeout must stay that minute inside the pool's ten-minute reuse
    /// guard. The numbers are written out, so a bound computed wrongly from
    /// the constants fails here rather than agreeing with itself.
    #[test]
    fn a_tproxy_udp_timeout_past_the_reuse_guard_is_refused_with_fake_ip() {
        let yaml = |udp_timeout: u64| {
            format!(
                "- address: '127.0.0.1:51271'\n  transport: udp\n  \
                 protocol: {{type: tproxy, udp_timeout: {udp_timeout}}}\n  \
                 dns: {{servers: udp://1.1.1.1, fake_ip: {{}}}}\n"
            )
        };
        for refused in [541, 600] {
            let err =
                crate::config::create_server_configs(serde_yaml::from_str(&yaml(refused)).unwrap())
                    .err()
                    .unwrap_or_else(|| panic!("{refused} s accepted"));
            assert!(err.to_string().contains("udp_timeout"), "{err}");
        }
        // Elsewhere a tproxy listener is refused whatever its timeout: it
        // reads the original destination only Linux's TPROXY records.
        #[cfg(target_os = "linux")]
        crate::config::create_server_configs(serde_yaml::from_str(&yaml(540)).unwrap())
            .expect("540 s, the guard less one refresh interval, accepted");
    }

    /// A dns block with neither servers nor fake_ip would silently mean the
    /// default resolver: refused.
    #[test]
    fn an_empty_dns_block_is_refused() {
        let yaml = "- address: '127.0.0.1:1080'\n  protocol: {type: socks}\n  dns: {}\n";
        let err = crate::config::create_server_configs(serde_yaml::from_str(yaml).unwrap())
            .err()
            .expect("refused");
        assert!(
            err.to_string().contains("no servers and no fake_ip"),
            "{err}"
        );
    }

    /// Fake IP on a QUIC listener is refused, inline or through its group:
    /// its UDP relay routes outside the hooks that restore fake addresses.
    #[test]
    fn fake_ip_on_a_quic_listener_is_refused() {
        let quic = |dns: &str| {
            format!(
                "- dns_group: fake\n  dns_servers: udp://1.1.1.1\n  fake_ip: {{}}\n\
                 - address: '127.0.0.1:4443'\n  transport: quic\n  \
                 quic_settings: {{cert: cert.pem, key: key.pem}}\n  \
                 protocol: {{type: socks}}\n  {dns}\n"
            )
        };
        for dns in [
            "dns: {servers: fake}",
            "dns: {servers: udp://1.1.1.1, fake_ip: {}}",
        ] {
            let yaml = quic(dns);
            let err = crate::config::create_server_configs(serde_yaml::from_str(&yaml).unwrap())
                .err()
                .unwrap_or_else(|| panic!("accepted:\n{yaml}"));
            assert!(err.to_string().contains("QUIC listener"), "{err}");
        }
    }

    /// A bad network on a listener's block is caught at validation, and a
    /// TUN with a pool, its own or a group's, needs its UDP path.
    #[test]
    fn misplaced_or_malformed_fake_ip_is_refused() {
        let tun = |dns: &str| {
            format!(
                "- dns_group: fake\n  dns_servers: udp://1.1.1.1\n  fake_ip: {{}}\n\
                 - device_name: {name}\n  address: 10.0.0.1\n  netmask: 255.255.255.0\n  \
                 udp_enabled: false\n  {dns}\n",
                // A name each platform accepts (macOS wants utunN).
                name = if cfg!(target_os = "macos") {
                    "utun99"
                } else {
                    "shoestest0"
                }
            )
        };
        for (yaml, needle) in [
            (tun("dns: {servers: fake}"), "requires udp_enabled"),
            (
                tun("dns: {servers: udp://1.1.1.1, fake_ip: {}}"),
                "requires udp_enabled",
            ),
            (
                "- address: '127.0.0.1:1080'\n  protocol: {type: socks}\n  \
                 dns: {fake_ip: {network: not-a-cidr}}\n"
                    .to_string(),
                "fake_ip",
            ),
        ] {
            let err = crate::config::create_server_configs(serde_yaml::from_str(&yaml).unwrap())
                .err()
                .unwrap_or_else(|| panic!("accepted:\n{yaml}"));
            assert!(err.to_string().contains(needle), "{err}");
        }
    }

    /// `native_cache_secs` is for the OS resolver only.
    #[test]
    fn native_cache_secs_on_a_hickory_server_is_refused() {
        let yaml = "- address: '127.0.0.1:1080'\n  protocol: {type: socks}\n  \
                    dns: {servers: {url: 'udp://192.0.2.1', native_cache_secs: 5}}\n";
        let err = crate::config::create_server_configs(serde_yaml::from_str(yaml).unwrap())
            .err()
            .expect("refused");
        assert!(err.to_string().contains("native_cache_secs"), "{err}");
    }
    use crate::dns::parsed::{IpStrategy, ParsedDnsServer};
    use crate::resolver::NativeResolver;
    use crate::tcp::chain_builder::build_direct_chain_group;

    /// Helper to build a shared chain group and bootstrap resolver for tests.
    fn shared_test_deps() -> (
        Arc<crate::client_proxy_chain::ClientChainGroup>,
        Arc<dyn Resolver>,
    ) {
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let chain = Arc::new(build_direct_chain_group(resolver.clone()));
        (chain, resolver)
    }

    fn make_entry(
        server: ParsedDnsServer,
        chain: &Arc<crate::client_proxy_chain::ClientChainGroup>,
        bootstrap: &Arc<dyn Resolver>,
    ) -> ParsedDnsServerEntry {
        ParsedDnsServerEntry::new(
            server,
            chain.clone(),
            bootstrap.clone(),
            IpStrategy::default(),
            5,
            5,
            1,
            0,
        )
    }

    fn make_spec(url: &str) -> ExpandedDnsSpec {
        ExpandedDnsSpec {
            url: url.to_string(),
            parsed_url: ParsedDnsUrl::parse(url).unwrap(),
            client_chains: vec![],
            bootstrap: None,
            ip_strategy: IpStrategy::default(),
            timeout_secs: 5,
            connect_timeout_secs: 5,
            attempts: 1,
            native_cache_secs: 0,
        }
    }

    #[test]
    fn test_compatible_servers_are_pooled() {
        let (chain, bootstrap) = shared_test_deps();
        let entries = vec![
            make_entry(
                ParsedDnsServer::Udp {
                    addr: "8.8.8.8:53".parse().unwrap(),
                },
                &chain,
                &bootstrap,
            ),
            make_entry(
                ParsedDnsServer::Udp {
                    addr: "8.8.4.4:53".parse().unwrap(),
                },
                &chain,
                &bootstrap,
            ),
        ];

        let resolver = build_resolver(entries).unwrap();
        let debug = format!("{:?}", resolver);
        assert!(
            debug.contains("pool["),
            "compatible entries should be pooled into one HickoryResolver, got: {}",
            debug
        );
        assert!(
            !debug.contains("CompositeResolver"),
            "compatible entries should NOT produce CompositeResolver, got: {}",
            debug
        );
    }

    #[test]
    fn test_incompatible_timeout_prevents_pooling() {
        let (chain, bootstrap) = shared_test_deps();
        let mut entry_a = make_entry(
            ParsedDnsServer::Udp {
                addr: "8.8.8.8:53".parse().unwrap(),
            },
            &chain,
            &bootstrap,
        );
        entry_a.timeout_secs = 5;

        let mut entry_b = make_entry(
            ParsedDnsServer::Udp {
                addr: "8.8.4.4:53".parse().unwrap(),
            },
            &chain,
            &bootstrap,
        );
        entry_b.timeout_secs = 10;

        let resolver = build_resolver(vec![entry_a, entry_b]).unwrap();
        let debug = format!("{:?}", resolver);
        assert!(
            debug.contains("CompositeResolver"),
            "incompatible timeouts should fall back to CompositeResolver, got: {}",
            debug
        );
    }

    #[test]
    fn test_incompatible_attempts_prevents_pooling() {
        let (chain, bootstrap) = shared_test_deps();
        let mut entry_a = make_entry(
            ParsedDnsServer::Udp {
                addr: "8.8.8.8:53".parse().unwrap(),
            },
            &chain,
            &bootstrap,
        );
        entry_a.attempts = 1;

        let mut entry_b = make_entry(
            ParsedDnsServer::Udp {
                addr: "8.8.4.4:53".parse().unwrap(),
            },
            &chain,
            &bootstrap,
        );
        entry_b.attempts = 3;

        let resolver = build_resolver(vec![entry_a, entry_b]).unwrap();
        let debug = format!("{:?}", resolver);
        assert!(
            debug.contains("CompositeResolver"),
            "incompatible attempts should fall back to CompositeResolver, got: {}",
            debug
        );
    }

    #[test]
    fn test_incompatible_ip_strategy_prevents_pooling() {
        let (chain, bootstrap) = shared_test_deps();
        let mut entry_a = make_entry(
            ParsedDnsServer::Udp {
                addr: "8.8.8.8:53".parse().unwrap(),
            },
            &chain,
            &bootstrap,
        );
        entry_a.ip_strategy = IpStrategy::Ipv4Only;

        let mut entry_b = make_entry(
            ParsedDnsServer::Udp {
                addr: "8.8.4.4:53".parse().unwrap(),
            },
            &chain,
            &bootstrap,
        );
        entry_b.ip_strategy = IpStrategy::Ipv6Only;

        let resolver = build_resolver(vec![entry_a, entry_b]).unwrap();
        let debug = format!("{:?}", resolver);
        assert!(
            debug.contains("CompositeResolver"),
            "incompatible ip_strategy should fall back to CompositeResolver, got: {}",
            debug
        );
    }

    #[test]
    fn test_different_chain_groups_prevent_pooling() {
        let resolver: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let chain_a = Arc::new(build_direct_chain_group(resolver.clone()));
        let chain_b = Arc::new(build_direct_chain_group(resolver.clone()));

        let entry_a = make_entry(
            ParsedDnsServer::Udp {
                addr: "8.8.8.8:53".parse().unwrap(),
            },
            &chain_a,
            &resolver,
        );
        let entry_b = make_entry(
            ParsedDnsServer::Udp {
                addr: "8.8.4.4:53".parse().unwrap(),
            },
            &chain_b,
            &resolver,
        );

        let result = build_resolver(vec![entry_a, entry_b]).unwrap();
        let debug = format!("{:?}", result);
        assert!(
            debug.contains("CompositeResolver"),
            "different chain groups should fall back to CompositeResolver, got: {}",
            debug
        );
    }

    #[test]
    fn test_different_bootstrap_resolvers_prevent_pooling() {
        let (chain, _) = shared_test_deps();
        let bootstrap_a: Arc<dyn Resolver> = Arc::new(NativeResolver::new());
        let bootstrap_b: Arc<dyn Resolver> = Arc::new(NativeResolver::new());

        let entry_a = ParsedDnsServerEntry::new(
            ParsedDnsServer::Udp {
                addr: "8.8.8.8:53".parse().unwrap(),
            },
            chain.clone(),
            bootstrap_a,
            IpStrategy::default(),
            5,
            5,
            1,
            0,
        );
        let entry_b = ParsedDnsServerEntry::new(
            ParsedDnsServer::Udp {
                addr: "8.8.4.4:53".parse().unwrap(),
            },
            chain.clone(),
            bootstrap_b,
            IpStrategy::default(),
            5,
            5,
            1,
            0,
        );

        let result = build_resolver(vec![entry_a, entry_b]).unwrap();
        let debug = format!("{:?}", result);
        assert!(
            debug.contains("CompositeResolver"),
            "different bootstrap resolvers should fall back to CompositeResolver, got: {}",
            debug
        );
    }

    #[test]
    fn test_system_resolver_prevents_pooling() {
        let (chain, bootstrap) = shared_test_deps();
        let entries = vec![
            make_entry(ParsedDnsServer::System, &chain, &bootstrap),
            make_entry(
                ParsedDnsServer::Udp {
                    addr: "8.8.8.8:53".parse().unwrap(),
                },
                &chain,
                &bootstrap,
            ),
        ];

        let resolver = build_resolver(entries).unwrap();
        let debug = format!("{:?}", resolver);
        assert!(
            !debug.contains("pool["),
            "system resolver entry should prevent pooling, got: {}",
            debug
        );
    }

    #[test]
    fn test_single_entry_not_pooled() {
        let (chain, bootstrap) = shared_test_deps();
        let entries = vec![make_entry(
            ParsedDnsServer::Udp {
                addr: "8.8.8.8:53".parse().unwrap(),
            },
            &chain,
            &bootstrap,
        )];

        let resolver = build_resolver(entries).unwrap();
        let debug = format!("{:?}", resolver);
        // Single entry should not go through pooling (no benefit).
        assert!(
            !debug.contains("pool["),
            "single entry should not be pooled, got: {}",
            debug
        );
        assert!(
            !debug.contains("CompositeResolver"),
            "single entry should not be composited, got: {}",
            debug
        );
    }

    #[test]
    fn test_three_compatible_servers_pooled() {
        let (chain, bootstrap) = shared_test_deps();
        let entries = vec![
            make_entry(
                ParsedDnsServer::Udp {
                    addr: "8.8.8.8:53".parse().unwrap(),
                },
                &chain,
                &bootstrap,
            ),
            make_entry(
                ParsedDnsServer::Udp {
                    addr: "8.8.4.4:53".parse().unwrap(),
                },
                &chain,
                &bootstrap,
            ),
            make_entry(
                ParsedDnsServer::Tcp {
                    addr: "1.1.1.1:53".parse().unwrap(),
                },
                &chain,
                &bootstrap,
            ),
        ];

        let resolver = build_resolver(entries).unwrap();
        let debug = format!("{:?}", resolver);
        assert!(
            debug.contains("pool["),
            "three compatible entries should be pooled, got: {}",
            debug
        );
    }

    #[test]
    fn test_incompatible_connect_timeout_prevents_pooling() {
        let (chain, bootstrap) = shared_test_deps();
        let mut entry_a = make_entry(
            ParsedDnsServer::Udp {
                addr: "8.8.8.8:53".parse().unwrap(),
            },
            &chain,
            &bootstrap,
        );
        entry_a.connect_timeout_secs = 5;

        let mut entry_b = make_entry(
            ParsedDnsServer::Udp {
                addr: "8.8.4.4:53".parse().unwrap(),
            },
            &chain,
            &bootstrap,
        );
        entry_b.connect_timeout_secs = 2;

        let resolver = build_resolver(vec![entry_a, entry_b]).unwrap();
        let debug = format!("{:?}", resolver);
        assert!(
            debug.contains("CompositeResolver"),
            "incompatible connect_timeout should fall back to CompositeResolver, got: {}",
            debug
        );
    }

    #[tokio::test]
    async fn test_plan_group_pools_equivalent_specs_with_distinct_runtime_objects() {
        let registry = DnsRegistry::new();
        let spec_a = make_spec("udp://8.8.8.8");
        let spec_b = make_spec("udp://8.8.4.4");

        let (_, plan_a) = build_entry_and_plan(&spec_a, &registry).await.unwrap();
        let (_, plan_b) = build_entry_and_plan(&spec_b, &registry).await.unwrap();
        let plans = vec![plan_a, plan_b];

        let resolver = build_hickory_resolver_group(&plans).await.unwrap();
        let debug = format!("{:?}", resolver);
        assert!(
            debug.contains("pool["),
            "equivalent specs should pool through the refresh builder path, got: {}",
            debug
        );
        assert!(
            !debug.contains("CompositeResolver"),
            "equivalent specs should not de-pool into CompositeResolver, got: {}",
            debug
        );
    }

    #[tokio::test]
    async fn test_plan_group_falls_back_for_incompatible_specs() {
        let registry = DnsRegistry::new();
        let spec_a = make_spec("udp://8.8.8.8");
        let mut spec_b = make_spec("udp://8.8.4.4");
        spec_b.attempts = 3;

        let (_, plan_a) = build_entry_and_plan(&spec_a, &registry).await.unwrap();
        let (_, plan_b) = build_entry_and_plan(&spec_b, &registry).await.unwrap();
        let plans = vec![plan_a, plan_b];

        let resolver = build_hickory_resolver_group(&plans).await.unwrap();
        let debug = format!("{:?}", resolver);
        assert!(
            debug.contains("CompositeResolver"),
            "incompatible specs should fall back to CompositeResolver, got: {}",
            debug
        );
    }

    /// A bootstrap that answers with nothing is an error on a rebuild, not a
    /// panic: the refreshing resolver keeps the resolver it has.
    #[tokio::test]
    async fn an_empty_bootstrap_answer_is_an_error_not_a_panic() {
        #[derive(Debug)]
        struct Nothing;
        impl Resolver for Nothing {
            fn resolve_location(
                &self,
                _: &crate::address::NetLocation,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<Output = std::io::Result<Vec<std::net::SocketAddr>>>
                        + Send,
                >,
            > {
                Box::pin(async { Ok(vec![]) })
            }
        }
        let mut registry = DnsRegistry::new();
        registry.register("empty".to_string(), Arc::new(Nothing));
        let mut spec = make_spec("https://dns.example/dns-query");
        spec.bootstrap = Some(DnsBootstrap::Group("empty".to_string()));
        let err = match build_entry_and_plan(&spec, &registry).await {
            Ok(_) => panic!("an entry was built with no address"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("no addresses"), "{err}");
    }

    /// DN-D2: a group that puts the system resolver beside a hickory-backed
    /// one is rebuilt on the same policy as a pure hickory group, bootstrap
    /// included. It used to be built once and kept for the process's life.
    /// A group of only the system resolver has nothing to rebuild.
    #[tokio::test]
    async fn a_mixed_group_is_rebuilt_like_a_pure_one() {
        let registry = DnsRegistry::new();
        let mixed = [make_spec("udp://8.8.8.8"), make_spec("system")];
        let resolver = build_resolver_from_specs(&mixed, &registry, "mixed")
            .await
            .unwrap();
        let debug = format!("{resolver:?}");
        assert!(debug.contains("RefreshingResolver"), "{debug}");

        let system = [make_spec("system")];
        let resolver = build_resolver_from_specs(&system, &registry, "system")
            .await
            .unwrap();
        let debug = format!("{resolver:?}");
        assert!(!debug.contains("RefreshingResolver"), "{debug}");
    }
}
