//! Configuration validation - validates configs and creates final ServerConfigs.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "predates the lint; see the [lints] note in Cargo.toml"
)]

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

use crate::address::NetLocationMask;
use crate::dns::ParsedDnsUrl;
use crate::option_util::{NoneOrSome, OneOrSome};
use crate::reality::{decode_private_key, decode_short_id};
use crate::rule_set::RuleSet;
use crate::thread_util::get_num_threads;

use super::pem::{embed_optional_pem_from_map, embed_pem_from_map};
use super::types::{
    ClientChain, ClientChainHop, ClientConfig, ClientProxyConfig, Config, ConfigSelection,
    DEFAULT_REALITY_SHORT_ID, DnsBootstrap, DnsConfig, DnsConfigGroup, DnsServerSpec,
    ExpandedDnsGroup, ExpandedDnsSpec, HttpUpgradeServerConfig, ObfsConfig, PemSource,
    RuleActionConfig, RuleConfig, ServerConfig, ServerProxyConfig, ServerQuicConfig,
    ShadowTlsServerConfig, ShadowTlsServerHandshakeConfig, ShadowsocksConfig, TlsServerConfig,
    Transport, TunConfig, WebsocketServerConfig, direct_allow_rule,
};

const MIN_TLS_BUFFER_SIZE: usize = 16 * 1024;

/// The longest username or password mieru accepts. `apis/constant/user.go:19`
/// caps the name at 64 bytes and the Go client applies the same figure to the
/// password (`pkg/appctl/appctlcommon/client.go:67`).
const MIERU_MAX_CREDENTIAL_LEN: usize = 64;

/// Result of config validation containing server configs and expanded DNS groups.
/// DNS resolvers are built at runtime from the expanded groups.
pub struct ValidatedConfigs {
    pub configs: Vec<Config>,
    /// Expanded DNS groups in topological order (bootstrap deps first).
    pub dns_groups: Vec<ExpandedDnsGroup>,
    /// Every outbound the config mentions, keyed and conflict-checked. Built
    /// here and installed where a service starts — never here, because this
    /// function also serves `--dry-run` and the config editor.
    pub outbounds: crate::outbound_stats::OutboundSet,
}

/// Validates configs and returns startable server configs with expanded DNS groups.
///
/// This function:
/// - Builds client_groups and rule_groups from ClientConfigGroup and RuleConfigGroup entries
/// - Resolves group references using topological sort
/// - Collects named PEMs
/// - Expands DNS groups (composition, client chains) and validates them
/// - Validates all ServerConfigs and TunConfigs against the groups and PEMs
/// - Returns ValidatedConfigs containing configs and expanded DNS groups
pub fn create_server_configs(all_configs: Vec<Config>) -> std::io::Result<ValidatedConfigs> {
    // Built here and returned, never installed here: this function also serves
    // `--dry-run` and the config editor, and validating a draft must not touch
    // the live list of a service running in the same process.
    let mut outbounds = crate::outbound_stats::OutboundSet::default();

    // First pass: collect raw groups with unresolved references
    let mut raw_client_groups: HashMap<String, OneOrSome<ConfigSelection<ClientConfig>>> =
        HashMap::new();
    raw_client_groups.insert(
        String::from("direct"),
        OneOrSome::One(ConfigSelection::Config(ClientConfig::default())),
    );

    let mut rule_groups: HashMap<String, Vec<RuleConfig>> = HashMap::new();
    rule_groups.insert(
        String::from("allow-all-direct"),
        vec![RuleConfig {
            masks: OneOrSome::One(NetLocationMask::ANY),
            rule_sets: NoneOrSome::Unspecified,
            loaded_rule_sets: Vec::new(),
            action: RuleActionConfig::Allow {
                override_address: None,
                client_chains: NoneOrSome::One(ClientChain::default()),
            },
        }],
    );
    rule_groups.insert(
        String::from("block-all"),
        vec![RuleConfig {
            masks: OneOrSome::One(NetLocationMask::ANY),
            rule_sets: NoneOrSome::Unspecified,
            loaded_rule_sets: Vec::new(),
            action: RuleActionConfig::Block,
        }],
    );

    let mut server_configs: Vec<ServerConfig> = vec![];
    let mut tun_configs: Vec<TunConfig> = vec![];
    let mut named_pems: HashMap<String, String> = HashMap::new();
    let mut dns_groups: HashMap<String, DnsConfigGroup> = HashMap::new();
    let mut rule_sets: HashMap<String, Arc<RuleSet>> = HashMap::new();

    for config in all_configs.into_iter() {
        match config {
            Config::ClientConfigGroup(group) => {
                if raw_client_groups
                    .insert(group.client_group.clone(), group.client_proxies)
                    .is_some()
                {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("client group already exists: {}", group.client_group),
                    ));
                }
            }
            Config::RuleConfigGroup(group) => {
                if rule_groups
                    .insert(group.rule_group.clone(), group.rules.into_vec())
                    .is_some()
                {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("rule group already exists: {}", group.rule_group),
                    ));
                }
            }
            Config::Server(server_config) => {
                server_configs.push(server_config);
            }
            Config::TunServer(tun_config) => {
                tun_configs.push(tun_config);
            }
            Config::NamedPem(pem) => {
                let pem_data = match pem.source {
                    PemSource::Data(data) => data,
                    PemSource::Path(_) => {
                        panic!("named pem path should have been converted to data");
                    }
                };

                if named_pems.insert(pem.pem.clone(), pem_data).is_some() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("named pem already exists: {}", pem.pem),
                    ));
                }
            }
            Config::DnsConfigGroup(group) => {
                let group_name = group.dns_group.clone();
                if dns_groups.insert(group_name.clone(), group).is_some() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("dns group already exists: {}", group_name),
                    ));
                }
            }
            Config::RuleSet(config) => {
                if rule_sets.contains_key(&config.rule_set) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("rule_set already exists: {}", config.rule_set),
                    ));
                }
                // Read and parse now, so a bad file is a startup error that
                // --dry-run catches rather than a surprise at first connection.
                let loaded = RuleSet::load(&config.rule_set, Path::new(&config.path))?;
                log::debug!("Loaded rule-set {} from {}", loaded.name(), config.path);
                rule_sets.insert(config.rule_set.clone(), loaded);
            }
        }
    }

    // Resolve client groups using topological sort
    let mut client_groups = resolve_client_groups_topologically(&raw_client_groups)?;

    // A group nothing references is still a configured server, and a person
    // expects to see it listed at zero rather than missing.
    for configs in client_groups.values() {
        for config in configs {
            outbounds.insert(&config.stats_key()?, &config.address.to_string())?;
        }
    }

    // Embed PEMs into all client configs in groups before they're used
    for configs in client_groups.values_mut() {
        for config in configs.iter_mut() {
            validate_client_config(config, &named_pems)?;
        }
    }

    // Extract inline DNS configs from server/tun configs into dns_groups.
    // This replaces inline specs with group name references.
    let mut inline_dns_counter = 0u32;
    for config in server_configs.iter_mut() {
        extract_inline_dns(&mut config.dns, &mut dns_groups, &mut inline_dns_counter)?;
    }
    for config in tun_configs.iter_mut() {
        extract_inline_dns(&mut config.dns, &mut dns_groups, &mut inline_dns_counter)?;
    }

    // Expand DNS group composition references for ALL groups (named + inline).
    let expanded_dns_groups = expand_dns_groups_composition(&dns_groups)?;

    // Topological sort by bootstrap dependencies and detect errors
    // This is necessary if we have a DNS group A with bootstrap set to DNS group B, we need
    // to know to build DNS group B first.
    let dns_group_order = topological_sort_dns_groups_by_bootstrap(&expanded_dns_groups)?;

    // Expand and validate DNS specs (client chains, protocol compatibility).
    let mut final_dns_groups: Vec<ExpandedDnsGroup> = Vec::new();
    let group_names: HashSet<&str> = expanded_dns_groups.keys().map(|s| s.as_str()).collect();

    for name in dns_group_order {
        let specs = expanded_dns_groups.get(&name).unwrap();
        let expanded_specs = expand_dns_specs(
            specs,
            &client_groups,
            &named_pems,
            &group_names,
            &mut outbounds,
        )?;
        final_dns_groups.push(ExpandedDnsGroup {
            name,
            specs: expanded_specs,
        });
    }

    // Validate server configs (DNS is now just a group reference).
    for config in server_configs.iter_mut() {
        validate_server_config(
            config,
            &client_groups,
            &rule_groups,
            &named_pems,
            &rule_sets,
            &mut outbounds,
        )?;
        validate_dns_group_ref(&config.dns, &group_names)?;
    }

    // Validate TUN configs. The dns-safety verdicts are computed once for
    // all groups; each TUN entry is then a lookup.
    let tun_dns_verdicts = tun_dns_verdicts(&final_dns_groups);
    for config in tun_configs.iter_mut() {
        validate_tun_config(
            config,
            &client_groups,
            &rule_groups,
            &rule_sets,
            &mut outbounds,
        )?;
        validate_dns_group_ref(&config.dns, &group_names)?;
        validate_tun_dns_needs_no_system_resolver(&config.dns, &tun_dns_verdicts)?;
    }

    // Combine into Config list (only Server and TunServer variants)
    let mut result: Vec<Config> = server_configs.into_iter().map(Config::Server).collect();
    result.extend(tun_configs.into_iter().map(Config::TunServer));

    Ok(ValidatedConfigs {
        configs: result,
        dns_groups: final_dns_groups,
        outbounds,
    })
}

/// Resolves client group references using topological sort.
///
/// Groups can reference other groups, forming a dependency graph.
/// This function:
/// 1. Builds the dependency graph
/// 2. Detects cycles
/// 3. Resolves groups in topological order
fn resolve_client_groups_topologically(
    raw_groups: &HashMap<String, OneOrSome<ConfigSelection<ClientConfig>>>,
) -> std::io::Result<HashMap<String, Vec<ClientConfig>>> {
    // Build dependency graph: for each group, collect which groups it references
    let mut dependencies: HashMap<String, Vec<String>> = HashMap::new();
    for (group_name, selections) in raw_groups {
        let mut deps = vec![];
        for selection in selections.iter() {
            if let ConfigSelection::GroupName(ref_name) = selection {
                deps.push(ref_name.clone());
            }
        }
        dependencies.insert(group_name.clone(), deps);
    }

    // Check for unknown group references
    for (group_name, deps) in &dependencies {
        for dep in deps {
            if !raw_groups.contains_key(dep) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "Client group '{}' references unknown group '{}'",
                        group_name, dep
                    ),
                ));
            }
        }
    }

    // Topological sort using Kahn's algorithm with cycle detection
    let sorted_groups = topological_sort(&dependencies)?;

    // Resolve groups in topological order
    let mut resolved: HashMap<String, Vec<ClientConfig>> = HashMap::new();
    for group_name in sorted_groups {
        let selections = raw_groups.get(&group_name).unwrap();
        let mut expanded_configs = vec![];

        for selection in selections.iter() {
            match selection {
                ConfigSelection::Config(config) => {
                    expanded_configs.push(config.clone());
                }
                ConfigSelection::GroupName(ref_name) => {
                    // This group should already be resolved (due to topological order)
                    let referenced_configs = resolved.get(ref_name).ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            format!(
                                "Internal error: group '{}' not resolved before '{}'",
                                ref_name, group_name
                            ),
                        )
                    })?;
                    expanded_configs.extend(referenced_configs.clone());
                }
            }
        }

        resolved.insert(group_name, expanded_configs);
    }

    Ok(resolved)
}

/// Performs topological sort on a dependency graph using Kahn's algorithm.
/// Returns groups in order such that dependencies come before dependents.
/// Returns an error if a cycle is detected.
fn topological_sort(dependencies: &HashMap<String, Vec<String>>) -> std::io::Result<Vec<String>> {
    let mut in_degree: HashMap<String, usize> = HashMap::new();
    let mut reverse_deps: HashMap<String, Vec<String>> = HashMap::new();

    // Initialize in-degree for all nodes
    for group_name in dependencies.keys() {
        in_degree.entry(group_name.clone()).or_insert(0);
        reverse_deps.entry(group_name.clone()).or_default();
    }

    // Build in-degree counts and reverse dependency map
    for (group_name, deps) in dependencies {
        for dep in deps {
            *in_degree.entry(group_name.clone()).or_insert(0) += 1;
            reverse_deps
                .entry(dep.clone())
                .or_default()
                .push(group_name.clone());
        }
    }

    // Find all nodes with in-degree 0 (no dependencies)
    let mut queue: Vec<String> = in_degree
        .iter()
        .filter(|&(_, deg)| *deg == 0)
        .map(|(name, _)| name.clone())
        .collect();

    let mut result = vec![];

    while let Some(node) = queue.pop() {
        result.push(node.clone());

        // Reduce in-degree for all nodes that depend on this one
        if let Some(dependents) = reverse_deps.get(&node) {
            for dependent in dependents {
                if let Some(deg) = in_degree.get_mut(dependent) {
                    *deg -= 1;
                    if *deg == 0 {
                        queue.push(dependent.clone());
                    }
                }
            }
        }
    }

    // If we haven't processed all nodes, there's a cycle
    if result.len() != dependencies.len() {
        // Find the cycle for a better error message
        let processed: HashSet<_> = result.iter().collect();
        let in_cycle: Vec<_> = dependencies
            .keys()
            .filter(|k| !processed.contains(k))
            .cloned()
            .collect();

        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "Circular dependency detected in client groups: {}",
                in_cycle.join(", ")
            ),
        ));
    }

    Ok(result)
}

/// Phase 1: Expand DNS group composition references.
/// Returns a map of group name to flat list of server specs (no group references).
fn expand_dns_groups_composition(
    dns_groups: &HashMap<String, DnsConfigGroup>,
) -> std::io::Result<HashMap<String, Vec<DnsServerSpec>>> {
    // Build composition dependency graph and validate references
    let mut dependencies: HashMap<String, Vec<String>> = HashMap::new();

    for (group_name, group) in dns_groups {
        let deps: Vec<String> = group
            .dns_servers
            .iter()
            .filter_map(|spec| {
                spec.as_group_ref().map(|ref_name| {
                    if !dns_groups.contains_key(ref_name) {
                        Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            format!(
                                "DNS group '{}' references unknown group '{}'",
                                group_name, ref_name
                            ),
                        ))
                    } else {
                        Ok(ref_name.to_string())
                    }
                })
            })
            .collect::<std::io::Result<Vec<_>>>()?;
        dependencies.insert(group_name.clone(), deps);
    }

    // Topological sort by composition dependencies
    let order = topological_sort(&dependencies).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            e.to_string()
                .replace("client groups", "DNS groups (composition)"),
        )
    })?;

    // Expand in topological order
    let mut expanded: HashMap<String, Vec<DnsServerSpec>> = HashMap::new();

    for name in order {
        let group = dns_groups.get(&name).unwrap();
        let specs: Vec<DnsServerSpec> = group
            .dns_servers
            .iter()
            .flat_map(|spec| match spec.as_group_ref() {
                Some(ref_name) => expanded.get(ref_name).unwrap().clone(),
                None => vec![spec.clone()],
            })
            .collect();
        expanded.insert(name, specs);
    }

    Ok(expanded)
}

/// A TUN entry's dns group must never silently need the system resolver.
///
/// A hostname URL is resolved through the spec's bootstrap resolver, and
/// without `bootstrap_url` that is the system resolver -- on a TUN whose
/// whole point is to keep names off plaintext UDP:53, a silent leak
/// dressed as DoH. The same fallback hides two more ways: a bootstrap
/// chain that bottoms out in `url: system` (explicit at the root, but a
/// silent fallback when a hostname resolves THROUGH it), and a
/// `client_chain` hop at a hostname, which the DNS builder resolves with
/// a plain system resolver. IP-address URLs need no resolution and keep
/// working with no bootstrap; `url: system` directly in the TUN's own
/// group stays allowed as the explicit request it is. Plain server
/// configs keep the system-bootstrap convenience.
///
/// Verdicts are computed once for all groups, in the bootstrap-first
/// order `final_dns_groups` already carries, so each group reuses its
/// bootstrap groups' verdicts -- the same edges the topological sort
/// walked -- instead of re-deriving them per TUN entry.
struct TunDnsVerdict {
    /// Why this group cannot be a TUN entry's own dns group.
    as_root: Option<String>,
    /// Why this group cannot sit anywhere in a TUN entry's bootstrap
    /// chain: everything in `as_root`, plus `url: system`, which is only
    /// explicit at the root.
    as_bootstrap: Option<String>,
}

fn tun_dns_verdicts(groups: &[ExpandedDnsGroup]) -> HashMap<&str, TunDnsVerdict> {
    fn chain_hop_hostname(chains: &[ClientChain]) -> Option<&str> {
        chains
            .iter()
            .flat_map(|chain| chain.hops.iter())
            .flat_map(
                |hop| -> Box<dyn Iterator<Item = &ConfigSelection<ClientConfig>>> {
                    match hop {
                        ClientChainHop::Single(sel) => Box::new(std::iter::once(sel)),
                        ClientChainHop::Pool(pool) => Box::new(pool.iter()),
                    }
                },
            )
            .find_map(|sel| match sel {
                ConfigSelection::Config(cfg) => cfg.address.address().hostname(),
                // Group refs are resolved to configs during expansion.
                ConfigSelection::GroupName(_) => None,
            })
    }

    let mut verdicts: HashMap<&str, TunDnsVerdict> = HashMap::new();
    for group in groups {
        let mut as_root: Option<String> = None;
        let mut as_bootstrap: Option<String> = None;
        for spec in &group.specs {
            let parsed = &spec.parsed_url;
            if matches!(parsed, ParsedDnsUrl::System) {
                as_bootstrap.get_or_insert_with(|| {
                    format!(
                        "group '{}' contains 'url: system': reached through a bootstrap \
                         chain, that IS the silent system-resolver fallback",
                        group.name
                    )
                });
                continue;
            }
            if let Some(host) = chain_hop_hostname(&spec.client_chains) {
                let msg = format!(
                    "TUN dns server '{}' reaches its upstream through a client_chain hop \
                     at hostname '{host}', which is resolved by the system resolver. Use \
                     an IP address for the hop.",
                    spec.url
                );
                as_root.get_or_insert_with(|| msg.clone());
                as_bootstrap.get_or_insert(msg);
            }
            match spec.bootstrap.as_ref().map(DnsBootstrap::as_str) {
                None => {
                    if parsed.has_hostname() {
                        let msg = format!(
                            "TUN dns server '{}' has a hostname URL and no bootstrap_url: \
                             resolving it would silently use the system resolver, which is \
                             the leak the dns block exists to prevent. Use an IP-address URL \
                             (e.g. https://1.1.1.1/dns-query) or add a bootstrap_url.",
                            spec.url
                        );
                        as_root.get_or_insert_with(|| msg.clone());
                        as_bootstrap.get_or_insert(msg);
                    }
                }
                Some(bootstrap) => {
                    // A group-name bootstrap inherits that group's
                    // as-bootstrap verdict; groups are in dependency order,
                    // so it is already computed. IP-only bootstrap URLs
                    // were validated during expansion.
                    if let Some(v) = verdicts.get(bootstrap)
                        && let Some(reason) = &v.as_bootstrap
                    {
                        let msg = format!(
                            "TUN dns server '{}' bootstraps through group '{bootstrap}', \
                             which cannot serve a TUN bootstrap chain: {reason}",
                            spec.url
                        );
                        as_root.get_or_insert_with(|| msg.clone());
                        as_bootstrap.get_or_insert(msg);
                    }
                }
            }
        }
        verdicts.insert(
            group.name.as_str(),
            TunDnsVerdict {
                as_root,
                as_bootstrap,
            },
        );
    }
    verdicts
}

fn validate_tun_dns_needs_no_system_resolver(
    dns: &Option<DnsConfig>,
    verdicts: &HashMap<&str, TunDnsVerdict>,
) -> std::io::Result<()> {
    let Some(group_name) = dns.as_ref().and_then(|c| c.resolved_group()) else {
        return Ok(());
    };
    if let Some(v) = verdicts.get(group_name)
        && let Some(reason) = &v.as_root
    {
        return Err(std::io::Error::other(reason.clone()));
    }
    Ok(())
}

/// Phase 2: Topological sort on expanded DNS groups based on bootstrap_url dependencies.
/// Returns groups in order such that bootstrap dependencies come before dependents.
fn topological_sort_dns_groups_by_bootstrap(
    expanded_groups: &HashMap<String, Vec<DnsServerSpec>>,
) -> std::io::Result<Vec<String>> {
    // Build dependency graph: for each group, collect which groups it references via bootstrap_url
    let dependencies: HashMap<String, Vec<String>> = expanded_groups
        .iter()
        .map(|(group_name, specs)| {
            let deps: Vec<String> = specs
                .iter()
                .filter_map(|spec| spec.bootstrap_url())
                .filter(|url| expanded_groups.contains_key(*url))
                .map(String::from)
                .collect();
            (group_name.clone(), deps)
        })
        .collect();

    topological_sort(&dependencies).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            e.to_string()
                .replace("client groups", "DNS groups (bootstrap)"),
        )
    })
}

/// Extracts inline DNS specs from a config into dns_groups with a generated name.
/// Replaces config.dns.servers with a single group name reference.
/// If servers is already a single group reference or empty, does nothing.
fn extract_inline_dns(
    dns: &mut Option<DnsConfig>,
    dns_groups: &mut HashMap<String, DnsConfigGroup>,
    counter: &mut u32,
) -> std::io::Result<()> {
    let Some(config) = dns else {
        return Ok(());
    };

    // Empty means use default resolver - nothing to extract
    if config.servers.is_empty() {
        return Ok(());
    }

    // Already a single group reference - nothing to extract
    if let NoneOrSome::One(spec) = &config.servers
        && spec.as_group_ref().is_some()
    {
        return Ok(());
    }

    // Generate unique name and extract specs into a new group
    let generated_name = format!("__inline_dns_{}", *counter);
    *counter += 1;

    let group = DnsConfigGroup {
        dns_group: generated_name.clone(),
        dns_servers: std::mem::replace(&mut config.servers, NoneOrSome::Unspecified),
    };
    dns_groups.insert(generated_name.clone(), group);

    // Replace servers with the group reference
    config.servers = NoneOrSome::One(DnsServerSpec::Simple(generated_name));

    Ok(())
}

/// Validates that DNS config references an existing group.
fn validate_dns_group_ref(
    dns: &Option<DnsConfig>,
    group_names: &HashSet<&str>,
) -> std::io::Result<()> {
    let Some(config) = dns else {
        return Ok(());
    };

    // Empty means use default resolver
    if config.servers.is_empty() {
        return Ok(());
    }

    // After extraction, servers should be a single group reference
    if let NoneOrSome::One(spec) = &config.servers
        && let Some(group_name) = spec.as_group_ref()
    {
        if !group_names.contains(group_name) {
            return Err(std::io::Error::other(format!(
                "unknown dns_group in server config: '{}'",
                group_name
            )));
        }
        return Ok(());
    }

    // Should not reach here after extract_inline_dns
    Err(std::io::Error::other(
        "DNS servers should be a single group reference after extraction",
    ))
}

/// Expand and validate DNS specs.
///
/// Expands client chains (resolves group refs to configs) and validates:
/// - Inline client configs (PEMs, etc.)
/// - Protocol compatibility (system doesn't support chains, UDP/H3 only direct chains)
/// - Bootstrap URL validity (must be a known group or valid IP-only URL)
fn expand_dns_specs(
    specs: &[DnsServerSpec],
    client_groups: &HashMap<String, Vec<ClientConfig>>,
    named_pems: &HashMap<String, String>,
    dns_group_names: &HashSet<&str>,
    outbounds: &mut crate::outbound_stats::OutboundSet,
) -> std::io::Result<Vec<ExpandedDnsSpec>> {
    let mut result = Vec::new();

    for spec in specs {
        let url_str = spec.url();
        let server_name_override = spec.server_name();

        // Parse URL to validate and check protocol
        let parsed_url = ParsedDnsUrl::parse_with_server_name(url_str, server_name_override)
            .map_err(|e| std::io::Error::other(e.to_string()))?;

        // Expand and validate client chains
        let client_chains_raw = spec.client_chains();
        let mut expanded_chains: Vec<ClientChain> = Vec::new();

        for chain_selection in client_chains_raw.iter() {
            let mut chain = match chain_selection {
                ConfigSelection::Config(chain) => chain.clone(),
                ConfigSelection::GroupName(name) => ClientChain {
                    hops: OneOrSome::One(ClientChainHop::Single(ConfigSelection::GroupName(
                        name.clone(),
                    ))),
                },
            };
            // Validate inline client configs before expanding
            for hop in chain.hops.iter_mut() {
                validate_client_chain_hop(hop, client_groups, named_pems)?;
            }
            expand_client_chain(&mut chain.hops, client_groups, outbounds)?;
            expanded_chains.push(chain);
        }

        // Validate protocol compatibility with chains
        if !expanded_chains.is_empty() {
            // System DNS never supports client_chain
            if matches!(&parsed_url, ParsedDnsUrl::System) {
                return Err(std::io::Error::other(
                    "client_chain is not supported for system DNS resolver",
                ));
            }

            // Check if all chains are direct-only (for UDP/H3 validation)
            let all_direct = expanded_chains.iter().all(is_chain_direct_only);

            if !all_direct {
                match &parsed_url {
                    ParsedDnsUrl::Udp { .. } => {
                        return Err(std::io::Error::other(
                            "UDP DNS only supports direct client_chain (for bind_interface)",
                        ));
                    }
                    ParsedDnsUrl::H3 { .. } => {
                        return Err(std::io::Error::other(
                            "H3 DNS only supports direct client_chain (for bind_interface)",
                        ));
                    }
                    _ => {}
                }
            }
        }

        // Validate bootstrap_url: a known group name, or a valid IP-only URL.
        let bootstrap = match spec.bootstrap_url() {
            None => None,
            Some(name) if dns_group_names.contains(name) => {
                Some(DnsBootstrap::Group(name.to_string()))
            }
            Some(bootstrap_url) => {
                let parsed = ParsedDnsUrl::parse(bootstrap_url).map_err(|e| {
                    std::io::Error::other(format!(
                        "invalid bootstrap_url '{}': {}",
                        bootstrap_url, e
                    ))
                })?;

                if parsed.has_hostname() {
                    return Err(std::io::Error::other(format!(
                        "bootstrap_url '{}' contains hostname - must use IP address or dns_group name",
                        bootstrap_url
                    )));
                }
                Some(DnsBootstrap::Url {
                    url: bootstrap_url.to_string(),
                    parsed,
                })
            }
        };

        result.push(ExpandedDnsSpec {
            url: url_str.to_string(),
            parsed_url,
            client_chains: expanded_chains,
            bootstrap,
            ip_strategy: spec.ip_strategy(),
            timeout_secs: spec.timeout_secs(),
            connect_timeout_secs: spec.connect_timeout_secs(),
            attempts: spec.attempts(),
        });
    }

    Ok(result)
}

/// Check if a client chain is direct-only (single hop with all direct protocol configs).
fn is_chain_direct_only(chain: &ClientChain) -> bool {
    // Must have exactly one hop (OneOrSome::One variant)
    let hop = match &chain.hops {
        OneOrSome::One(hop) => hop,
        OneOrSome::Some(_) => return false, // Multiple hops
    };

    // The single hop must be all direct configs
    match hop {
        ClientChainHop::Single(ConfigSelection::Config(config)) => config.protocol.is_direct(),
        ClientChainHop::Single(ConfigSelection::GroupName(_)) => {
            // Should not happen after expansion
            false
        }
        ClientChainHop::Pool(selections) => selections.iter().all(|sel| match sel {
            ConfigSelection::Config(config) => config.protocol.is_direct(),
            ConfigSelection::GroupName(_) => false,
        }),
    }
}

fn validate_server_config(
    server_config: &mut ServerConfig,
    client_groups: &HashMap<String, Vec<ClientConfig>>,
    rule_groups: &HashMap<String, Vec<RuleConfig>>,
    named_pems: &HashMap<String, String>,
    rule_sets: &HashMap<String, Arc<RuleSet>>,
    outbounds: &mut crate::outbound_stats::OutboundSet,
) -> std::io::Result<()> {
    // First handle QUIC settings certificates
    if let Some(ref mut quic_settings) = server_config.quic_settings {
        embed_pem_from_map(&mut quic_settings.cert, named_pems);
        embed_pem_from_map(&mut quic_settings.key, named_pems);
        for cert in quic_settings.client_ca_certs.iter_mut() {
            embed_pem_from_map(cert, named_pems);
        }
    }
    if server_config.transport != Transport::Tcp && server_config.tcp_settings.is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "TCP transport is not selected but TCP settings specified",
        ));
    }

    if server_config.transport == Transport::Quic {
        match server_config.quic_settings {
            Some(ServerQuicConfig {
                ref mut client_fingerprints,
                ref mut num_endpoints,
                ..
            }) => {
                validate_client_fingerprints(client_fingerprints)?;

                if *num_endpoints == 0 {
                    *num_endpoints = get_num_threads();
                }
            }
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "QUIC transport is selected but QUIC settings not specified",
                ));
            }
        }
    } else if server_config.quic_settings.is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "QUIC transport is not selected but QUIC settings specified",
        ));
    }

    validate_sniff_config(
        &server_config.sniff,
        &format!("server at {}", server_config.bind_location),
    )?;

    if let super::types::BindLocation::Path(_) = server_config.bind_location
        && server_config.transport != Transport::Tcp
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Unix domain socket support only available for TCP transport",
        ));
    }

    ConfigSelection::replace_none_or_some_groups(&mut server_config.rules, rule_groups)?;

    if server_config.rules.is_empty() {
        server_config.rules = direct_allow_rule();
    }

    for rule_config_selection in server_config.rules.iter_mut() {
        validate_rule_config(
            rule_config_selection.unwrap_config_mut(),
            client_groups,
            named_pems,
            rule_sets,
            outbounds,
        )?;
    }

    // `redirect` is valid here and nowhere else: the arm for it in
    // `validate_server_proxy_config` is the refusal for the nested case, so
    // the top-level one is checked on its own and does not go through it.
    if matches!(server_config.protocol, ServerProxyConfig::Redirect {}) {
        return validate_redirect_listener(server_config);
    }

    // `tproxy` is the only UDP-native inbound, and needs it. Anything else on
    // `transport: udp` used to pass here and panic on a `todo!()` at startup.
    if let ServerProxyConfig::Tproxy {
        udp_timeout,
        udp_nat_max,
    } = server_config.protocol
    {
        return validate_tproxy_listener(server_config, udp_timeout, udp_nat_max);
    }
    if server_config.transport == Transport::Udp {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "transport: udp is for the tproxy inbound only; {} runs on tcp or quic",
                server_config.protocol
            ),
        ));
    }

    validate_server_proxy_config(
        &mut server_config.protocol,
        client_groups,
        rule_groups,
        named_pems,
        rule_sets,
        false, // top-level, not inside TLS/Reality
        outbounds,
    )?;

    Ok(())
}

/// Where a `redirect` listener may run. It forwards whatever the kernel
/// redirected to wherever the kernel says it was going.
fn validate_redirect_listener(server_config: &ServerConfig) -> std::io::Result<()> {
    // SO_ORIGINAL_DST is netfilter's. Refused rather than accepted and
    // useless: elsewhere every connection would be turned away at runtime.
    if !cfg!(target_os = "linux") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "the redirect inbound needs Linux: it reads SO_ORIGINAL_DST, which NAT REDIRECT sets",
        ));
    }

    if server_config.transport != Transport::Tcp {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "the redirect inbound is TCP only; NAT REDIRECT has no original destination to \
             read on any other transport",
        ));
    }

    // NAT REDIRECT delivers to a port, so a Unix socket can never receive one.
    if let super::types::BindLocation::Path(_) = server_config.bind_location {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "the redirect inbound listens on a TCP address, not a Unix socket: NAT REDIRECT \
             delivers to a port",
        ));
    }

    // No loopback rule, deliberately, although the first design had one.
    // REDIRECT in PREROUTING rewrites the destination to the primary address
    // of the interface the packet came in on, not to 127.0.0.1, so a loopback
    // listener never sees a LAN client's connection and the kernel answers
    // RST. awg-manager binds its sing-box `redirect-in` to 0.0.0.0 for that
    // reason (`internal/singbox/router/service_lifecycle.go`, "redirect-in →
    // 0.0.0.0"). What keeps a reachable listener from being an open proxy is
    // that a client cannot choose the original destination: the kernel
    // records it, and a connection dialled at the listener directly reports
    // the listener's own address, which `original_destination` turns into a
    // refusal.
    Ok(())
}

/// Where a `tproxy` listener may run, and the limits it may set.
fn validate_tproxy_listener(
    server_config: &ServerConfig,
    udp_timeout: u64,
    udp_nat_max: usize,
) -> std::io::Result<()> {
    // IP_TRANSPARENT and IP_RECVORIGDSTADDR are Linux's.
    if !cfg!(target_os = "linux") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "the tproxy inbound needs Linux: it reads IP_RECVORIGDSTADDR, which TPROXY sets",
        ));
    }

    if server_config.transport != Transport::Udp {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "the tproxy inbound needs transport: udp; TCP is the redirect inbound's",
        ));
    }

    // Sniffing reads a TCP stream's first bytes. Refused rather than accepted
    // and ignored: a datagram inbound has no stream to read.
    if server_config
        .sniff
        .as_ref()
        .is_some_and(|sniff| sniff.enabled)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "the tproxy inbound cannot sniff: sniffing reads a TCP stream, and tproxy carries \
             UDP datagrams; drop the sniff block",
        ));
    }

    let super::types::BindLocation::Address(addresses) = &server_config.bind_location else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "the tproxy inbound listens on a UDP address, not a Unix socket: TPROXY delivers \
             to a port",
        ));
    };

    // Loopback only. A transparent socket on the wildcard also receives
    // datagrams delivered to the host in the ordinary way, and relays them to
    // the address they were already at: shoes talking to itself without end
    // (awg-manager #689, in the spec's security notes). TPROXY's `--on-ip`
    // names the listener, so loopback costs a router nothing. It keeps the
    // LAN from reaching the listener directly; the host still can, and the
    // demux drops a datagram addressed to the listener itself
    // (`tproxy::worth_routing`).
    for address in addresses.iter() {
        for socket_addr in address.to_socket_addrs()? {
            if !socket_addr.ip().is_loopback() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "the tproxy inbound must bind a loopback address, not {socket_addr}: \
                         on any other a transparent socket relays ordinary traffic to itself. \
                         Point TPROXY's --on-ip at 127.0.0.1"
                    ),
                ));
            }
        }
    }

    // Each session holds a descriptor, and Linux caps a process's at
    // `fs.nr_open`, 1048576 by default, so more could never be used. The cap
    // also keeps the figure inside tokio's `Semaphore::MAX_PERMITS`, past
    // which building the listener's budgets panics at startup.
    if udp_nat_max == 0 || udp_nat_max > MAX_TPROXY_UDP_NAT_MAX {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "tproxy udp_nat_max must be between 1 and {MAX_TPROXY_UDP_NAT_MAX}, \
                 not {udp_nat_max}"
            ),
        ));
    }
    validate_udp_timeout("tproxy", udp_timeout)
}

/// Zero would expire every session as it opened (a TUIC association was
/// reaped on the first sweep). The upper bound is the router's timer, which
/// panics on a duration it cannot hold (about two years); a day is far past
/// any UDP flow worth keeping.
fn validate_udp_timeout(protocol: &str, udp_timeout: u64) -> std::io::Result<()> {
    if udp_timeout == 0 || udp_timeout > MAX_UDP_TIMEOUT_SECS {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "{protocol} udp_timeout must be between 1 and {MAX_UDP_TIMEOUT_SECS} seconds, \
                 not {udp_timeout}"
            ),
        ));
    }
    Ok(())
}

const MAX_UDP_TIMEOUT_SECS: u64 = 86400;
const MAX_TPROXY_UDP_NAT_MAX: usize = 1 << 20;

/// A sniff block that is on but can never sniff anything is a typo, not a
/// preference. Fail at load rather than quietly doing nothing at runtime.
fn validate_sniff_config(
    sniff: &Option<super::types::SniffConfig>,
    context: &str,
) -> std::io::Result<()> {
    let Some(sniff) = sniff else {
        return Ok(());
    };
    if !sniff.enabled {
        return Ok(());
    }
    if sniff.protocols.as_ref().is_some_and(|p| p.is_empty()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "{context}: sniff is enabled but its protocol list is empty; \
                 drop `protocols` to sniff tls and http, or set `enabled: false`"
            ),
        ));
    }
    Ok(())
}

fn validate_client_fingerprints(
    client_fingerprints: &mut NoneOrSome<String>,
) -> std::io::Result<()> {
    if !client_fingerprints.is_unspecified() && client_fingerprints.is_empty() {
        println!("WARNING: Client fingerprints provided but empty, defaulting to 'any'");
    }

    if client_fingerprints.iter().any(|fp| fp == "any") {
        let _ = std::mem::replace(client_fingerprints, NoneOrSome::Unspecified);
    } else {
        let _ = crate::rustls_config_util::process_fingerprints(
            &client_fingerprints.clone().into_vec(),
        )?;
    }

    Ok(())
}

/// Validates Reality private_key to ensure it's a valid base64url-encoded X25519 key.
fn validate_reality_private_key(private_key: &str, target_name: &str) -> std::io::Result<()> {
    decode_private_key(private_key).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "REALITY target '{}': invalid private_key: {}",
                target_name, e
            ),
        )
    })?;

    Ok(())
}

/// Validates Reality client short_id to ensure it's a valid hexadecimal string
fn validate_reality_client_short_id(short_id: &str) -> std::io::Result<()> {
    if short_id.len() > 16 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "Reality client short_id is too long: '{}' ({} chars, max 16)",
                short_id,
                short_id.len()
            ),
        ));
    }

    if !short_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "Reality client short_id contains non-hexadecimal characters: '{}'. \
                 Only 0-9, a-f, and A-F are allowed.",
                short_id
            ),
        ));
    }

    decode_short_id(short_id).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Reality client short_id decode failed: {}", e),
        )
    })?;

    Ok(())
}

fn validate_reality_server_short_ids(
    short_ids: &OneOrSome<String>,
    target_name: &str,
) -> std::io::Result<()> {
    let is_default = match short_ids {
        OneOrSome::One(id) => id == DEFAULT_REALITY_SHORT_ID,
        OneOrSome::Some(ids) => ids.len() == 1 && ids[0] == DEFAULT_REALITY_SHORT_ID,
    };

    if is_default {
        log::warn!(
            "Reality server '{}' using default short_ids (all zeros). \
             For better security in production, configure explicit short_ids.",
            target_name
        );
    }

    for (i, short_id) in short_ids.iter().enumerate() {
        if short_id.len() > 16 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "REALITY target '{}': short_ids[{}] is too long: '{}' ({} chars, max 16)",
                    target_name,
                    i,
                    short_id,
                    short_id.len()
                ),
            ));
        }

        if !short_id.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "REALITY target '{}': short_ids[{}] contains non-hexadecimal characters: '{}'. \
                     Only 0-9, a-f, and A-F are allowed.",
                    target_name, i, short_id
                ),
            ));
        }
    }

    Ok(())
}

/// Validates that Vision is only enabled when the inner protocol is VLESS (client-side)
fn validate_client_vision_protocol(
    vision_enabled: bool,
    protocol: &ClientProxyConfig,
    config_type: &str,
) -> std::io::Result<()> {
    if !vision_enabled {
        return Ok(());
    }

    match protocol {
        ClientProxyConfig::Vless { .. } => Ok(()),
        other_protocol => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "{} client config has vision=true but inner protocol is {} (not VLESS). \
                 Vision (XTLS-RPRX-Vision) requires VLESS as the inner protocol. \
                 Either set vision=false or change the inner protocol to VLESS.",
                config_type,
                other_protocol.protocol_name()
            ),
        )),
    }
}

/// A protocol that owns its transport cannot sit under a wrapping layer:
/// the chain builder would hand it to the per-stream handler factory, which
/// has no handler for it. The type system does not say so, so this does.
fn refuse_wrapped_transport_owner(layer: &str, inner: &ClientProxyConfig) -> std::io::Result<()> {
    if !inner.owns_transport() {
        return Ok(());
    }
    let hint = match (inner, layer) {
        (ClientProxyConfig::Sstp(_), "TLS") => {
            " SSTP does its own TLS; put the settings under the sstp protocol's tls block."
        }
        (ClientProxyConfig::OpenConnect(_), "TLS") => {
            " OpenConnect does its own TLS; put the settings under the openconnect protocol's tls block."
        }
        _ => "",
    };
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!(
            "{} owns its transport and cannot be wrapped in a {layer} layer; it must be \
             the only hop in its chain.{hint}",
            inner.protocol_name()
        ),
    ))
}

/// Recursive validation of client proxy config structure (Vision rules, etc.)
fn validate_client_proxy_structure(config: &ClientProxyConfig) -> std::io::Result<()> {
    match config {
        ClientProxyConfig::Tls(tls_config) => {
            refuse_wrapped_transport_owner("TLS", &tls_config.protocol)?;
            validate_client_vision_protocol(tls_config.vision, &tls_config.protocol, "TLS")?;
            let sni_hostname = match &tls_config.sni_hostname {
                crate::option_util::NoneOrOne::One(name) => Some(name.as_str()),
                _ => None,
            };
            validate_tls_server_name("TLS", sni_hostname)?;
            validate_client_proxy_structure(&tls_config.protocol)?;
        }
        ClientProxyConfig::Reality {
            vision, protocol, ..
        } => {
            refuse_wrapped_transport_owner("Reality", protocol)?;
            validate_client_vision_protocol(*vision, protocol, "Reality")?;
            validate_client_proxy_structure(protocol)?;
        }
        ClientProxyConfig::ShadowTls {
            protocol,
            sni_hostname,
            ..
        } => {
            refuse_wrapped_transport_owner("ShadowTLS", protocol)?;
            validate_tls_server_name("ShadowTLS", sni_hostname.as_deref())?;
            validate_client_proxy_structure(protocol)?;
        }
        ClientProxyConfig::Websocket(ws_config) => {
            refuse_wrapped_transport_owner("WebSocket", &ws_config.protocol)?;
            validate_client_proxy_structure(&ws_config.protocol)?;
        }
        ClientProxyConfig::HttpUpgrade(config) => {
            refuse_wrapped_transport_owner("HTTPUpgrade", &config.protocol)?;
            validate_client_proxy_structure(&config.protocol)?;
        }
        _ => {}
    }
    Ok(())
}

/// A TLS or ShadowTLS `sni_hostname` rustls cannot hold -- a name with a
/// space, say -- used to panic when the chain was built, after the config
/// had loaded. `""` is accepted and sends no server name, as it does for
/// REALITY (SF-4).
fn validate_tls_server_name(layer: &str, sni_hostname: Option<&str>) -> std::io::Result<()> {
    match sni_hostname {
        Some(name) if !name.is_empty() => rustls::pki_types::ServerName::try_from(name.to_string())
            .map(|_| ())
            .map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "{layer} client sni_hostname is not a server name ({e}); \
                             set it to a hostname or an IP address, or \"\" to send none"
                    ),
                )
            }),
        _ => Ok(()),
    }
}

/// A REALITY hop names the server it imitates. Only the outermost hop falls
/// back to the outbound's address, and only when that is a hostname; any
/// other REALITY hop without `sni_hostname` used to panic when the chain was
/// built (SF-4). `sni_hostname: ""` is the way to send no name.
fn validate_reality_sni(
    config: &ClientProxyConfig,
    address_is_a_hostname: bool,
) -> std::io::Result<()> {
    match config {
        ClientProxyConfig::Reality {
            sni_hostname,
            protocol,
            ..
        } => {
            if sni_hostname.is_none() && !address_is_a_hostname {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "REALITY client needs sni_hostname: the server name it imitates, which must \
                     match a key of the server's reality_targets. The outbound's address is used \
                     only when it is a hostname and REALITY is the outermost layer. Set \
                     sni_hostname: \"\" to send no server name.",
                ));
            }
            validate_reality_sni(protocol, false)
        }
        ClientProxyConfig::Tls(tls_config) => validate_reality_sni(&tls_config.protocol, false),
        ClientProxyConfig::ShadowTls { protocol, .. } => validate_reality_sni(protocol, false),
        ClientProxyConfig::Websocket(ws_config) => validate_reality_sni(&ws_config.protocol, false),
        ClientProxyConfig::HttpUpgrade(config) => validate_reality_sni(&config.protocol, false),
        _ => Ok(()),
    }
}

fn validate_client_config(
    client_config: &mut ClientConfig,
    named_pems: &HashMap<String, String>,
) -> std::io::Result<()> {
    validate_reality_sni(
        &client_config.protocol,
        client_config.address.address().hostname().is_some(),
    )?;

    if client_config.transport != Transport::Tcp && client_config.tcp_settings.is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "TCP transport is not selected but TCP settings specified",
        ));
    }

    // Hysteria2 and TUIC are QUIC-native: their transport is implied by the
    // protocol rather than selected, so they carry quic_settings without a
    // 'transport: quic' line. Everything else in the block below - embedding
    // named PEMs, pairing cert with key, checking fingerprints - applies to
    // them exactly as it does to a QUIC transport.
    let quic_native = matches!(
        client_config.protocol,
        ClientProxyConfig::Hysteria2(_) | ClientProxyConfig::Tuic(_)
    );

    if let Some(ref mut quic_config) = client_config.quic_settings {
        if client_config.transport != Transport::Quic && !quic_native {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "QUIC transport is not selected but QUIC settings specified",
            ));
        }

        embed_optional_pem_from_map(&mut quic_config.cert, named_pems);
        embed_optional_pem_from_map(&mut quic_config.key, named_pems);

        let super::types::ClientQuicConfig {
            cert,
            key,
            server_fingerprints,
            ..
        } = quic_config;
        if cert.is_none() != key.is_none() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Both client cert and key have to be specified, or both have to be omitted",
            ));
        }
        validate_server_fingerprints(server_fingerprints)?;
    }

    #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
    if client_config.bind_interface.is_one() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "bind_interface is only available on Android, Fuchsia, or Linux.",
        ));
    }

    // Protocols that own their transport reject the socket-level knobs that do
    // not apply to them. The QUIC-based ones keep quic_settings, which carries
    // verify, SNI, fingerprints, ALPN and the client certificate - all of which
    // mean the same thing for them as for a QUIC transport.
    if client_config.protocol.owns_transport() {
        let proto = client_config.protocol.protocol_name();
        if client_config.transport != Transport::Tcp {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{proto} uses its own transport. Do not set 'transport'."),
            ));
        }
        // SSTP's and OpenConnect's transport is TCP, so its socket settings
        // apply to them.
        if client_config.tcp_settings.is_some()
            && !matches!(
                client_config.protocol,
                ClientProxyConfig::Sstp(_) | ClientProxyConfig::OpenConnect(_)
            )
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("tcp_settings is not valid for {proto} protocol."),
            ));
        }
        // quic_settings needs no check here: a tunnel protocol never selects
        // 'transport: quic', so the QUIC block above has already rejected it.
    }

    let own_tls = match &mut client_config.protocol {
        ClientProxyConfig::Sstp(sstp) => {
            validate_sstp(sstp)?;
            Some(("SSTP", &sstp.tls))
        }
        ClientProxyConfig::OpenConnect(openconnect) => {
            validate_openconnect(openconnect)?;
            Some(("OpenConnect", &openconnect.tls))
        }
        _ => None,
    };
    if let Some((label, tls)) = own_tls {
        // Unless sni_hostname names something, the address's hostname is
        // the name the certificate is checked against (`""` and `null` send
        // no SNI but still verify against it), and the connector unwraps
        // that name as validated: one rustls refuses must be refused here.
        // `:443` parses to a hostname of "", which no header, name check or
        // resolver can use; the connector would panic on it.
        if client_config.address.address().hostname() == Some("") {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "{label} address needs a host: a hostname or an IP address before the port."
                ),
            ));
        }
        let names_something = matches!(
            &tls.sni_hostname,
            crate::option_util::NoneOrOne::One(name) if !name.is_empty()
        );
        if !names_something {
            validate_tls_server_name(label, client_config.address.address().hostname())?;
        }
    }

    match &client_config.protocol {
        ClientProxyConfig::Hysteria2(hysteria2) => {
            validate_obfs_config(hysteria2.obfs.as_ref())?;

            // Ports and schedule were parsed with the config
            // (`PortHoppingConfig`); what needs the outbound's address is
            // checked here. The canonical peer address is fixed for the
            // connection's life - that is what keeps QUIC from seeing a path
            // change on every hop - so there is nowhere for a re-resolution
            // to go.
            if hysteria2.port_hopping.is_some()
                && client_config.address.address().hostname().is_some()
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Hysteria2 port_hopping requires a literal IP address. The peer \
                     address is fixed for the connection's life, so a hostname has \
                     nowhere to re-resolve to.",
                ));
            }
        }
        ClientProxyConfig::Mieru(mieru) => {
            // The same limits the Go client enforces before it will dial
            // (`pkg/appctl/appctlcommon/client.go:57-68`, MaxUserNameLen = 64).
            // A server built from the same config would reject these
            // credentials, so catching them here beats a connection that
            // authenticates against nothing.
            if mieru.username.is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "mieru requires a username: the key is derived from it.",
                ));
            }
            if mieru.username.len() > MIERU_MAX_CREDENTIAL_LEN {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("mieru usernames are limited to {MIERU_MAX_CREDENTIAL_LEN} bytes."),
                ));
            }
            if mieru.password.expose().is_empty() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "mieru requires a password: the key is derived from it.",
                ));
            }
            if mieru.password.expose().len() > MIERU_MAX_CREDENTIAL_LEN {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("mieru passwords are limited to {MIERU_MAX_CREDENTIAL_LEN} bytes."),
                ));
            }

            // mieru defines exactly two transports, TCP and UDP, and this
            // client implements the first. Its TCP segment framing carried
            // over QUIC or over datagrams is neither of them, so it would
            // produce bytes no mieru server understands. Refusing beats
            // dialling something that cannot work.
            if client_config.transport != Transport::Tcp {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "The mieru client outbound only supports its TCP transport. \
                     Remove 'transport', or set it to tcp.",
                ));
            }
        }
        ClientProxyConfig::Tuic(tuic) => {
            if tuic.heartbeat_ms == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "TUIC heartbeat_ms must be greater than zero.",
                ));
            }
            // Accepting this silently would be worse than refusing it: the user
            // would believe they had 0-RTT and get an ordinary handshake.
            if tuic.zero_rtt_handshake {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "The TUIC client outbound does not implement zero_rtt_handshake. \
                     Remove the option; the server side still supports it.",
                ));
            }
        }
        _ => {}
    }

    validate_client_proxy_config(&mut client_config.protocol, named_pems)?;

    Ok(())
}

/// Minimum obfuscation password length, matching smPSKMinLen in
/// apernet/hysteria extras/obfs/salamander.go.
const MIN_OBFS_PASSWORD_LEN: usize = 4;

fn validate_obfs_config(obfs: Option<&ObfsConfig>) -> std::io::Result<()> {
    let Some(ObfsConfig::Salamander { password }) = obfs else {
        return Ok(());
    };
    if password.expose().len() < MIN_OBFS_PASSWORD_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "Obfuscation password must be at least {MIN_OBFS_PASSWORD_LEN} bytes; \
                 the reference implementation rejects anything shorter."
            ),
        ));
    }
    Ok(())
}

/// The SSTP outbound's fields, against the limits the spec's Configuration
/// table names (docs/specs/2026-10-30-sstp-client-outbound.md).
fn validate_sstp(sstp: &mut super::types::SstpClientConfig) -> std::io::Result<()> {
    let invalid = |message: String| std::io::Error::new(std::io::ErrorKind::InvalidInput, message);
    // RFC 2759 §4: "0 to (theoretically) 256 case-sensitive ASCII
    // characters"; empty is refused because no server accepts it.
    if sstp.username.is_empty() || sstp.username.len() > 256 {
        return Err(invalid("SSTP username must be 1 to 256 characters.".into()));
    }
    if !sstp.username.is_ascii() || sstp.username.contains('\0') {
        return Err(invalid(
            "SSTP username must be ASCII (RFC 2759 §4), without NUL.".into(),
        ));
    }
    // RFC 2759 §4: up to 256 Unicode characters, counted as UTF-16 units
    // because that is what MS-CHAPv2 hashes.
    let password = sstp.password.expose();
    if password.is_empty() || password.encode_utf16().count() > 256 {
        return Err(invalid("SSTP password must be 1 to 256 characters.".into()));
    }
    // PAP carries each credential behind a one-octet length (RFC 1334
    // §2.1.1), as bytes: 256 of them would go out as length zero.
    if sstp.auth.contains(&super::types::SstpAuthMethod::Pap)
        && (sstp.username.len() > 255 || password.len() > 255)
    {
        return Err(invalid(
            "SSTP with pap in auth needs a username and password of at most 255 bytes each: \
             PAP sends each behind a one-byte length."
                .into(),
        ));
    }
    if sstp.auth.is_empty() {
        return Err(invalid(
            "SSTP auth must list at least one method: mschapv2, pap.".into(),
        ));
    }
    let mut seen = std::collections::HashSet::new();
    if !sstp.auth.iter().all(|method| seen.insert(*method)) {
        return Err(invalid("SSTP auth lists a method twice.".into()));
    }
    // Above 1500 buys TCP nothing (the far host's MSS bounds segments) and
    // SoftEther caps the MRU at 1500; below 576 is under IPv4's minimum
    // reassembly size.
    if !(576..=1500).contains(&sstp.mtu) {
        return Err(invalid(format!(
            "SSTP mtu must be between 576 and 1500, not {}.",
            sstp.mtu
        )));
    }
    // It goes on the request line as the query string, so it is limited to
    // RFC 3986's unreserved characters; Keenetic generates hexadecimal.
    if let Some(secret) = &sstp.camouflage_secret {
        let secret = secret.expose();
        if secret.is_empty()
            || !secret
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
        {
            return Err(invalid(
                "SSTP camouflage_secret must be the part after '?' in the address the server \
                 shows: letters, digits, '-', '.', '_' or '~', and not empty."
                    .into(),
            ));
        }
    }
    validate_server_fingerprints(&mut sstp.tls.server_fingerprints)?;
    let sni_hostname = match &sstp.tls.sni_hostname {
        crate::option_util::NoneOrOne::One(name) => Some(name.as_str()),
        _ => None,
    };
    validate_tls_server_name("SSTP", sni_hostname)?;
    // `is_empty`, not `is_unspecified`: `server_fingerprints: []` or `null`
    // is a pin set that pins nothing, and selects the verifier that checks
    // nothing just the same.
    if !sstp.tls.verify && sstp.tls.server_fingerprints.is_empty() {
        return Err(invalid(
            "SSTP would send your credentials to any server that answers; pin its \
             certificate with tls.server_fingerprints or leave tls.verify on."
                .into(),
        ));
    }
    Ok(())
}

/// The OpenConnect outbound's fields, against the spec's Configuration
/// section (docs/specs/2026-10-31-openconnect-client-outbound.md).
fn validate_openconnect(
    openconnect: &mut super::types::OpenConnectClientConfig,
) -> std::io::Result<()> {
    let invalid = |message: String| std::io::Error::new(std::io::ErrorKind::InvalidInput, message);
    // ocserv bounds a username at MAX_USERNAME_SIZE (64) and a password at
    // MAX_PASSWORD_SIZE (64), `src/defs.h`; AnyConnect servers vary. The
    // limits here are the XML's, so the error is the server's, not ours.
    if openconnect.username.is_empty() || openconnect.username.len() > 256 {
        return Err(invalid(
            "OpenConnect username must be 1 to 256 characters.".into(),
        ));
    }
    if openconnect.username.contains(['\0', '<', '>', '&']) {
        return Err(invalid(
            "OpenConnect username cannot contain '<', '>', '&' or NUL.".into(),
        ));
    }
    let password = openconnect.password.expose();
    if password.is_empty() || password.len() > 256 {
        return Err(invalid(
            "OpenConnect password must be 1 to 256 characters.".into(),
        ));
    }
    if let Some(group) = &openconnect.group
        && (group.is_empty() || group.len() > 64 || group.contains(['<', '>', '&', '\0']))
    {
        return Err(invalid(
            "OpenConnect group must be 1 to 64 characters, without '<', '>', '&' or NUL.".into(),
        ));
    }
    // It goes on the request line: an absolute path, no query (the
    // camouflage secret is the query), no whitespace.
    if !openconnect.path.starts_with('/')
        || openconnect.path.len() > 256
        || openconnect
            .path
            .bytes()
            .any(|b| b <= b' ' || b >= 0x7f || b == b'?' || b == b'#')
    {
        return Err(invalid(
            "OpenConnect path must be an absolute path such as \"/\" or \"/group\", \
             without a query, spaces or control characters."
                .into(),
        ));
    }
    // As for SSTP: above 1500 buys nothing, below 576 is under IPv4's
    // minimum; ocserv refuses a link MTU under its own minimum anyway.
    if !(576..=1500).contains(&openconnect.mtu) {
        return Err(invalid(format!(
            "OpenConnect mtu must be between 576 and 1500, not {}.",
            openconnect.mtu
        )));
    }
    if let Some(secret) = &openconnect.camouflage_secret {
        let secret = secret.expose();
        if secret.is_empty()
            || !secret
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
        {
            return Err(invalid(
                "OpenConnect camouflage_secret must be the part after '?' in the address the \
                 server shows: letters, digits, '-', '.', '_' or '~', and not empty."
                    .into(),
            ));
        }
    }
    validate_server_fingerprints(&mut openconnect.tls.server_fingerprints)?;
    let sni_hostname = match &openconnect.tls.sni_hostname {
        crate::option_util::NoneOrOne::One(name) => Some(name.as_str()),
        _ => None,
    };
    validate_tls_server_name("OpenConnect", sni_hostname)?;
    if !openconnect.tls.verify && openconnect.tls.server_fingerprints.is_empty() {
        return Err(invalid(
            "OpenConnect would send your credentials to any server that answers; pin its \
             certificate with tls.server_fingerprints or leave tls.verify on."
                .into(),
        ));
    }
    Ok(())
}

fn validate_server_fingerprints(
    server_fingerprints: &mut NoneOrSome<String>,
) -> std::io::Result<()> {
    if !server_fingerprints.is_unspecified() && server_fingerprints.is_empty() {
        println!("WARNING: Server fingerprints provided but empty, defaulting to 'any'");
    }

    if server_fingerprints.iter().any(|fp| fp == "any") {
        let _ = std::mem::replace(server_fingerprints, NoneOrSome::Unspecified);
    } else {
        let _ = crate::rustls_config_util::process_fingerprints(
            &server_fingerprints.clone().into_vec(),
        )?;
    }

    Ok(())
}

fn validate_client_proxy_config(
    client_proxy_config: &mut ClientProxyConfig,
    named_pems: &HashMap<String, String>,
) -> std::io::Result<()> {
    validate_client_proxy_structure(client_proxy_config)?;

    match client_proxy_config {
        ClientProxyConfig::Reality {
            short_id, protocol, ..
        } => {
            validate_reality_client_short_id(short_id)?;

            if short_id == DEFAULT_REALITY_SHORT_ID {
                log::warn!(
                    "Reality client using default short_id (all zeros). \
                     For better security in production, configure an explicit short_id that matches your server."
                );
            }

            validate_client_proxy_config(protocol, named_pems)?;
        }

        ClientProxyConfig::Tls(tls_config) => {
            embed_optional_pem_from_map(&mut tls_config.cert, named_pems);
            embed_optional_pem_from_map(&mut tls_config.key, named_pems);

            if tls_config.cert.is_none() != tls_config.key.is_none() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Both client cert and key have to be specified, or both have to be omitted",
                ));
            }
            validate_server_fingerprints(&mut tls_config.server_fingerprints)?;

            validate_client_proxy_config(&mut tls_config.protocol, named_pems)?;
        }

        ClientProxyConfig::ShadowTls { protocol, .. } => {
            validate_client_proxy_config(protocol, named_pems)?;
        }

        ClientProxyConfig::Websocket(ws_config) => {
            validate_client_proxy_config(&mut ws_config.protocol, named_pems)?;
        }

        ClientProxyConfig::HttpUpgrade(config) => {
            validate_client_proxy_config(&mut config.protocol, named_pems)?;
        }

        ClientProxyConfig::Wireguard(wg_config) => {
            validate_wireguard_config(wg_config)?;
        }

        ClientProxyConfig::AmneziaWg(awg_config) => {
            validate_amneziawg_config(awg_config)?;
        }

        _ => {}
    }
    Ok(())
}

/// Keys and prefixes are checked as the config is parsed (`WgKey`,
/// `IpPrefix`); what is left is the MTU.
fn validate_wireguard_config(config: &super::types::WireGuardClientConfig) -> std::io::Result<()> {
    if config.mtu < 576 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("WireGuard mtu {} is too small (minimum 576)", config.mtu),
        ));
    }
    Ok(())
}

/// The fragmentation warning for `mtu` and `s4`, if full-size packets cross
/// a 1500-byte path. The advice is checked arithmetic: `s4` is 16-bit, and
/// one past 864 leaves no MTU at or above the 576 floor that fits, which
/// `1440 - s4` used to answer with an underflow.
fn amneziawg_mtu_warning(mtu: u16, s4: u16) -> Option<String> {
    let wire_size = u32::from(mtu) + u32::from(s4) + 60;
    if wire_size <= 1500 {
        return None;
    }
    let advice = match 1440u32.checked_sub(u32::from(s4)) {
        Some(fitting) if fitting >= 576 => format!("Lower mtu to {fitting} or reduce s4."),
        _ => format!(
            "No mtu of 576 or more fits beside s4 {s4}; reduce s4 to at most {}.",
            1440 - 576
        ),
    };
    Some(format!(
        "AmneziaWG mtu {mtu} + s4 {s4} puts full-size packets at {wire_size} bytes on the wire, \
         past a standard 1500-byte path MTU -- every large packet will fragment. {advice}"
    ))
}

/// Keys and prefixes are checked as the config is parsed (`WgKey`,
/// `IpPrefix`).
fn validate_amneziawg_config(config: &super::types::AmneziaWgClientConfig) -> std::io::Result<()> {
    // Validate MTU
    if config.mtu < 576 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("AmneziaWG mtu {} is too small (minimum 576)", config.mtu),
        ));
    }

    // A full-size transport packet reaches the wire at mtu + S4 junk prefix
    // + 16 transport header + 16 AEAD tag + 8 UDP + 20 IPv4 = mtu + S4 + 60,
    // and S4, unlike the content padding and the random trailer, is never
    // clamped against the MTU. Amnezia's own generator draws S4 up to 27 and
    // pairs it with the WireGuard-default MTU of 1420, which crosses 1500 at
    // S4 >= 21 -- so a copied config can silently fragment every full-size
    // packet it sends (3x-ui#6376 measured the threshold byte-for-byte).
    // A warning, not an error: paths with jumbo or sub-1500 MTUs exist, and
    // only the operator knows theirs.
    if let Some(warning) = amneziawg_mtu_warning(config.mtu, config.awg.s4) {
        log::warn!("{warning}");
    }

    // Parse and validate the obfuscation parameters now, so a bad H-range or a
    // header protection key with too little padding is a startup error rather
    // than a tunnel that silently never completes a handshake.
    crate::amneziawg::convert_amnezia_config(&config.awg, config.mtu)?;

    Ok(())
}

fn validate_server_proxy_config(
    server_proxy_config: &mut ServerProxyConfig,
    client_groups: &HashMap<String, Vec<ClientConfig>>,
    rule_groups: &HashMap<String, Vec<RuleConfig>>,
    named_pems: &HashMap<String, String>,
    rule_sets: &HashMap<String, Arc<RuleSet>>,
    inside_tls_or_reality: bool,
    outbounds: &mut crate::outbound_stats::OutboundSet,
) -> std::io::Result<()> {
    match server_proxy_config {
        ServerProxyConfig::Naiveproxy { .. } if !inside_tls_or_reality => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "NaiveProxy must be used inside a TLS or Reality protocol. \
                 Configure it as the inner protocol of tls: or reality: targets.",
            ));
        }
        // Reached only when nested; see `validate_server_config`. Inside
        // TLS or WebSocket the handler is handed a wrapper, not the accepted
        // socket, so there is no original destination to read.
        ServerProxyConfig::Redirect {} => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "redirect can only be a listener's own protocol, not an inner one: it reads the \
                 original destination from the accepted socket",
            ));
        }
        ServerProxyConfig::Tproxy { .. } => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "tproxy can only be a listener's own protocol, not an inner one: it reads each \
                 datagram's original destination from the listening socket",
            ));
        }
        ServerProxyConfig::Tls {
            tls_targets,
            default_tls_target,
            shadowtls_targets,
            reality_targets,
            tls_buffer_size,
        } => {
            if tls_targets.is_empty()
                && default_tls_target.is_none()
                && shadowtls_targets.is_empty()
                && reality_targets.is_empty()
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "TLS server has no entries",
                ));
            }
            for tls_server_config in tls_targets.values_mut() {
                embed_pem_from_map(&mut tls_server_config.cert, named_pems);
                embed_pem_from_map(&mut tls_server_config.key, named_pems);
                for cert in tls_server_config.client_ca_certs.iter_mut() {
                    embed_pem_from_map(cert, named_pems);
                }

                let TlsServerConfig {
                    ref mut protocol,
                    ref mut override_rules,
                    ref mut client_fingerprints,
                    ..
                } = *tls_server_config;

                validate_client_fingerprints(client_fingerprints)?;

                validate_server_proxy_config(
                    protocol,
                    client_groups,
                    rule_groups,
                    named_pems,
                    rule_sets,
                    true,
                    outbounds,
                )?;

                ConfigSelection::replace_none_or_some_groups(override_rules, rule_groups)?;

                for rule_config_selection in override_rules.iter_mut() {
                    validate_rule_config(
                        rule_config_selection.unwrap_config_mut(),
                        client_groups,
                        named_pems,
                        rule_sets,
                        outbounds,
                    )?;
                }
            }
            if let Some(tls_server_config) = default_tls_target {
                embed_pem_from_map(&mut tls_server_config.cert, named_pems);
                embed_pem_from_map(&mut tls_server_config.key, named_pems);
                for cert in tls_server_config.client_ca_certs.iter_mut() {
                    embed_pem_from_map(cert, named_pems);
                }

                let TlsServerConfig {
                    ref mut protocol,
                    ref mut override_rules,
                    ..
                } = **tls_server_config;
                validate_server_proxy_config(
                    protocol,
                    client_groups,
                    rule_groups,
                    named_pems,
                    rule_sets,
                    true,
                    outbounds,
                )?;

                ConfigSelection::replace_none_or_some_groups(override_rules, rule_groups)?;

                for rule_config_selection in override_rules.iter_mut() {
                    validate_rule_config(
                        rule_config_selection.unwrap_config_mut(),
                        client_groups,
                        named_pems,
                        rule_sets,
                        outbounds,
                    )?;
                }
            }
            for (sni_hostname, tls_server_config) in shadowtls_targets.iter_mut() {
                if tls_targets.contains_key(sni_hostname) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "duplicated SNI hostname between TLS and ShadowTLS targets: {sni_hostname}"
                        ),
                    ));
                }
                let ShadowTlsServerConfig {
                    ref mut protocol,
                    ref mut override_rules,
                    ref mut handshake,
                    ..
                } = *tls_server_config;

                match handshake {
                    ShadowTlsServerHandshakeConfig::Local(local_handshake) => {
                        embed_pem_from_map(&mut local_handshake.cert, named_pems);
                        embed_pem_from_map(&mut local_handshake.key, named_pems);
                        validate_client_fingerprints(&mut local_handshake.client_fingerprints)?;
                    }
                    ShadowTlsServerHandshakeConfig::Remote(remote_handshake) => {
                        // This chain reaches build_client_proxy_chain without
                        // passing through a rule, so it has to be expanded
                        // here or it is expanded nowhere: its outbounds would
                        // be missing from the set, and a group reference in it
                        // would panic in chain_builder. Its inline hops are
                        // validated first, as a rule's are.
                        for hop in remote_handshake.client_chain.iter_mut() {
                            validate_client_chain_hop(hop, client_groups, named_pems)?;
                        }
                        expand_client_chain(
                            &mut remote_handshake.client_chain,
                            client_groups,
                            outbounds,
                        )?;
                    }
                }

                validate_server_proxy_config(
                    protocol,
                    client_groups,
                    rule_groups,
                    named_pems,
                    rule_sets,
                    true,
                    outbounds,
                )?;

                ConfigSelection::replace_none_or_some_groups(override_rules, rule_groups)?;

                for rule_config_selection in override_rules.iter_mut() {
                    validate_rule_config(
                        rule_config_selection.unwrap_config_mut(),
                        client_groups,
                        named_pems,
                        rule_sets,
                        outbounds,
                    )?;
                }
            }

            for (sni_hostname, reality_config) in reality_targets.iter_mut() {
                if tls_targets.contains_key(sni_hostname) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "duplicated SNI hostname between TLS and REALITY targets: {sni_hostname}"
                        ),
                    ));
                }
                if shadowtls_targets.contains_key(sni_hostname) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "duplicated SNI hostname between ShadowTLS and REALITY targets: {sni_hostname}"
                        ),
                    ));
                }

                validate_reality_private_key(&reality_config.private_key, sni_hostname)?;
                validate_reality_server_short_ids(&reality_config.short_ids, sni_hostname)?;

                // Same as the ShadowTLS remote handshake above: this chain is
                // built without ever passing through a rule.
                if !reality_config.dest_client_chain.is_empty() {
                    let mut hops: OneOrSome<ClientChainHop> =
                        OneOrSome::Some(reality_config.dest_client_chain.clone().into_vec());
                    for hop in hops.iter_mut() {
                        validate_client_chain_hop(hop, client_groups, named_pems)?;
                    }
                    expand_client_chain(&mut hops, client_groups, outbounds)?;
                    reality_config.dest_client_chain = NoneOrSome::Some(hops.into_vec());
                }

                validate_server_proxy_config(
                    &mut reality_config.protocol,
                    client_groups,
                    rule_groups,
                    named_pems,
                    rule_sets,
                    true,
                    outbounds,
                )?;

                ConfigSelection::replace_none_or_some_groups(
                    &mut reality_config.override_rules,
                    rule_groups,
                )?;

                for rule_config_selection in reality_config.override_rules.iter_mut() {
                    validate_rule_config(
                        rule_config_selection.unwrap_config_mut(),
                        client_groups,
                        named_pems,
                        rule_sets,
                        outbounds,
                    )?;
                }
            }

            if let Some(size) = tls_buffer_size
                && *size < MIN_TLS_BUFFER_SIZE
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("TLS buffer size must be at least {MIN_TLS_BUFFER_SIZE}"),
                ));
            }
        }
        ServerProxyConfig::Websocket { targets } => {
            for websocket_server_config in targets.iter_mut() {
                let WebsocketServerConfig {
                    protocol,
                    override_rules,
                    ..
                } = websocket_server_config;
                validate_server_proxy_config(
                    protocol,
                    client_groups,
                    rule_groups,
                    named_pems,
                    rule_sets,
                    false,
                    outbounds,
                )?;

                ConfigSelection::replace_none_or_some_groups(override_rules, rule_groups)?;

                for rule_config_selection in override_rules.iter_mut() {
                    validate_rule_config(
                        rule_config_selection.unwrap_config_mut(),
                        client_groups,
                        named_pems,
                        rule_sets,
                        outbounds,
                    )?;
                }
            }
        }
        ServerProxyConfig::HttpUpgrade { targets } => {
            for httpupgrade_server_config in targets.iter_mut() {
                let HttpUpgradeServerConfig {
                    protocol,
                    override_rules,
                    ..
                } = httpupgrade_server_config;
                validate_server_proxy_config(
                    protocol,
                    client_groups,
                    rule_groups,
                    named_pems,
                    rule_sets,
                    false,
                    outbounds,
                )?;

                ConfigSelection::replace_none_or_some_groups(override_rules, rule_groups)?;

                for rule_config_selection in override_rules.iter_mut() {
                    validate_rule_config(
                        rule_config_selection.unwrap_config_mut(),
                        client_groups,
                        named_pems,
                        rule_sets,
                        outbounds,
                    )?;
                }
            }
        }
        ServerProxyConfig::Hysteria2 { obfs, .. } => {
            validate_obfs_config(obfs.as_ref())?;
        }
        ServerProxyConfig::Trojan { shadowsocks, .. } => {
            if matches!(shadowsocks, Some(ShadowsocksConfig::Aead2022 { .. })) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Trojan does not support shadowsocks 2022 ciphers",
                ));
            }
        }
        ServerProxyConfig::Snell { cipher, .. } if cipher.starts_with("2022-blake3-") => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Snell does not support shadowsocks 2022 ciphers",
            ));
        }
        ServerProxyConfig::TuicV5 { udp_timeout, .. } => {
            validate_udp_timeout("tuic", *udp_timeout)?;
        }
        _ => (),
    }
    Ok(())
}

/// Validates a TUN configuration.
/// macOS is the one platform with two legitimate device shapes, so this arm
/// accepts either rather than requiring one.
///
/// A Network Extension provider hands over a descriptor from `packetFlow`
/// (`DevicePolicy::BorrowedFd`), exactly as on iOS. The privileged daemon
/// creates the device itself (`DevicePolicy::Owned`), and then `address` and
/// `netmask` are load-bearing, as they are on Windows: an interface without
/// them comes up reachable by nothing and says nothing about it.
///
/// `destination` is warned about rather than required, and the distinction is
/// worth stating because it nearly went the other way. The `tun` crate applies
/// all three together as a point-to-point alias and skips the whole step --
/// without an error -- if any one is missing, which reads like an argument for
/// demanding the trio. But that path runs only with the crate's macOS
/// `enable_routing` on, and shoes turns it off so that the crate does not
/// install a route the host will later have to revert (see
/// `create_sync_device`). With it off, `configure()` applies address, netmask
/// and destination through separate ioctls, so a missing `destination` costs
/// the peer address and nothing else. Requiring it would also make macOS the
/// only platform whose valid config Windows refuses, since Windows rejects
/// `destination` outright.
///
/// The name rule is the crate's: `Device::new` parses everything after `utun`
/// as the control unit and otherwise fails with `Error::InvalidName`, or with
/// a bare integer-parse error for a non-numeric suffix. Neither says what the
/// rule is, so it is stated here. Omitting the name asks the kernel for the
/// next free unit, which is what a host should do -- picking one races every
/// other utun user on the machine.
///
/// That rule applies only when shoes creates the device. With a descriptor the
/// name is documented as ignored (see `TunConfig::device_name`) and the crate
/// never reads it, so rejecting one would refuse a config that works -- the
/// macOS provider is handed whatever YAML the app generates, and a Linux-shaped
/// `tun0` in it is meaningless rather than wrong.
#[cfg(target_os = "macos")]
fn validate_macos_tun_device(
    device_fd: Option<i32>,
    device_name: Option<&str>,
    address: Option<std::net::IpAddr>,
    netmask: Option<std::net::IpAddr>,
    destination: Option<std::net::IpAddr>,
) -> std::io::Result<()> {
    // With a descriptor the host has already configured the interface, and
    // the crate returns before it reads any of the fields below.
    if device_fd.is_some() {
        return Ok(());
    }

    if let Some(name) = device_name
        && name
            .strip_prefix("utun")
            .is_none_or(|unit| unit.is_empty() || !unit.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "TUN 'device_name' {name:?} is not valid on macOS: it must be 'utun' followed \
                 by a number (e.g. 'utun4'), or omitted so the kernel picks the next free unit"
            ),
        ));
    }

    if address.is_none() || netmask.is_none() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "TUN on macOS requires either 'device_fd' (from \
             NEPacketTunnelProvider.packetFlow) or both 'address' and 'netmask'; without \
             them the interface comes up reachable by nothing",
        ));
    }

    if destination.is_none() {
        log::warn!(
            "TUN on macOS has no 'destination': the utun is a point-to-point interface and \
             will have no peer address. Set it to the other end of the tunnel subnet."
        );
    }

    Ok(())
}

fn validate_tun_config(
    config: &mut TunConfig,
    client_groups: &HashMap<String, Vec<ClientConfig>>,
    rule_groups: &HashMap<String, Vec<RuleConfig>>,
    rule_sets: &HashMap<String, Arc<RuleSet>>,
    outbounds: &mut crate::outbound_stats::OutboundSet,
) -> std::io::Result<()> {
    // Validate ICMP requires TCP
    if !config.tcp_enabled && config.icmp_enabled {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "TUN: TCP must be enabled for ICMP",
        ));
    }

    validate_sniff_config(&config.sniff, "TUN")?;

    if let Some(ref fake_ip) = config.fake_ip {
        // Build the pool now and discard it: a bad CIDR or a zero max_entries
        // becomes a startup error here rather than a failure inside the VPN
        // data path, where the only symptom would be DNS quietly not working.
        let network = crate::dns::fake_ip::FakeIpNetwork::parse(&fake_ip.network)?;
        crate::dns::fake_ip::FakeIpPool::new(network, fake_ip.max_entries)?;

        // Fake addresses only ever reach us over the TUN's UDP path.
        if !config.udp_enabled {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "TUN: fake_ip requires udp_enabled, since DNS queries arrive over UDP",
            ));
        }
    }

    // Refused rather than ignored where it cannot be honoured. Offload is a
    // flag shoes sets when it opens a Linux device itself. A descriptor
    // handed in was opened by someone else, who chose its framing, so
    // `segmentation_offload: false` there would not turn offload off.
    if let Some(enabled) = config.segmentation_offload {
        if !cfg!(target_os = "linux") {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "TUN 'segmentation_offload' is only supported on Linux",
            ));
        }
        if config.device_fd.is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "TUN 'segmentation_offload: {enabled}' cannot apply to 'device_fd': the \
                     process that opened the descriptor chose its framing"
                ),
            ));
        }
    }

    // Validate that we have either Linux config (device_name/address) or mobile config (device_fd)
    #[cfg(target_os = "linux")]
    {
        if config.device_fd.is_none() && (config.device_name.is_none() || config.address.is_none())
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "TUN on Linux requires either 'device_fd' or both 'device_name' and 'address'",
            ));
        }
    }
    #[cfg(target_os = "android")]
    {
        if config.device_fd.is_none() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "TUN on Android requires 'device_fd' from VpnService.Builder.establish()",
            ));
        }
    }
    #[cfg(target_os = "ios")]
    {
        if config.device_fd.is_none() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "TUN on iOS requires 'device_fd' from NEPacketTunnelProvider.packetFlow",
            ));
        }
    }
    #[cfg(target_os = "macos")]
    validate_macos_tun_device(
        config.device_fd,
        config.device_name.as_deref(),
        config.address,
        config.netmask,
        config.destination,
    )?;
    #[cfg(target_os = "windows")]
    {
        // No descriptor to inject: a wintun handle does not survive a process
        // boundary the way an fd does, so shoes always creates the adapter.
        if config.device_fd.is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "TUN on Windows does not support 'device_fd'; shoes creates the wintun \
                 adapter itself — configure 'device_name', 'address' and 'netmask'",
            ));
        }
        // Refused rather than forwarded: wintun-bindings turns a gateway into
        // `netsh ... gateway=`, which installs a system default route through
        // the adapter. On Linux `destination` is only the point-to-point peer
        // address; silently promoting it to a default route would hijack the
        // host's routing the moment a Linux config is ported.
        if config.destination.is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "TUN 'destination' is not supported on Windows: it would install a \
                 default route through the adapter, and routes stay the host's — \
                 add routes yourself (see examples/tun_windows.yaml)",
            ));
        }
        // A wintun adapter without an address is reachable by nothing and
        // fails silently, so the address is required rather than optional.
        if config.device_name.is_none() || config.address.is_none() || config.netmask.is_none() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "TUN on Windows requires 'device_name', 'address' and 'netmask'",
            ));
        }
        // IPv4 only, said at config time: wintun-bindings 0.7 configures the
        // adapter through `netsh interface ipv4`, and its ipv6 arm emits
        // parameters netsh's ipv6 context does not accept — an IPv6 address
        // here would pass --dry-run and then fail at tunnel start with an
        // opaque netsh error.
        if !config
            .address
            .as_ref()
            .is_some_and(std::net::IpAddr::is_ipv4)
            || !config
                .netmask
                .as_ref()
                .is_some_and(std::net::IpAddr::is_ipv4)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "TUN on Windows requires an IPv4 'address' and 'netmask': the wintun \
                 configuration path cannot express IPv6",
            ));
        }
    }

    // Resolve rule group references
    ConfigSelection::replace_none_or_some_groups(&mut config.rules, rule_groups)?;

    // Validate rules
    for rule in config.rules.iter_mut() {
        let rule = rule.unwrap_config_mut();
        validate_rule_config(rule, client_groups, &HashMap::new(), rule_sets, outbounds)?;
    }

    Ok(())
}

fn validate_rule_config(
    rule_config: &mut RuleConfig,
    client_groups: &HashMap<String, Vec<ClientConfig>>,
    named_pems: &HashMap<String, String>,
    rule_sets: &HashMap<String, Arc<RuleSet>>,
    outbounds: &mut crate::outbound_stats::OutboundSet,
) -> std::io::Result<()> {
    let names = rule_config.rule_sets.clone().into_vec();
    rule_config.loaded_rule_sets = Vec::with_capacity(names.len());
    for name in names {
        let loaded = rule_sets.get(&name).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "rule references an unknown rule_set: {name}. \
                     Declare it with a top-level `- rule_set: {name}` entry."
                ),
            )
        })?;
        rule_config.loaded_rule_sets.push(loaded.clone());
    }

    if let RuleActionConfig::Allow {
        ref mut client_chains,
        ..
    } = rule_config.action
    {
        // Handle unspecified: default to single chain with direct hop
        if client_chains.is_unspecified() {
            *client_chains = NoneOrSome::One(ClientChain::default());
        }

        // Validate not explicitly empty (client_chains: [])
        if matches!(client_chains, NoneOrSome::None) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "client_chains cannot be empty; omit the field for default direct connection",
            ));
        }

        // Validate each chain
        for (chain_index, chain) in client_chains.iter_mut().enumerate() {
            // First validate all hops in this chain
            for hop in chain.hops.iter_mut() {
                validate_client_chain_hop(hop, client_groups, named_pems)?;
            }
            // Then expand group references to inline configs
            expand_client_chain(&mut chain.hops, client_groups, outbounds)?;
            // Validate that direct connectors only appear at hop 0
            validate_direct_connector_positions(&chain.hops, chain_index)?;
            // Validate AmneziaWG is the only hop in its chain
            validate_amneziawg_chain_position(&chain.hops, chain_index)?;
        }
    }

    Ok(())
}

/// Validates that direct connectors only appear at hop 0.
///
/// Direct connectors can only be used as the first hop in a chain because they
/// create the TCP connection. At hop 1+, the TCP connection already exists, so
/// "direct" makes no sense there.
fn validate_direct_connector_positions(
    hops: &OneOrSome<ClientChainHop>,
    chain_index: usize,
) -> std::io::Result<()> {
    for (hop_index, hop) in hops.iter().enumerate() {
        if hop_index == 0 {
            // Direct connectors are allowed at hop 0
            continue;
        }

        // For hop 1+, check if any connector is direct
        let has_direct = match hop {
            ClientChainHop::Single(ConfigSelection::Config(config)) => config.protocol.is_direct(),
            ClientChainHop::Single(ConfigSelection::GroupName(_)) => {
                // Groups should already be expanded at this point
                unreachable!("Group references should be expanded before validation")
            }
            ClientChainHop::Pool(selections) => {
                selections.iter().any(|selection| match selection {
                    ConfigSelection::Config(config) => config.protocol.is_direct(),
                    ConfigSelection::GroupName(_) => {
                        unreachable!("Group references should be expanded before validation")
                    }
                })
            }
        };

        if has_direct {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "Direct connector at chain {} hop {} is invalid. \
                     Direct connectors can only be used at hop 0 (the first hop) \
                     because they create the TCP connection. At hop 1+, the connection \
                     already exists through the previous hop.",
                    chain_index, hop_index
                ),
            ));
        }
    }

    Ok(())
}

/// Validates that virtual network tunnels (WireGuard/AmneziaWG) are only used
/// as a single-hop terminal outbound. They are L3 tunnels, not stream wrappers,
/// so they cannot be mixed with other hops in a chain.
fn validate_amneziawg_chain_position(
    hops: &OneOrSome<ClientChainHop>,
    chain_index: usize,
) -> std::io::Result<()> {
    let has_tunnel = hops.iter().any(|hop| {
        let configs = match hop {
            ClientChainHop::Single(ConfigSelection::Config(config)) => {
                vec![config]
            }
            ClientChainHop::Pool(selections) => selections
                .iter()
                .filter_map(|s| match s {
                    ConfigSelection::Config(config) => Some(config),
                    _ => None,
                })
                .collect(),
            _ => vec![],
        };
        configs.iter().any(|c| c.protocol.owns_transport())
    });

    if !has_tunnel {
        return Ok(());
    }

    if hops.iter().count() != 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "Chain {}: a protocol that owns its transport (WireGuard, AmneziaWG, \
                 Hysteria2, TUIC, SSTP, OpenConnect) must be the only hop in a chain.",
                chain_index
            ),
        ));
    }

    let hop = hops.iter().next().unwrap();
    if let ClientChainHop::Pool(selections) = hop {
        let all_tunnel = selections.iter().all(|s| match s {
            ConfigSelection::Config(config) => config.protocol.owns_transport(),
            _ => false,
        });
        if !all_tunnel {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "Chain {}: a protocol that owns its transport (WireGuard, AmneziaWG, \
                     Hysteria2, TUIC, SSTP, OpenConnect) cannot be mixed with other protocols in a pool.",
                    chain_index
                ),
            ));
        }
    }

    Ok(())
}

fn validate_client_chain_hop(
    hop: &mut ClientChainHop,
    client_groups: &HashMap<String, Vec<ClientConfig>>,
    named_pems: &HashMap<String, String>,
) -> std::io::Result<()> {
    match hop {
        ClientChainHop::Single(selection) => {
            validate_and_expand_selection(selection, client_groups, named_pems)?;
        }
        ClientChainHop::Pool(selections) => {
            for selection in selections.iter_mut() {
                validate_and_expand_selection(selection, client_groups, named_pems)?;
            }
        }
    }
    Ok(())
}

/// Validates a ConfigSelection and expands group references to inline configs.
fn validate_and_expand_selection(
    selection: &mut ConfigSelection<ClientConfig>,
    client_groups: &HashMap<String, Vec<ClientConfig>>,
    named_pems: &HashMap<String, String>,
) -> std::io::Result<()> {
    match selection {
        ConfigSelection::Config(client_config) => {
            validate_client_config(client_config, named_pems)?;
        }
        ConfigSelection::GroupName(group_name) => {
            let group_configs = client_groups.get(group_name).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Unknown client_group in chain: {group_name}"),
                )
            })?;
            // Validate all configs in the group; expansion happens in expand_client_chain
            for mut config in group_configs.clone() {
                validate_client_config(&mut config, named_pems)?;
            }
        }
    }
    Ok(())
}

/// Expands all group references in a client chain to their resolved configs.
/// This should be called after validate_client_chain_hop to replace GroupName
/// selections with their actual configs.
fn expand_client_chain(
    client_chain: &mut OneOrSome<ClientChainHop>,
    client_groups: &HashMap<String, Vec<ClientConfig>>,
    outbounds: &mut crate::outbound_stats::OutboundSet,
) -> std::io::Result<()> {
    let expanded_hops: Vec<ClientChainHop> = client_chain
        .iter()
        .map(|hop| expand_chain_hop(hop, client_groups, outbounds))
        .collect::<std::io::Result<Vec<_>>>()?;

    *client_chain = if expanded_hops.len() == 1 {
        OneOrSome::One(expanded_hops.into_iter().next().unwrap())
    } else {
        OneOrSome::Some(expanded_hops)
    };
    Ok(())
}

/// Expands a single chain hop by resolving all group references.
fn expand_chain_hop(
    hop: &ClientChainHop,
    client_groups: &HashMap<String, Vec<ClientConfig>>,
    outbounds: &mut crate::outbound_stats::OutboundSet,
) -> std::io::Result<ClientChainHop> {
    match hop {
        ClientChainHop::Single(selection) => {
            let configs = expand_selection(selection, client_groups, outbounds)?;
            // Single becomes a Pool if the group has multiple configs
            if configs.len() == 1 {
                Ok(ClientChainHop::Single(ConfigSelection::Config(
                    configs.into_iter().next().unwrap(),
                )))
            } else {
                Ok(ClientChainHop::Pool(OneOrSome::Some(
                    configs.into_iter().map(ConfigSelection::Config).collect(),
                )))
            }
        }
        ClientChainHop::Pool(selections) => {
            let mut all_configs = vec![];
            for selection in selections.iter() {
                all_configs.extend(expand_selection(selection, client_groups, outbounds)?);
            }
            Ok(ClientChainHop::Pool(OneOrSome::Some(
                all_configs
                    .into_iter()
                    .map(ConfigSelection::Config)
                    .collect(),
            )))
        }
    }
}

/// Expands a single selection to its constituent configs.
fn expand_selection(
    selection: &ConfigSelection<ClientConfig>,
    client_groups: &HashMap<String, Vec<ClientConfig>>,
    outbounds: &mut crate::outbound_stats::OutboundSet,
) -> std::io::Result<Vec<ClientConfig>> {
    let configs = match selection {
        ConfigSelection::Config(config) => vec![config.clone()],
        ConfigSelection::GroupName(name) => client_groups.get(name).cloned().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Unknown client group: {name}"),
            )
        })?,
    };

    // Every chain hop funnels through here, inline ones included, which is
    // the form that would otherwise go unlisted. Insertion is idempotent, so
    // a hop that came from a group costs nothing.
    for config in &configs {
        outbounds.insert(&config.stats_key()?, &config.address.to_string())?;
    }

    Ok(configs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::pem::convert_cert_paths;
    use crate::config::types::tun::TEST_TUN_DEVICE_NAME;
    use crate::dns::IpStrategy;

    /// The macOS device shapes, checked directly rather than through a whole
    /// `TunConfig`, because the interesting part is the interaction between
    /// five fields.
    ///
    /// This is the arm that did not exist: until it landed, a macOS TUN config
    /// was not validated the way the other four platforms' are, and the
    /// resulting device came up with no address and no complaint.
    #[cfg(target_os = "macos")]
    mod macos_tun_device {
        use super::*;
        use std::net::IpAddr;

        fn ip(s: &str) -> IpAddr {
            s.parse().unwrap()
        }

        fn owned(
            name: Option<&str>,
            address: Option<&str>,
            netmask: Option<&str>,
            destination: Option<&str>,
        ) -> std::io::Result<()> {
            validate_macos_tun_device(
                None,
                name,
                address.map(ip),
                netmask.map(ip),
                destination.map(ip),
            )
        }

        #[test]
        fn the_daemon_shape_is_accepted() {
            owned(
                None,
                Some("10.0.0.2"),
                Some("255.255.255.0"),
                Some("10.0.0.1"),
            )
            .expect("address, netmask and destination is the shape the daemon writes");
        }

        /// An address or a netmask missing is refused: the interface would
        /// come up reachable by nothing.
        #[test]
        fn an_unaddressable_interface_is_refused() {
            for (case, address, netmask) in [
                ("no address", None, Some("255.255.255.0")),
                ("no netmask", Some("10.0.0.2"), None),
                ("neither", None, None),
            ] {
                let err = owned(None, address, netmask, Some("10.0.0.1"))
                    .expect_err(&format!("{case} must be refused"));
                assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput, "{case}");
                assert!(
                    err.to_string().contains("'netmask'"),
                    "{case}: the message must name the fields, got {err}"
                );
            }
        }

        /// `destination` is a warning, not a rejection.
        ///
        /// Requiring it would make macOS the only platform whose valid config
        /// Windows refuses -- Windows rejects `destination` outright, because
        /// its adapter path would turn it into a default route -- and the
        /// crate hazard that would have justified demanding it (the
        /// all-three-or-silently-skip alias) is not on the path shoes takes.
        #[test]
        fn a_missing_destination_is_allowed() {
            owned(None, Some("10.0.0.2"), Some("255.255.255.0"), None)
                .expect("a missing peer address costs the peer address, not the interface");
        }

        /// The Network Extension shape. The crate returns before it reads any
        /// address field, so requiring them here would reject the provider
        /// that already works on this platform.
        #[test]
        fn a_descriptor_needs_no_address_fields() {
            validate_macos_tun_device(Some(7), None, None, None, None)
                .expect("a borrowed descriptor is the Network Extension's shape");
        }

        #[test]
        fn the_device_name_must_be_utun_and_a_number() {
            for name in ["utun", "tun0", "utunx", "utun4x", "en0", ""] {
                let err = owned(
                    Some(name),
                    Some("10.0.0.2"),
                    Some("255.255.255.0"),
                    Some("10.0.0.1"),
                )
                .expect_err(&format!("{name:?} is not a utun unit"));
                assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
                assert!(
                    err.to_string().contains("utun"),
                    "the message must state the rule, got {err}"
                );
            }

            for name in ["utun0", "utun4", "utun12"] {
                owned(
                    Some(name),
                    Some("10.0.0.2"),
                    Some("255.255.255.0"),
                    Some("10.0.0.1"),
                )
                .unwrap_or_else(|e| panic!("{name:?} is a valid unit, got {e}"));
            }
        }

        /// The name rule applies only when shoes creates the device.
        ///
        /// `TunConfig::device_name` is documented as ignored where the device
        /// arrives as a descriptor, and the crate never reads it there. The
        /// macOS Network Extension provider is handed whatever YAML the app
        /// generated, which is the same document Linux and Android use, so a
        /// `tun0` in it is meaningless rather than wrong. Rejecting it broke
        /// fourteen existing tests, each of them right.
        #[test]
        fn a_descriptor_makes_the_name_irrelevant_rather_than_wrong() {
            validate_macos_tun_device(Some(7), Some("tun0"), None, None, None)
                .expect("a name the platform ignores must not fail the config");
        }
    }

    mod openconnect {
        use crate::config::{OpenConnectClientConfig, SstpTlsConfig};
        use crate::option_util::NoneOrSome;

        fn openconnect() -> OpenConnectClientConfig {
            OpenConnectClientConfig {
                username: "alice".into(),
                password: "pw".to_string().into(),
                group: None,
                path: "/".into(),
                mtu: 1280,
                tls: SstpTlsConfig::default(),
                camouflage_secret: None,
            }
        }

        type Plant = Box<dyn Fn(&mut OpenConnectClientConfig)>;

        #[test]
        fn the_fields_are_bounded_as_the_spec_says() {
            super::super::validate_openconnect(&mut openconnect()).unwrap();
            let cases: Vec<(&str, Plant)> = vec![
                ("username", Box::new(|c| c.username = String::new())),
                ("username", Box::new(|c| c.username = "a<b".into())),
                ("password", Box::new(|c| c.password = String::new().into())),
                ("group", Box::new(|c| c.group = Some(String::new()))),
                ("group", Box::new(|c| c.group = Some("x&y".into()))),
                ("path", Box::new(|c| c.path = "vpn".into())),
                ("path", Box::new(|c| c.path = "/?secret".into())),
                ("path", Box::new(|c| c.path = "/a b".into())),
                ("mtu", Box::new(|c| c.mtu = 575)),
                ("mtu", Box::new(|c| c.mtu = 1501)),
                (
                    "camouflage_secret",
                    Box::new(|c| c.camouflage_secret = Some("a b".to_string().into())),
                ),
                ("would send", Box::new(|c| c.tls.verify = false)),
                (
                    "would send",
                    Box::new(|c| {
                        c.tls.verify = false;
                        c.tls.server_fingerprints = NoneOrSome::Some(vec![]);
                    }),
                ),
            ];
            for (expected, plant) in cases {
                let mut config = openconnect();
                plant(&mut config);
                let err = super::super::validate_openconnect(&mut config).unwrap_err();
                assert!(err.to_string().contains(expected), "{expected}: {err}");
            }
            let mut pinned = openconnect();
            pinned.tls.verify = false;
            pinned.tls.server_fingerprints = NoneOrSome::One("ab".repeat(32));
            super::super::validate_openconnect(&mut pinned).unwrap();
            let mut grouped = openconnect();
            grouped.group = Some("Route".into());
            grouped.path = "/Route".into();
            grouped.camouflage_secret = Some("0123abcd".to_string().into());
            super::super::validate_openconnect(&mut grouped).unwrap();
        }
    }

    mod sstp {
        use crate::config::{ClientProxyConfig, SstpAuthMethod, SstpClientConfig, SstpTlsConfig};
        use crate::option_util::NoneOrOne;

        fn sstp() -> SstpClientConfig {
            SstpClientConfig {
                username: "alice".into(),
                password: "pw".to_string().into(),
                auth: vec![SstpAuthMethod::Mschapv2],
                mtu: 1280,
                tls: SstpTlsConfig::default(),
                camouflage_secret: None,
            }
        }

        /// The connector unwraps the TLS settings as validated, so a name
        /// rustls refuses must be refused here rather than at startup.
        #[test]
        fn an_sni_hostname_that_is_not_a_server_name_is_refused() {
            let mut config = sstp();
            config.tls.sni_hostname = NoneOrOne::One("vpn example.com".into());
            let err = super::super::validate_sstp(&mut config).unwrap_err();
            assert!(
                err.to_string().contains("SSTP client sni_hostname"),
                "{err}"
            );
            config.tls.sni_hostname = NoneOrOne::One("vpn.example.com".into());
            super::super::validate_sstp(&mut config).unwrap();
            config.tls.sni_hostname = NoneOrOne::One(String::new());
            super::super::validate_sstp(&mut config).unwrap();
        }

        /// With verification off, only a pin stands between the credentials
        /// and whoever answers; a pin set that is empty rather than absent
        /// pins nothing and must be refused the same way.
        #[test]
        fn verification_off_needs_a_pin_that_pins_something() {
            use crate::option_util::NoneOrSome;
            for empty in [
                NoneOrSome::Unspecified,
                NoneOrSome::None,
                NoneOrSome::Some(vec![]),
            ] {
                let mut config = sstp();
                config.tls.verify = false;
                config.tls.server_fingerprints = empty;
                let err = super::super::validate_sstp(&mut config).unwrap_err();
                assert!(err.to_string().contains("pin its certificate"), "{err}");
            }
            let mut config = sstp();
            config.tls.verify = false;
            config.tls.server_fingerprints = NoneOrSome::One("ab".repeat(32));
            super::super::validate_sstp(&mut config).unwrap();
        }

        /// With no sni_hostname, the address's hostname is what the
        /// certificate is checked against, and the connector unwraps it as
        /// validated; a label of 64 characters is a name rustls refuses.
        #[test]
        fn an_address_hostname_rustls_refuses_is_refused_at_load() {
            use crate::address::NetLocation;
            use crate::config::ClientConfig;
            let mut config = ClientConfig {
                address: NetLocation::from_str(
                    &format!("{}.example.com:443", "a".repeat(64)),
                    None,
                )
                .unwrap(),
                protocol: ClientProxyConfig::Sstp(Box::new(sstp())),
                ..Default::default()
            };
            let err = super::super::validate_client_config(
                &mut config,
                &std::collections::HashMap::new(),
            )
            .unwrap_err();
            assert!(
                err.to_string().contains("SSTP client sni_hostname"),
                "{err}"
            );

            // `""` and `null` send no SNI but still verify against the
            // address's name, so they do not excuse it either.
            for no_sni in [NoneOrOne::One(String::new()), NoneOrOne::None] {
                let ClientProxyConfig::Sstp(sstp) = &mut config.protocol else {
                    panic!("sstp");
                };
                sstp.tls.sni_hostname = no_sni;
                let err = super::super::validate_client_config(
                    &mut config,
                    &std::collections::HashMap::new(),
                )
                .unwrap_err();
                assert!(
                    err.to_string().contains("SSTP client sni_hostname"),
                    "{err}"
                );
            }

            // An explicit, valid sni_hostname makes the address's name moot.
            let ClientProxyConfig::Sstp(sstp) = &mut config.protocol else {
                panic!("sstp");
            };
            sstp.tls.sni_hostname = NoneOrOne::One("vpn.example.com".into());
            super::super::validate_client_config(&mut config, &std::collections::HashMap::new())
                .unwrap();
        }

        /// `:443` parses to an empty hostname, which the connector cannot
        /// turn into a name to verify or a Host header.
        #[test]
        fn an_empty_address_hostname_is_refused_at_load() {
            use crate::address::NetLocation;
            use crate::config::ClientConfig;
            let mut config = ClientConfig {
                address: NetLocation::from_str(":443", None).unwrap(),
                protocol: ClientProxyConfig::Sstp(Box::new(sstp())),
                ..Default::default()
            };
            let err = super::super::validate_client_config(
                &mut config,
                &std::collections::HashMap::new(),
            )
            .unwrap_err();
            assert!(
                err.to_string().contains("SSTP address needs a host"),
                "{err}"
            );
        }

        /// The secret rides the request line, so it is limited to what a
        /// query string carries unescaped.
        #[test]
        fn a_camouflage_secret_is_a_bare_query_string() {
            for bad in ["", "a b", "a?b", "a/b", "a#b", "сек"] {
                let mut config = sstp();
                config.camouflage_secret = Some(bad.to_string().into());
                let err = super::super::validate_sstp(&mut config).unwrap_err();
                assert!(
                    err.to_string().contains("camouflage_secret"),
                    "{bad:?}: {err}"
                );
            }
            let mut config = sstp();
            config.camouflage_secret = Some("0123abcd".to_string().into());
            super::super::validate_sstp(&mut config).unwrap();
        }

        /// PAP's lengths are one octet of bytes; MS-CHAPv2's are not.
        #[test]
        fn pap_bounds_the_credentials_at_255_bytes() {
            let mut config = sstp();
            config.username = "u".repeat(256);
            super::super::validate_sstp(&mut config).unwrap();
            config.auth.push(SstpAuthMethod::Pap);
            let err = super::super::validate_sstp(&mut config).unwrap_err();
            assert!(err.to_string().contains("255 bytes"), "{err}");

            let mut config = sstp();
            config.auth = vec![SstpAuthMethod::Pap];
            // 128 characters, within MS-CHAPv2's 256 UTF-16 units, 256 bytes.
            config.password = "é".repeat(128).into();
            let err = super::super::validate_sstp(&mut config).unwrap_err();
            assert!(err.to_string().contains("255 bytes"), "{err}");
        }

        /// Under a wrapping layer the chain builder would hand a transport
        /// owner to the per-stream handler factory, which panics on it.
        #[test]
        fn a_transport_owner_under_any_layer_is_refused() {
            let inner = Box::new(ClientProxyConfig::Sstp(Box::new(sstp())));
            let websocket: ClientProxyConfig =
                serde_yaml::from_str("type: websocket\nprotocol: {type: direct}").unwrap();
            let ClientProxyConfig::Websocket(mut ws) = websocket else {
                panic!("websocket");
            };
            ws.protocol = inner.clone();
            let err =
                super::super::validate_client_proxy_structure(&ClientProxyConfig::Websocket(ws))
                    .unwrap_err();
            assert!(
                err.to_string().contains("SSTP owns its transport")
                    && err.to_string().contains("WebSocket"),
                "{err}"
            );

            let tls: ClientProxyConfig =
                serde_yaml::from_str("type: tls\nprotocol: {type: direct}").unwrap();
            let ClientProxyConfig::Tls(mut tls) = tls else {
                panic!("tls");
            };
            tls.protocol = inner;
            let err = super::super::validate_client_proxy_structure(&ClientProxyConfig::Tls(tls))
                .unwrap_err();
            assert!(
                err.to_string().contains("sstp protocol's tls block"),
                "{err}"
            );
        }
    }

    mod quic_outbounds {
        use super::*;
        use crate::address::NetLocation;
        use crate::config::types::client::{
            Hysteria2ClientConfig, MieruClientConfig, PortHoppingConfig, PortHoppingFields,
            TuicClientConfig, TuicUdpRelayMode,
        };
        use crate::config::types::transport::{ClientQuicConfig, TcpConfig};

        fn server() -> NetLocation {
            NetLocation::from_str("example.com:443", None).unwrap()
        }

        fn hysteria2_client(obfs: Option<ObfsConfig>) -> ClientConfig {
            ClientConfig {
                address: server(),
                protocol: ClientProxyConfig::Hysteria2(Box::new(Hysteria2ClientConfig {
                    password: "secret".into(),
                    udp_enabled: true,
                    obfs,
                    port_hopping: None,
                })),
                ..Default::default()
            }
        }

        fn tuic_client(uuid: &str, heartbeat_ms: u64) -> ClientConfig {
            ClientConfig {
                address: server(),
                protocol: ClientProxyConfig::Tuic(Box::new(TuicClientConfig {
                    uuid: uuid.parse().unwrap(),
                    password: "secret".into(),
                    udp_enabled: true,
                    udp_relay_mode: TuicUdpRelayMode::Native,
                    zero_rtt_handshake: false,
                    heartbeat_ms,
                    congestion_control: Default::default(),
                })),
                ..Default::default()
            }
        }

        fn validate(config: &mut ClientConfig) -> std::io::Result<()> {
            validate_client_config(config, &HashMap::new())
        }

        fn hysteria2_client_with_hopping(hopping: Option<PortHoppingConfig>) -> ClientConfig {
            ClientConfig {
                // A literal address: port hopping fixes the peer for the
                // connection's life, so the hostname form is refused.
                address: NetLocation::from_str("203.0.113.10:443", None).unwrap(),
                protocol: ClientProxyConfig::Hysteria2(Box::new(Hysteria2ClientConfig {
                    password: "secret".into(),
                    udp_enabled: true,
                    obfs: None,
                    port_hopping: hopping,
                })),
                ..Default::default()
            }
        }

        fn fields(ports: &str) -> PortHoppingFields {
            PortHoppingFields {
                ports: ports.to_string(),
                interval_ms: None,
                min_interval_ms: None,
                max_interval_ms: None,
            }
        }

        fn hopping(ports: &str) -> PortHoppingConfig {
            PortHoppingConfig::try_from(fields(ports)).unwrap()
        }

        /// What parsing `fields` says, as the user would read it.
        fn refusal(fields: PortHoppingFields) -> String {
            PortHoppingConfig::try_from(fields).unwrap_err()
        }

        #[test]
        fn test_port_hopping_accepts_a_range() {
            let mut config = hysteria2_client_with_hopping(Some(hopping("20000-20010")));
            assert!(validate(&mut config).is_ok());
        }

        /// Nothing to hop between is not a configuration, it is a typo.
        #[test]
        fn test_port_hopping_rejects_an_unparsable_range() {
            assert!(PortHoppingConfig::try_from(fields("not-ports")).is_err());
        }

        /// Upstream's floor. Below it the hop rate is itself a signature, and
        /// a silently clamped value would be a setting that does not do what
        /// it says. It used to be checked only here; the parser now refuses
        /// it wherever the settings come from.
        #[test]
        fn test_port_hopping_rejects_an_interval_under_the_floor() {
            let mut f = fields("20000-20010");
            f.interval_ms = Some(4_999);
            let err = refusal(f);
            assert!(err.contains("interval_ms must be at least 5000"), "{err}");

            let mut f = fields("20000-20010");
            f.min_interval_ms = Some(4_999);
            f.max_interval_ms = Some(10_000);
            assert!(refusal(f).contains("min_interval_ms must be at least 5000"));
        }

        #[test]
        fn test_port_hopping_rejects_an_inverted_range() {
            let mut f = fields("20000-20010");
            f.min_interval_ms = Some(30_000);
            f.max_interval_ms = Some(10_000);
            assert!(refusal(f).contains("is greater than max_interval_ms"));
        }

        /// Two answers to one question. Picking one silently would be a guess
        /// the user never sees.
        #[test]
        fn test_port_hopping_rejects_a_fixed_interval_beside_a_range() {
            let mut f = fields("20000-20010");
            f.interval_ms = Some(30_000);
            f.min_interval_ms = Some(10_000);
            f.max_interval_ms = Some(20_000);
            assert!(refusal(f).contains("not both"));
        }

        #[test]
        fn test_port_hopping_rejects_half_a_range() {
            let mut f = fields("20000-20010");
            f.min_interval_ms = Some(10_000);
            assert!(refusal(f).contains("or neither"));
        }

        /// Port 0 parses as a port but is not a destination.
        #[test]
        fn test_port_hopping_rejects_port_zero() {
            assert!(PortHoppingConfig::try_from(fields("0-1000")).is_err());
            assert!(PortHoppingConfig::try_from(fields("0,20000-20005")).is_err());
        }

        /// The YAML a user writes reaches the same refusal, with the field.
        #[test]
        fn test_a_bad_hopping_block_is_a_parse_error() {
            let yaml = "ports: 20000-20010\ninterval_ms: 1000\n";
            let err = serde_yaml::from_str::<PortHoppingConfig>(yaml)
                .unwrap_err()
                .to_string();
            assert!(
                err.contains("port_hopping interval_ms must be at least 5000"),
                "{err}"
            );
        }

        /// A hostname has nowhere to re-resolve to once the connection is up,
        /// so it is refused at load rather than failing when the endpoint is
        /// built.
        #[test]
        fn test_port_hopping_rejects_a_hostname_address() {
            let mut config = hysteria2_client_with_hopping(Some(hopping("20000-20010")));
            config.address = NetLocation::from_str("example.com:443", None).unwrap();
            let err = validate(&mut config).unwrap_err();
            assert!(err.to_string().contains("literal IP"), "{err}");
        }

        #[test]
        fn test_hysteria2_allows_quic_settings() {
            let mut config = hysteria2_client(None);
            config.quic_settings = Some(ClientQuicConfig::default());
            assert!(validate(&mut config).is_ok());
        }

        #[test]
        fn test_wireguard_still_rejects_quic_settings() {
            let mut config = ClientConfig {
                address: server(),
                protocol: ClientProxyConfig::Wireguard(Box::new(
                    crate::config::WireGuardClientConfig {
                        private_key: "cHJpdmF0ZWtleXByaXZhdGVrZXlwcml2YXRla2V5MTI="
                            .parse::<crate::config::WgKey>()
                            .unwrap()
                            .into(),
                        peer_public_key: "cHVibGlja2V5cHVibGlja2V5cHVibGlja2V5MTIzNDU="
                            .parse()
                            .unwrap(),
                        preshared_key: None,
                        local_addresses: OneOrSome::One("10.0.0.2/32".parse().unwrap()),
                        allowed_ips: OneOrSome::One("0.0.0.0/0".parse().unwrap()),
                        persistent_keepalive: None,
                        mtu: 1280,
                    },
                )),
                quic_settings: Some(ClientQuicConfig::default()),
                ..Default::default()
            };
            let err = validate(&mut config).unwrap_err().to_string();
            assert!(err.contains("QUIC"), "{err}");
        }

        #[test]
        fn test_hysteria2_rejects_transport() {
            let mut config = hysteria2_client(None);
            config.transport = Transport::Quic;
            let err = validate(&mut config).unwrap_err().to_string();
            assert!(err.contains("transport"), "{err}");
        }

        #[test]
        fn test_hysteria2_rejects_tcp_settings() {
            let mut config = hysteria2_client(None);
            config.tcp_settings = Some(TcpConfig::default());
            let err = validate(&mut config).unwrap_err().to_string();
            assert!(err.contains("tcp_settings"), "{err}");
        }

        #[test]
        fn test_rejects_short_obfs_password() {
            let mut config = hysteria2_client(Some(ObfsConfig::Salamander {
                password: "abc".into(),
            }));
            let err = validate(&mut config).unwrap_err().to_string();
            assert!(err.contains('4'), "error should state the minimum: {err}");
        }

        #[test]
        fn test_accepts_four_byte_obfs_password() {
            let mut config = hysteria2_client(Some(ObfsConfig::Salamander {
                password: "abcd".into(),
            }));
            assert!(validate(&mut config).is_ok());
        }

        #[test]
        fn test_tuic_rejects_bad_uuid() {
            // At parse time now: a `Uuid` field does not deserialize from it.
            let yaml = "address: 127.0.0.1:443\nprotocol:\n  type: tuic\n  uuid: not-a-uuid\n  password: secret\n";
            let err = serde_yaml::from_str::<ClientConfig>(yaml)
                .unwrap_err()
                .to_string();
            assert!(err.to_lowercase().contains("uuid"), "{err}");
        }

        #[test]
        fn test_tuic_accepts_a_valid_uuid() {
            let mut config = tuic_client("b0e80a62-8a51-47f0-91f1-f0f7faf8d9d4", 10_000);
            assert!(validate(&mut config).is_ok());
        }

        #[test]
        fn test_tuic_accepts_the_quic_relay_mode() {
            let mut config = tuic_client("b0e80a62-8a51-47f0-91f1-f0f7faf8d9d4", 10_000);
            let ClientProxyConfig::Tuic(ref mut tuic) = config.protocol else {
                unreachable!()
            };
            tuic.udp_relay_mode = crate::config::TuicUdpRelayMode::Quic;
            assert!(validate(&mut config).is_ok());
        }

        #[test]
        fn test_tuic_rejects_zero_rtt_until_the_client_implements_it() {
            let mut config = tuic_client("b0e80a62-8a51-47f0-91f1-f0f7faf8d9d4", 10_000);
            let ClientProxyConfig::Tuic(ref mut tuic) = config.protocol else {
                unreachable!()
            };
            tuic.zero_rtt_handshake = true;
            let err = validate(&mut config).unwrap_err().to_string();
            assert!(err.contains("zero_rtt_handshake"), "{err}");
        }

        fn mieru_client() -> ClientConfig {
            ClientConfig {
                address: server(),
                protocol: ClientProxyConfig::Mieru(MieruClientConfig {
                    username: "alice".to_string(),
                    password: "hunter2".into(),
                }),
                ..Default::default()
            }
        }

        #[test]
        fn test_mieru_accepts_the_tcp_transport() {
            let mut config = mieru_client();
            assert!(validate(&mut config).is_ok());
        }

        /// The key is derived from both credentials, so an empty one is not a
        /// weak password - it is a config that cannot authenticate against
        /// anything. Upstream refuses to dial in the same situation
        /// (`pkg/appctl/appctlcommon/client.go:57-63`).
        #[test]
        fn test_mieru_rejects_empty_credentials() {
            let mut config = mieru_client();
            if let ClientProxyConfig::Mieru(mieru) = &mut config.protocol {
                mieru.username = String::new();
            }
            let err = validate(&mut config).unwrap_err();
            assert!(err.to_string().contains("username"), "{err}");

            let mut config = mieru_client();
            if let ClientProxyConfig::Mieru(mieru) = &mut config.protocol {
                mieru.password = "".into();
            }
            let err = validate(&mut config).unwrap_err();
            assert!(err.to_string().contains("password"), "{err}");
        }

        /// 64 bytes is the ceiling upstream enforces on both fields, so a
        /// longer one is a config a matching server would refuse. Failing at
        /// load names the field; failing at connect time does not.
        #[test]
        fn test_mieru_rejects_over_long_credentials() {
            let mut config = mieru_client();
            if let ClientProxyConfig::Mieru(mieru) = &mut config.protocol {
                mieru.username = "x".repeat(MIERU_MAX_CREDENTIAL_LEN + 1);
            }
            assert!(validate(&mut config).is_err());

            let mut config = mieru_client();
            if let ClientProxyConfig::Mieru(mieru) = &mut config.protocol {
                mieru.password = "x".repeat(MIERU_MAX_CREDENTIAL_LEN + 1).into();
            }
            assert!(validate(&mut config).is_err());

            // And exactly at the limit is fine.
            let mut config = mieru_client();
            if let ClientProxyConfig::Mieru(mieru) = &mut config.protocol {
                mieru.username = "x".repeat(MIERU_MAX_CREDENTIAL_LEN);
                mieru.password = "x".repeat(MIERU_MAX_CREDENTIAL_LEN).into();
            }
            assert!(validate(&mut config).is_ok());
        }

        /// mieru defines exactly two transports, TCP and UDP, and this client
        /// implements the first. Carrying its TCP framing over QUIC or over a
        /// datagram transport produces bytes no mieru server understands, so
        /// the combination is refused rather than dialled.
        #[test]
        fn test_mieru_rejects_a_non_tcp_transport() {
            for transport in [Transport::Quic, Transport::Udp] {
                let mut config = mieru_client();
                config.transport = transport;
                let err = validate(&mut config).unwrap_err().to_string();
                assert!(
                    err.contains("mieru"),
                    "the error should name the protocol: {err}"
                );
                assert!(
                    err.to_lowercase().contains("transport"),
                    "the error should name the setting: {err}"
                );
            }
        }

        /// The options mieru has and this client does not are not shoes config
        /// fields, so serde refuses them by name before validation runs. Pinned
        /// so that adding one of them as a real field cannot silently become a
        /// no-op.
        #[test]
        fn test_mieru_refuses_unimplemented_mieru_options_by_name() {
            for field in [
                "multiplexing",
                "low_entropy",
                "port_range",
                "handshake_mode",
            ] {
                let yaml = format!(
                    "type: mieru\nusername: alice\npassword: hunter2\n{field}: something\n"
                );
                let err = serde_yaml::from_str::<ClientProxyConfig>(&yaml)
                    .unwrap_err()
                    .to_string();
                assert!(
                    err.contains(field),
                    "refusing {field} should name it: {err}"
                );
            }
        }

        #[test]
        fn test_tuic_rejects_zero_heartbeat() {
            let mut config = tuic_client("b0e80a62-8a51-47f0-91f1-f0f7faf8d9d4", 0);
            let err = validate(&mut config).unwrap_err().to_string();
            assert!(err.contains("heartbeat_ms"), "{err}");
        }
    }

    /// The matches on the proxy config enums in this file end in `_ => {}`, so
    /// a transport whose arm is missing is skipped in silence -- the protocol
    /// it wraps is never validated. The inner rule here names a client group
    /// that does not exist, which only that recursion can catch.
    #[tokio::test]
    async fn httpupgrade_validates_the_protocol_it_wraps() {
        let yaml = r#"
- address: 0.0.0.0:8443
  protocol:
    type: httpupgrade
    targets:
      - matching_path: /download
        protocol:
          type: socks
        override_rules:
          - mask: 0.0.0.0/0
            action: allow
            client_chain: no-such-group
  rules:
    - mask: 0.0.0.0/0
      action: allow
"#;
        let configs: Vec<Config> = serde_yaml::from_str(yaml).unwrap();
        let err = validate_configs_test(configs)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("no-such-group"),
            "the wrapped protocol's rules were not validated: {err}"
        );
    }

    async fn validate_configs_test(configs: Vec<Config>) -> std::io::Result<Vec<Config>> {
        let (converted_configs, _) = convert_cert_paths(configs).await?;
        let validated = create_server_configs(converted_configs)?;
        Ok(validated.configs)
    }

    fn tun_yaml_with_dns(server_url: &str, bootstrap: Option<&str>) -> String {
        let bootstrap_line = match bootstrap {
            Some(b) => format!("\n        bootstrap_url: \"{b}\""),
            None => String::new(),
        };
        format!(
            r#"
- device_name: "{TEST_TUN_DEVICE_NAME}"
  address: "10.99.0.1"
  netmask: "255.255.255.0"
  dns:
    servers:
      - url: "{server_url}"{bootstrap_line}
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain:
        - protocol:
            type: direct
"#
        )
    }

    /// A hostname DoH URL without a bootstrap resolves through the system
    /// resolver -- on a TUN, the plaintext leak the dns block exists to
    /// prevent. Rejected, with the message naming both fixes.
    #[tokio::test]
    async fn tun_dns_with_hostname_url_and_no_bootstrap_is_rejected() {
        let yaml = tun_yaml_with_dns("https://dns.example.com/dns-query", None);
        let configs: Vec<Config> = serde_yaml::from_str(&yaml).unwrap();
        let err = validate_configs_test(configs).await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("bootstrap_url"), "got: {msg}");
        assert!(msg.contains("IP-address URL"), "got: {msg}");
    }

    /// The IP-URL shape a client emits to avoid the chicken-and-egg needs
    /// no bootstrap and must keep validating.
    #[tokio::test]
    async fn tun_dns_with_ip_url_needs_no_bootstrap() {
        let yaml = tun_yaml_with_dns("https://1.1.1.1/dns-query", None);
        let configs: Vec<Config> = serde_yaml::from_str(&yaml).unwrap();
        validate_configs_test(configs).await.unwrap();
    }

    /// A hostname URL WITH an IP bootstrap has no silent fallback and is
    /// allowed.
    #[tokio::test]
    async fn tun_dns_with_hostname_url_and_ip_bootstrap_is_allowed() {
        let yaml = tun_yaml_with_dns("https://dns.example.com/dns-query", Some("udp://1.1.1.1"));
        let configs: Vec<Config> = serde_yaml::from_str(&yaml).unwrap();
        validate_configs_test(configs).await.unwrap();
    }

    /// `system` one hop down is the same silent fallback the direct form
    /// is rejected for: a hostname URL bootstrapped by a group containing
    /// `url: system` still resolves the hostname over plaintext UDP:53.
    #[tokio::test]
    async fn tun_dns_bootstrapped_by_a_system_group_is_rejected() {
        let yaml = &format!(
            r#"
- dns_group: "sysgroup"
  dns_servers:
    - url: "system"
- device_name: "{TEST_TUN_DEVICE_NAME}"
  address: "10.99.0.1"
  netmask: "255.255.255.0"
  dns:
    servers:
      - url: "https://dns.example.com/dns-query"
        bootstrap_url: "sysgroup"
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain:
        - protocol:
            type: direct
"#
        );
        let configs: Vec<Config> = serde_yaml::from_str(yaml).unwrap();
        let err = validate_configs_test(configs).await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("system"), "got: {msg}");
        assert!(msg.contains("bootstrap"), "got: {msg}");
    }

    /// `url: system` directly in the TUN's own group is the explicit
    /// request it looks like, and stays allowed.
    #[tokio::test]
    async fn tun_dns_with_explicit_system_url_is_allowed() {
        let yaml = tun_yaml_with_dns("system", None);
        let configs: Vec<Config> = serde_yaml::from_str(&yaml).unwrap();
        validate_configs_test(configs).await.unwrap();
    }

    /// A DNS upstream reached through a client_chain hop at a hostname
    /// resolves that hop with the system resolver -- the leak moves one
    /// layer, it does not close. Rejected with the hop named.
    #[tokio::test]
    async fn tun_dns_with_hostname_chain_hop_is_rejected() {
        let yaml = &format!(
            r#"
- device_name: "{TEST_TUN_DEVICE_NAME}"
  address: "10.99.0.1"
  netmask: "255.255.255.0"
  dns:
    servers:
      - url: "https://1.1.1.1/dns-query"
        client_chain:
          - address: "proxy.example.com:1080"
            protocol:
              type: socks
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain:
        - protocol:
            type: direct
"#
        );
        let configs: Vec<Config> = serde_yaml::from_str(yaml).unwrap();
        let err = validate_configs_test(configs).await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("proxy.example.com"), "got: {msg}");
        assert!(msg.contains("client_chain"), "got: {msg}");
    }

    /// The same hostname-without-bootstrap group on a plain server keeps
    /// today's behaviour: the system-bootstrap default is a documented
    /// convenience outside TUN mode.
    #[tokio::test]
    async fn server_dns_with_hostname_url_and_no_bootstrap_still_validates() {
        let yaml = r#"
- address: "127.0.0.1:18599"
  transport: tcp
  protocol:
    type: socks
  dns:
    servers:
      - url: "https://dns.example.com/dns-query"
"#;
        let configs: Vec<Config> = serde_yaml::from_str(yaml).unwrap();
        validate_configs_test(configs).await.unwrap();
    }

    #[tokio::test]
    async fn test_validate_config_success() {
        use crate::config::types::ClientConfigGroup;
        use crate::config::types::groups::RuleConfigGroup;

        let configs = vec![
            Config::RuleConfigGroup(RuleConfigGroup {
                rule_group: "test-rules".to_string(),
                rules: OneOrSome::One(RuleConfig {
                    masks: OneOrSome::One(NetLocationMask::ANY),
                    action: RuleActionConfig::Allow {
                        override_address: None,
                        client_chains: NoneOrSome::One(ClientChain::default()),
                    },
                    ..Default::default()
                }),
            }),
            Config::ClientConfigGroup(ClientConfigGroup {
                client_group: "test-group".to_string(),
                client_proxies: OneOrSome::One(ConfigSelection::Config(ClientConfig::default())),
            }),
        ];

        assert!(validate_configs_test(configs).await.is_ok());
    }

    #[tokio::test]
    async fn test_topological_sort_simple() {
        use crate::config::types::ClientConfigGroup;

        // group-b has no dependencies, group-a references group-b
        let configs = vec![
            Config::ClientConfigGroup(ClientConfigGroup {
                client_group: "group-a".to_string(),
                client_proxies: OneOrSome::One(ConfigSelection::GroupName("group-b".to_string())),
            }),
            Config::ClientConfigGroup(ClientConfigGroup {
                client_group: "group-b".to_string(),
                client_proxies: OneOrSome::One(ConfigSelection::Config(ClientConfig::default())),
            }),
        ];

        assert!(validate_configs_test(configs).await.is_ok());
    }

    #[tokio::test]
    async fn test_topological_sort_cycle_detected() {
        use crate::config::types::ClientConfigGroup;

        let configs = vec![
            Config::ClientConfigGroup(ClientConfigGroup {
                client_group: "group-a".to_string(),
                client_proxies: OneOrSome::One(ConfigSelection::GroupName("group-b".to_string())),
            }),
            Config::ClientConfigGroup(ClientConfigGroup {
                client_group: "group-b".to_string(),
                client_proxies: OneOrSome::One(ConfigSelection::GroupName("group-a".to_string())),
            }),
        ];

        let result = validate_configs_test(configs).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("Circular dependency"),
            "Error should mention circular dependency: {err}"
        );
    }

    #[tokio::test]
    async fn test_topological_sort_unknown_group() {
        use crate::config::types::ClientConfigGroup;

        let configs = vec![Config::ClientConfigGroup(ClientConfigGroup {
            client_group: "group-a".to_string(),
            client_proxies: OneOrSome::One(ConfigSelection::GroupName("nonexistent".to_string())),
        })];

        let result = validate_configs_test(configs).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown group") || err.contains("Unknown"),
            "Error should mention unknown group: {err}"
        );
    }

    #[tokio::test]
    async fn test_topological_sort_diamond() {
        use crate::config::types::ClientConfigGroup;

        // Diamond: a -> b, a -> c, b -> d, c -> d
        let configs = vec![
            Config::ClientConfigGroup(ClientConfigGroup {
                client_group: "group-d".to_string(),
                client_proxies: OneOrSome::One(ConfigSelection::Config(ClientConfig::default())),
            }),
            Config::ClientConfigGroup(ClientConfigGroup {
                client_group: "group-c".to_string(),
                client_proxies: OneOrSome::One(ConfigSelection::GroupName("group-d".to_string())),
            }),
            Config::ClientConfigGroup(ClientConfigGroup {
                client_group: "group-b".to_string(),
                client_proxies: OneOrSome::One(ConfigSelection::GroupName("group-d".to_string())),
            }),
            Config::ClientConfigGroup(ClientConfigGroup {
                client_group: "group-a".to_string(),
                client_proxies: OneOrSome::Some(vec![
                    ConfigSelection::GroupName("group-b".to_string()),
                    ConfigSelection::GroupName("group-c".to_string()),
                ]),
            }),
        ];

        assert!(validate_configs_test(configs).await.is_ok());
    }

    #[tokio::test]
    async fn test_nested_groups_resolve() {
        use crate::config::types::ClientConfigGroup;

        let configs = vec![
            Config::ClientConfigGroup(ClientConfigGroup {
                client_group: "us-proxies".to_string(),
                client_proxies: OneOrSome::One(ConfigSelection::Config(ClientConfig::default())),
            }),
            Config::ClientConfigGroup(ClientConfigGroup {
                client_group: "eu-proxies".to_string(),
                client_proxies: OneOrSome::One(ConfigSelection::Config(ClientConfig::default())),
            }),
            Config::ClientConfigGroup(ClientConfigGroup {
                client_group: "all-proxies".to_string(),
                client_proxies: OneOrSome::Some(vec![
                    ConfigSelection::GroupName("us-proxies".to_string()),
                    ConfigSelection::GroupName("eu-proxies".to_string()),
                ]),
            }),
        ];

        assert!(validate_configs_test(configs).await.is_ok());
    }

    #[tokio::test]
    async fn test_empty_config() {
        let original: Vec<Config> = vec![];
        let yaml_str = serde_yaml::to_string(&original).expect("Failed to serialize");
        let deserialized: Vec<Config> =
            serde_yaml::from_str(&yaml_str).expect("Failed to deserialize");

        assert_eq!(deserialized.len(), 0);
        assert!(validate_configs_test(deserialized).await.is_ok());
    }

    #[tokio::test]
    async fn test_named_pem_duplicate_names() {
        let configs = vec![
            Config::NamedPem(super::super::types::NamedPem {
                pem: "duplicate-name".to_string(),
                source: PemSource::Data("pem1".to_string()),
            }),
            Config::NamedPem(super::super::types::NamedPem {
                pem: "duplicate-name".to_string(),
                source: PemSource::Data("pem2".to_string()),
            }),
        ];

        let result = validate_configs_test(configs).await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("named pem already exists: duplicate-name")
        );
    }

    #[tokio::test]
    async fn test_recursive_certificate_embedding() {
        let test_dir = tempfile::tempdir().unwrap();
        let cert_dir = test_dir.path().join("certs");
        tokio::fs::create_dir_all(&cert_dir).await.unwrap();

        // Forward slashes even on Windows: the path is interpolated into
        // double-quoted YAML scalars below, where a backslash starts an
        // escape sequence ("C:\Users" reads as an \U unicode escape and the
        // parse fails). Windows file APIs accept either separator.
        let cert_dir = std::path::PathBuf::from(cert_dir.display().to_string().replace('\\', "/"));

        let test_cert = "-----BEGIN CERTIFICATE-----\nTEST CERT CONTENT\n-----END CERTIFICATE-----";
        let test_key = "-----BEGIN PRIVATE KEY-----\nTEST KEY CONTENT\n-----END PRIVATE KEY-----";

        let cert_files = vec![
            ("quic.crt", test_cert),
            ("quic.key", test_key),
            ("server.crt", test_cert),
            ("server.key", test_key),
            ("ca.crt", test_cert),
            ("shadow.crt", test_cert),
            ("shadow.key", test_key),
            ("client-quic.crt", test_cert),
            ("client-quic.key", test_key),
            ("client.crt", test_cert),
            ("client.key", test_key),
        ];

        for (filename, content) in cert_files {
            let path = cert_dir.join(filename);
            tokio::fs::write(&path, content).await.unwrap();
        }

        let config_yaml = format!(
            r#"
- address: "0.0.0.0:443"
  transport: quic
  quic_settings:
    cert: "{}/quic.crt"
    key: "{}/quic.key"
  protocol:
    type: tls
    sni_targets:
      "example.com":
        cert: "{}/server.crt"
        key: "{}/server.key"
        client_ca_certs:
          - "{}/ca.crt"
        protocol:
          type: websocket
          targets:
            - matching_path: "/ws"
              protocol:
                type: vmess
                cipher: auto
                user_id: "123e4567-e89b-42d3-a456-426614174000"
    shadowtls_targets:
      "shadow.com":
        password: "shadowpass"
        handshake:
          cert: "{}/shadow.crt"
          key: "{}/shadow.key"
        protocol:
          type: socks
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain:
        - address: "proxy.example.com:443"
          transport: quic
          quic_settings:
            cert: "{}/client-quic.crt"
            key: "{}/client-quic.key"
          protocol:
            type: tls
            cert: "{}/client.crt"
            key: "{}/client.key"
            protocol:
              type: http
"#,
            cert_dir.display(),
            cert_dir.display(),
            cert_dir.display(),
            cert_dir.display(),
            cert_dir.display(),
            cert_dir.display(),
            cert_dir.display(),
            cert_dir.display(),
            cert_dir.display(),
            cert_dir.display(),
            cert_dir.display()
        );

        let configs: Vec<Config> = serde_yaml::from_str(&config_yaml).unwrap();
        let (converted_configs, load_count) = convert_cert_paths(configs).await.unwrap();

        assert_eq!(load_count, 11);

        let validated = create_server_configs(converted_configs).unwrap();
        let Config::Server(server_config) = &validated.configs[0] else {
            panic!("expected Config::Server");
        };

        let quic_settings = server_config.quic_settings.as_ref().unwrap();
        assert!(quic_settings.cert.contains("BEGIN CERTIFICATE"));
        assert!(quic_settings.key.contains("BEGIN PRIVATE KEY"));

        if let ServerProxyConfig::Tls {
            tls_targets,
            shadowtls_targets,
            ..
        } = &server_config.protocol
        {
            let tls_config = tls_targets.get("example.com").unwrap();
            assert!(tls_config.cert.contains("BEGIN CERTIFICATE"));
            assert!(tls_config.key.contains("BEGIN PRIVATE KEY"));

            let shadow_config = shadowtls_targets.get("shadow.com").unwrap();
            if let ShadowTlsServerHandshakeConfig::Local(handshake) = &shadow_config.handshake {
                assert!(handshake.cert.contains("BEGIN CERTIFICATE"));
                assert!(handshake.key.contains("BEGIN PRIVATE KEY"));
            }
        }
    }

    #[test]
    fn test_direct_connector_at_hop_0_allowed() {
        // Single direct connector at hop 0 should be allowed
        let hops = OneOrSome::One(ClientChainHop::Single(ConfigSelection::Config(
            ClientConfig::default(), // default is direct
        )));

        assert!(validate_direct_connector_positions(&hops, 0).is_ok());
    }

    fn http_proxy_config() -> ClientProxyConfig {
        ClientProxyConfig::Http {
            username: None,
            password: None,
            resolve_hostname: false,
        }
    }

    fn socks_proxy_config() -> ClientProxyConfig {
        ClientProxyConfig::Socks {
            username: None,
            password: None,
        }
    }

    #[test]
    fn test_direct_then_proxy_allowed() {
        // Direct at hop 0, proxy at hop 1 - should be allowed
        let hops = OneOrSome::Some(vec![
            ClientChainHop::Single(ConfigSelection::Config(ClientConfig::default())),
            ClientChainHop::Single(ConfigSelection::Config(ClientConfig {
                protocol: http_proxy_config(),
                ..Default::default()
            })),
        ]);

        assert!(validate_direct_connector_positions(&hops, 0).is_ok());
    }

    #[test]
    fn test_proxy_then_proxy_allowed() {
        // Proxy at hop 0, proxy at hop 1 - should be allowed
        let hops = OneOrSome::Some(vec![
            ClientChainHop::Single(ConfigSelection::Config(ClientConfig {
                protocol: http_proxy_config(),
                ..Default::default()
            })),
            ClientChainHop::Single(ConfigSelection::Config(ClientConfig {
                protocol: socks_proxy_config(),
                ..Default::default()
            })),
        ]);

        assert!(validate_direct_connector_positions(&hops, 0).is_ok());
    }

    #[test]
    fn test_direct_at_hop_1_rejected() {
        // Direct at hop 1 should be rejected
        let hops = OneOrSome::Some(vec![
            ClientChainHop::Single(ConfigSelection::Config(ClientConfig {
                protocol: http_proxy_config(),
                ..Default::default()
            })),
            ClientChainHop::Single(ConfigSelection::Config(ClientConfig::default())), // direct
        ]);

        let result = validate_direct_connector_positions(&hops, 0);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("hop 1"));
    }

    #[test]
    fn test_direct_in_middle_of_chain_rejected() {
        // Direct in the middle of a 3-hop chain should be rejected
        let hops = OneOrSome::Some(vec![
            ClientChainHop::Single(ConfigSelection::Config(ClientConfig {
                protocol: http_proxy_config(),
                ..Default::default()
            })),
            ClientChainHop::Single(ConfigSelection::Config(ClientConfig::default())), // direct
            ClientChainHop::Single(ConfigSelection::Config(ClientConfig {
                protocol: socks_proxy_config(),
                ..Default::default()
            })),
        ]);

        let result = validate_direct_connector_positions(&hops, 0);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("hop 1"));
    }

    #[test]
    fn test_direct_in_pool_at_hop_0_allowed() {
        // Mixed pool at hop 0 with direct - should be allowed
        let hops = OneOrSome::One(ClientChainHop::Pool(OneOrSome::Some(vec![
            ConfigSelection::Config(ClientConfig::default()), // direct
            ConfigSelection::Config(ClientConfig {
                protocol: http_proxy_config(),
                ..Default::default()
            }),
        ])));

        assert!(validate_direct_connector_positions(&hops, 0).is_ok());
    }

    #[test]
    fn test_direct_in_pool_at_hop_1_rejected() {
        // Mixed pool at hop 1 with direct - should be rejected
        let hops = OneOrSome::Some(vec![
            ClientChainHop::Single(ConfigSelection::Config(ClientConfig {
                protocol: http_proxy_config(),
                ..Default::default()
            })),
            ClientChainHop::Pool(OneOrSome::Some(vec![
                ConfigSelection::Config(ClientConfig::default()), // direct
                ConfigSelection::Config(ClientConfig {
                    protocol: socks_proxy_config(),
                    ..Default::default()
                }),
            ])),
        ]);

        let result = validate_direct_connector_positions(&hops, 0);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("hop 1"));
    }

    #[test]
    fn test_three_hop_direct_first_then_proxies_allowed() {
        // Direct at hop 0, two proxies following - should be allowed
        let hops = OneOrSome::Some(vec![
            ClientChainHop::Single(ConfigSelection::Config(ClientConfig::default())), // direct
            ClientChainHop::Single(ConfigSelection::Config(ClientConfig {
                protocol: http_proxy_config(),
                ..Default::default()
            })),
            ClientChainHop::Single(ConfigSelection::Config(ClientConfig {
                protocol: socks_proxy_config(),
                ..Default::default()
            })),
        ]);

        assert!(validate_direct_connector_positions(&hops, 0).is_ok());
    }

    #[tokio::test]
    async fn test_tun_config_parsing() {
        let yaml = &format!(
            r#"
- device_name: "{TEST_TUN_DEVICE_NAME}"
  address: "10.0.0.1"
  netmask: "255.255.255.0"
  mtu: 1400
  tcp_enabled: true
  udp_enabled: true
  icmp_enabled: false
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain:
        - protocol:
            type: direct
"#
        );
        let configs: Vec<Config> = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(configs.len(), 1);

        match &configs[0] {
            Config::TunServer(tun) => {
                assert_eq!(tun.device_name, Some(TEST_TUN_DEVICE_NAME.to_string()));
                assert_eq!(tun.address, Some("10.0.0.1".parse().unwrap()));
                assert_eq!(tun.netmask, Some("255.255.255.0".parse().unwrap()));
                assert_eq!(tun.mtu, 1400);
                assert!(tun.tcp_enabled);
                assert!(tun.udp_enabled);
                assert!(!tun.icmp_enabled);
            }
            _ => panic!("Expected TunServer config"),
        }

        // Validate the config
        let result = validate_configs_test(configs).await;
        assert!(result.is_ok(), "TUN config validation failed: {:?}", result);
    }

    #[tokio::test]
    async fn test_tun_config_with_device_fd() {
        let yaml = r#"
- device_fd: 42
  mtu: 1500
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain:
        - protocol:
            type: direct
"#;
        let configs: Vec<Config> = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(configs.len(), 1);

        match &configs[0] {
            Config::TunServer(tun) => {
                assert_eq!(tun.device_fd, Some(42));
                assert_eq!(tun.device_name, None);
                assert_eq!(tun.mtu, 1500);
            }
            _ => panic!("Expected TunServer config"),
        }
    }

    #[tokio::test]
    async fn test_tun_config_defaults() {
        let yaml = r#"
- device_name: "tun0"
  address: "10.0.0.1"
"#;
        let configs: Vec<Config> = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(configs.len(), 1);

        match &configs[0] {
            Config::TunServer(tun) => {
                // Check defaults
                // The default is per platform; see `default_mtu`.
                let expected = if cfg!(target_os = "ios") {
                    4064
                } else if cfg!(any(target_os = "android", target_os = "linux")) {
                    9000
                } else {
                    1500
                };
                assert_eq!(tun.mtu, expected);
                assert!(tun.tcp_enabled); // default true
                assert!(tun.udp_enabled); // default true
                assert!(tun.icmp_enabled); // default true
            }
            _ => panic!("Expected TunServer config"),
        }
    }

    #[tokio::test]
    async fn test_tun_icmp_requires_tcp() {
        // ICMP requires TCP to be enabled
        let tun_config = TunConfig {
            device_name: Some("tun0".to_string()),
            device_fd: None,
            address: Some("10.0.0.1".parse().unwrap()),
            // Windows requires a netmask, and this test is about ICMP.
            netmask: Some("255.255.255.0".parse().unwrap()),
            destination: None,
            mtu: 1500,
            tcp_enabled: false, // TCP disabled
            udp_enabled: true,
            icmp_enabled: true, // but ICMP enabled - should fail
            rules: NoneOrSome::Unspecified,
            dns: None,
            fake_ip: None,
            sniff: None,
            tcp_buffer_size: None,
            max_connections: None,
            segmentation_offload: None,
        };

        let configs = vec![Config::TunServer(tun_config)];
        let result = validate_configs_test(configs).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("TCP must be enabled for ICMP"),
            "Expected ICMP/TCP error, got: {err}"
        );
    }

    fn tun_config_with_fake_ip(fake_ip: crate::config::types::FakeIpConfig) -> TunConfig {
        TunConfig {
            device_name: Some(TEST_TUN_DEVICE_NAME.to_string()),
            device_fd: None,
            address: Some("10.0.0.1".parse().unwrap()),
            // Windows requires a netmask, macOS a `utunN` name; these tests
            // are about fake_ip.
            netmask: Some("255.255.255.0".parse().unwrap()),
            destination: None,
            mtu: 1500,
            tcp_enabled: true,
            udp_enabled: true,
            icmp_enabled: false,
            rules: NoneOrSome::Unspecified,
            dns: None,
            fake_ip: Some(fake_ip),
            sniff: None,
            tcp_buffer_size: None,
            max_connections: None,
            segmentation_offload: None,
        }
    }

    fn fake_ip_config(network: &str) -> crate::config::types::FakeIpConfig {
        crate::config::types::FakeIpConfig {
            network: network.to_string(),
            max_entries: 1024,
            bypass_domains: NoneOrSome::Unspecified,
            bypass_defaults: true,
        }
    }

    /// Windows refuses `destination` at config time: wintun-bindings would
    /// turn it into `netsh ... gateway=`, a system default route through the
    /// adapter, which contradicts "shoes configures the adapter only".
    #[cfg(target_os = "windows")]
    #[tokio::test]
    async fn test_tun_windows_rejects_destination() {
        let mut tun_config = tun_config_with_fake_ip(fake_ip_config("198.18.0.0/16"));
        tun_config.fake_ip = None;
        tun_config.destination = Some("10.0.0.1".parse().unwrap());
        let err = validate_configs_test(vec![Config::TunServer(tun_config)])
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("destination"), "{err}");
    }

    /// An IPv6 adapter address cannot be expressed through wintun-bindings'
    /// netsh path, so it must fail at config time, not at tunnel start.
    #[cfg(target_os = "windows")]
    #[tokio::test]
    async fn test_tun_windows_rejects_an_ipv6_address() {
        let mut tun_config = tun_config_with_fake_ip(fake_ip_config("198.18.0.0/16"));
        tun_config.fake_ip = None;
        tun_config.address = Some("fd00::2".parse().unwrap());
        tun_config.netmask = Some("ffff:ffff::".parse().unwrap());
        let err = validate_configs_test(vec![Config::TunServer(tun_config)])
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("IPv4"), "{err}");
    }

    /// `segmentation_offload` is honoured only where shoes opens a Linux
    /// device itself; anywhere else an explicit value is refused rather
    /// than silently doing nothing.
    #[tokio::test]
    async fn test_tun_segmentation_offload_is_refused_where_it_cannot_apply() {
        let mut tun_config = tun_config_with_fake_ip(fake_ip_config("198.18.0.0/16"));
        tun_config.fake_ip = None;
        tun_config.segmentation_offload = Some(false);
        let result = validate_configs_test(vec![Config::TunServer(tun_config.clone())]).await;
        if cfg!(target_os = "linux") {
            assert!(result.is_ok(), "{:?}", result.err());

            tun_config.device_name = None;
            tun_config.address = None;
            tun_config.device_fd = Some(42);
            let err = validate_configs_test(vec![Config::TunServer(tun_config)])
                .await
                .unwrap_err()
                .to_string();
            assert!(err.contains("device_fd"), "{err}");
        } else {
            let err = result.unwrap_err().to_string();
            assert!(err.contains("only supported on Linux"), "{err}");
        }
    }

    #[tokio::test]
    async fn test_tun_fake_ip_accepts_a_valid_network() {
        let configs = vec![Config::TunServer(tun_config_with_fake_ip(fake_ip_config(
            "198.18.0.0/16",
        )))];
        assert!(validate_configs_test(configs).await.is_ok());
    }

    /// A bad CIDR must be a startup error. If it reached the data path it would
    /// have to either panic inside the VPN or disable DNS without saying so.
    #[tokio::test]
    async fn test_tun_fake_ip_rejects_a_bad_network() {
        for bad in ["198.18.0.0", "198.18.0.0/31", "not-a-network/16"] {
            let configs = vec![Config::TunServer(tun_config_with_fake_ip(fake_ip_config(
                bad,
            )))];
            assert!(
                validate_configs_test(configs).await.is_err(),
                "expected fake_ip network '{bad}' to be rejected"
            );
        }
    }

    #[tokio::test]
    async fn test_tun_fake_ip_rejects_zero_max_entries() {
        let mut fake_ip = fake_ip_config("198.18.0.0/16");
        fake_ip.max_entries = 0;
        let configs = vec![Config::TunServer(tun_config_with_fake_ip(fake_ip))];
        assert!(validate_configs_test(configs).await.is_err());
    }

    /// DNS queries arrive over UDP, so Fake IP with UDP disabled would accept
    /// the config and then never intercept anything.
    #[tokio::test]
    async fn test_tun_fake_ip_requires_udp() {
        let mut tun_config = tun_config_with_fake_ip(fake_ip_config("198.18.0.0/16"));
        tun_config.udp_enabled = false;
        let configs = vec![Config::TunServer(tun_config)];
        let err = validate_configs_test(configs)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("fake_ip requires udp_enabled"),
            "Expected fake_ip/UDP error, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_dns_system_with_client_chain_rejected() {
        let configs = vec![Config::DnsConfigGroup(DnsConfigGroup {
            dns_group: "test-dns".to_string(),
            dns_servers: NoneOrSome::One(DnsServerSpec::WithOptions {
                url: "system".to_string(),
                client_chain: NoneOrSome::One(ConfigSelection::Config(ClientChain::default())),
                bootstrap_url: None,
                server_name: None,
                ip_strategy: IpStrategy::default(),
                timeout_secs: 10,
                connect_timeout_secs: 5,
                attempts: 1,
            }),
        })];

        let result = validate_configs_test(configs).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("client_chain is not supported for system DNS"),
            "Expected system DNS client_chain error, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_dns_udp_with_proxy_chain_rejected() {
        use crate::config::types::{ClientConfigGroup, ClientProxyConfig};

        // Create a non-direct (socks5) chain - should be rejected for UDP.
        let socks_config = ClientConfig {
            protocol: ClientProxyConfig::Socks {
                username: None,
                password: None,
            },
            ..Default::default()
        };

        let configs = vec![
            Config::ClientConfigGroup(ClientConfigGroup {
                client_group: "test-proxy".to_string(),
                client_proxies: OneOrSome::One(ConfigSelection::Config(socks_config)),
            }),
            Config::DnsConfigGroup(DnsConfigGroup {
                dns_group: "test-dns".to_string(),
                dns_servers: NoneOrSome::One(DnsServerSpec::WithOptions {
                    url: "udp://8.8.8.8".to_string(),
                    client_chain: NoneOrSome::One(ConfigSelection::GroupName(
                        "test-proxy".to_string(),
                    )),
                    bootstrap_url: None,
                    server_name: None,
                    ip_strategy: IpStrategy::default(),
                    timeout_secs: 10,
                    connect_timeout_secs: 5,
                    attempts: 1,
                }),
            }),
        ];

        let result = validate_configs_test(configs).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("UDP DNS only supports direct client_chain"),
            "Expected UDP DNS client_chain error, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_dns_udp_with_direct_chain_allowed() {
        use crate::config::types::ClientConfigGroup;

        // Create a direct chain - should be allowed for UDP (for bind_interface).
        let configs = vec![
            Config::ClientConfigGroup(ClientConfigGroup {
                client_group: "direct-chain".to_string(),
                client_proxies: OneOrSome::One(ConfigSelection::Config(ClientConfig::default())),
            }),
            Config::DnsConfigGroup(DnsConfigGroup {
                dns_group: "test-dns".to_string(),
                dns_servers: NoneOrSome::One(DnsServerSpec::WithOptions {
                    url: "udp://8.8.8.8".to_string(),
                    client_chain: NoneOrSome::One(ConfigSelection::GroupName(
                        "direct-chain".to_string(),
                    )),
                    bootstrap_url: None,
                    server_name: None,
                    ip_strategy: IpStrategy::default(),
                    timeout_secs: 10,
                    connect_timeout_secs: 5,
                    attempts: 1,
                }),
            }),
        ];

        assert!(validate_configs_test(configs).await.is_ok());
    }

    #[tokio::test]
    async fn test_dns_h3_with_proxy_chain_rejected() {
        use crate::config::types::{ClientConfigGroup, ClientProxyConfig};

        // Create a non-direct (socks5) chain - should be rejected for H3.
        let socks_config = ClientConfig {
            protocol: ClientProxyConfig::Socks {
                username: None,
                password: None,
            },
            ..Default::default()
        };

        let configs = vec![
            Config::ClientConfigGroup(ClientConfigGroup {
                client_group: "test-proxy".to_string(),
                client_proxies: OneOrSome::One(ConfigSelection::Config(socks_config)),
            }),
            Config::DnsConfigGroup(DnsConfigGroup {
                dns_group: "test-dns".to_string(),
                dns_servers: NoneOrSome::One(DnsServerSpec::WithOptions {
                    url: "h3://1.1.1.1/dns-query".to_string(),
                    client_chain: NoneOrSome::One(ConfigSelection::GroupName(
                        "test-proxy".to_string(),
                    )),
                    bootstrap_url: None,
                    server_name: None,
                    ip_strategy: IpStrategy::default(),
                    timeout_secs: 10,
                    connect_timeout_secs: 5,
                    attempts: 1,
                }),
            }),
        ];

        let result = validate_configs_test(configs).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("H3 DNS only supports direct client_chain"),
            "Expected H3 DNS client_chain error, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_dns_h3_with_direct_chain_allowed() {
        use crate::config::types::ClientConfigGroup;

        // Create a direct chain - should be allowed for H3 (for bind_interface).
        let configs = vec![
            Config::ClientConfigGroup(ClientConfigGroup {
                client_group: "direct-chain".to_string(),
                client_proxies: OneOrSome::One(ConfigSelection::Config(ClientConfig::default())),
            }),
            Config::DnsConfigGroup(DnsConfigGroup {
                dns_group: "test-dns".to_string(),
                dns_servers: NoneOrSome::One(DnsServerSpec::WithOptions {
                    url: "h3://1.1.1.1/dns-query".to_string(),
                    client_chain: NoneOrSome::One(ConfigSelection::GroupName(
                        "direct-chain".to_string(),
                    )),
                    bootstrap_url: None,
                    server_name: None,
                    ip_strategy: IpStrategy::default(),
                    timeout_secs: 10,
                    connect_timeout_secs: 5,
                    attempts: 1,
                }),
            }),
        ];

        assert!(validate_configs_test(configs).await.is_ok());
    }

    #[tokio::test]
    async fn test_dns_tcp_with_client_chain_allowed() {
        use crate::config::types::ClientConfigGroup;

        let configs = vec![
            Config::ClientConfigGroup(ClientConfigGroup {
                client_group: "test-proxy".to_string(),
                client_proxies: OneOrSome::One(ConfigSelection::Config(ClientConfig::default())),
            }),
            Config::DnsConfigGroup(DnsConfigGroup {
                dns_group: "test-dns".to_string(),
                dns_servers: NoneOrSome::One(DnsServerSpec::WithOptions {
                    url: "tcp://8.8.8.8".to_string(),
                    client_chain: NoneOrSome::One(ConfigSelection::GroupName(
                        "test-proxy".to_string(),
                    )),
                    bootstrap_url: None,
                    server_name: None,
                    ip_strategy: IpStrategy::default(),
                    timeout_secs: 10,
                    connect_timeout_secs: 5,
                    attempts: 1,
                }),
            }),
        ];

        // TCP with client_chain should be allowed
        assert!(validate_configs_test(configs).await.is_ok());
    }

    #[tokio::test]
    async fn test_dns_tls_with_client_chain_allowed() {
        use crate::config::types::ClientConfigGroup;

        let configs = vec![
            Config::ClientConfigGroup(ClientConfigGroup {
                client_group: "test-proxy".to_string(),
                client_proxies: OneOrSome::One(ConfigSelection::Config(ClientConfig::default())),
            }),
            Config::DnsConfigGroup(DnsConfigGroup {
                dns_group: "test-dns".to_string(),
                dns_servers: NoneOrSome::One(DnsServerSpec::WithOptions {
                    url: "tls://1.1.1.1".to_string(),
                    client_chain: NoneOrSome::One(ConfigSelection::GroupName(
                        "test-proxy".to_string(),
                    )),
                    bootstrap_url: None,
                    server_name: None,
                    ip_strategy: IpStrategy::default(),
                    timeout_secs: 10,
                    connect_timeout_secs: 5,
                    attempts: 1,
                }),
            }),
        ];

        // TLS with client_chain should be allowed
        assert!(validate_configs_test(configs).await.is_ok());
    }

    #[tokio::test]
    async fn test_dns_https_with_client_chain_allowed() {
        use crate::config::types::ClientConfigGroup;

        let configs = vec![
            Config::ClientConfigGroup(ClientConfigGroup {
                client_group: "test-proxy".to_string(),
                client_proxies: OneOrSome::One(ConfigSelection::Config(ClientConfig::default())),
            }),
            Config::DnsConfigGroup(DnsConfigGroup {
                dns_group: "test-dns".to_string(),
                dns_servers: NoneOrSome::One(DnsServerSpec::WithOptions {
                    url: "https://1.1.1.1/dns-query".to_string(),
                    client_chain: NoneOrSome::One(ConfigSelection::GroupName(
                        "test-proxy".to_string(),
                    )),
                    bootstrap_url: None,
                    server_name: None,
                    ip_strategy: IpStrategy::default(),
                    timeout_secs: 10,
                    connect_timeout_secs: 5,
                    attempts: 1,
                }),
            }),
        ];

        // HTTPS with client_chain should be allowed
        assert!(validate_configs_test(configs).await.is_ok());
    }

    #[tokio::test]
    async fn test_dns_group_composition_basic() {
        // Group full-dns includes base-dns
        let configs = vec![
            Config::DnsConfigGroup(DnsConfigGroup {
                dns_group: "base-dns".to_string(),
                dns_servers: NoneOrSome::Some(vec![
                    DnsServerSpec::Simple("udp://8.8.8.8".to_string()),
                    DnsServerSpec::Simple("udp://8.8.4.4".to_string()),
                ]),
            }),
            Config::DnsConfigGroup(DnsConfigGroup {
                dns_group: "full-dns".to_string(),
                dns_servers: NoneOrSome::Some(vec![
                    DnsServerSpec::Simple("base-dns".to_string()), // Group reference
                    DnsServerSpec::Simple("tls://1.1.1.1".to_string()),
                ]),
            }),
        ];

        let result = validate_configs_test(configs).await;
        assert!(
            result.is_ok(),
            "composition should work: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_dns_group_composition_multi_level() {
        // C includes B, B includes A
        let configs = vec![
            Config::DnsConfigGroup(DnsConfigGroup {
                dns_group: "level-a".to_string(),
                dns_servers: NoneOrSome::One(DnsServerSpec::Simple("udp://8.8.8.8".to_string())),
            }),
            Config::DnsConfigGroup(DnsConfigGroup {
                dns_group: "level-b".to_string(),
                dns_servers: NoneOrSome::Some(vec![
                    DnsServerSpec::Simple("level-a".to_string()),
                    DnsServerSpec::Simple("udp://1.1.1.1".to_string()),
                ]),
            }),
            Config::DnsConfigGroup(DnsConfigGroup {
                dns_group: "level-c".to_string(),
                dns_servers: NoneOrSome::Some(vec![
                    DnsServerSpec::Simple("level-b".to_string()),
                    DnsServerSpec::Simple("system".to_string()),
                ]),
            }),
        ];

        let result = validate_configs_test(configs).await;
        assert!(
            result.is_ok(),
            "multi-level composition should work: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_dns_group_composition_cycle_detected() {
        // A includes B, B includes A - cycle!
        let configs = vec![
            Config::DnsConfigGroup(DnsConfigGroup {
                dns_group: "group-a".to_string(),
                dns_servers: NoneOrSome::One(DnsServerSpec::Simple("group-b".to_string())),
            }),
            Config::DnsConfigGroup(DnsConfigGroup {
                dns_group: "group-b".to_string(),
                dns_servers: NoneOrSome::One(DnsServerSpec::Simple("group-a".to_string())),
            }),
        ];

        let result = validate_configs_test(configs).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("Circular dependency") || err.contains("cycle"),
            "Expected cycle error, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_dns_group_composition_unknown_ref() {
        // Reference to non-existent group
        let configs = vec![Config::DnsConfigGroup(DnsConfigGroup {
            dns_group: "my-dns".to_string(),
            dns_servers: NoneOrSome::One(DnsServerSpec::Simple("nonexistent".to_string())),
        })];

        let result = validate_configs_test(configs).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown group") || err.contains("nonexistent"),
            "Expected unknown group error, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_dns_group_composition_with_bootstrap() {
        // Composition and bootstrap work together
        // Note: Using IP-based URLs to avoid network calls during tests
        let configs = vec![
            Config::DnsConfigGroup(DnsConfigGroup {
                dns_group: "bootstrap-dns".to_string(),
                dns_servers: NoneOrSome::One(DnsServerSpec::Simple("udp://8.8.8.8".to_string())),
            }),
            Config::DnsConfigGroup(DnsConfigGroup {
                dns_group: "base-dns".to_string(),
                dns_servers: NoneOrSome::One(DnsServerSpec::Simple("tls://1.1.1.1".to_string())),
            }),
            Config::DnsConfigGroup(DnsConfigGroup {
                dns_group: "full-dns".to_string(),
                dns_servers: NoneOrSome::Some(vec![
                    DnsServerSpec::Simple("base-dns".to_string()), // Composition reference
                    DnsServerSpec::WithOptions {
                        url: "tls://8.8.4.4".to_string(), // IP-based, no resolution needed
                        client_chain: NoneOrSome::None,
                        bootstrap_url: Some("bootstrap-dns".to_string()), // Bootstrap reference (not used since URL is IP)
                        server_name: Some("dns.google".to_string()),      // SNI override
                        ip_strategy: IpStrategy::default(),
                        timeout_secs: 10,
                        connect_timeout_secs: 5,
                        attempts: 1,
                    },
                ]),
            }),
        ];

        let result = validate_configs_test(configs).await;
        assert!(
            result.is_ok(),
            "composition with bootstrap should work: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_server_dns_with_group_ref() {
        use crate::address::NetLocationPortRange;
        use crate::config::types::dns::DnsConfig;
        use crate::config::types::transport::BindLocation;

        // Server config references an existing dns_group
        let configs = vec![
            Config::DnsConfigGroup(DnsConfigGroup {
                dns_group: "my-dns".to_string(),
                dns_servers: NoneOrSome::One(DnsServerSpec::Simple("udp://8.8.8.8".to_string())),
            }),
            Config::Server(ServerConfig {
                bind_location: BindLocation::Address(OneOrSome::One(
                    NetLocationPortRange::new(
                        crate::address::Address::Ipv4(std::net::Ipv4Addr::LOCALHOST),
                        vec![1234],
                    )
                    .unwrap(),
                )),
                protocol: ServerProxyConfig::Http {
                    username: None,
                    password: None,
                },
                transport: Transport::Tcp,
                tcp_settings: None,
                quic_settings: None,
                rules: direct_allow_rule(),
                dns: Some(DnsConfig {
                    servers: NoneOrSome::One(DnsServerSpec::Simple("my-dns".to_string())),
                }),
                sniff: None,
            }),
        ];

        let result = validate_configs_test(configs).await;
        assert!(
            result.is_ok(),
            "server with dns group ref should work: {:?}",
            result.err()
        );

        // Verify servers is still the group name (not expanded)
        let validated = result.unwrap();
        if let Config::Server(s) = &validated[0] {
            assert_eq!(s.dns.as_ref().unwrap().resolved_group(), Some("my-dns"));
        }
    }

    #[tokio::test]
    async fn test_server_dns_with_mixed_group_and_url() {
        use crate::address::NetLocationPortRange;
        use crate::config::types::dns::DnsConfig;
        use crate::config::types::transport::BindLocation;

        // Server config with both group ref and URL in servers
        let configs = vec![
            Config::DnsConfigGroup(DnsConfigGroup {
                dns_group: "base-dns".to_string(),
                dns_servers: NoneOrSome::One(DnsServerSpec::Simple("udp://8.8.8.8".to_string())),
            }),
            Config::Server(ServerConfig {
                bind_location: BindLocation::Address(OneOrSome::One(
                    NetLocationPortRange::new(
                        crate::address::Address::Ipv4(std::net::Ipv4Addr::LOCALHOST),
                        vec![1234],
                    )
                    .unwrap(),
                )),
                protocol: ServerProxyConfig::Http {
                    username: None,
                    password: None,
                },
                transport: Transport::Tcp,
                tcp_settings: None,
                quic_settings: None,
                rules: direct_allow_rule(),
                dns: Some(DnsConfig {
                    servers: NoneOrSome::Some(vec![
                        DnsServerSpec::Simple("base-dns".to_string()), // group ref
                        DnsServerSpec::Simple("udp://1.1.1.1".to_string()), // URL
                    ]),
                }),
                sniff: None,
            }),
        ];

        let result = validate_configs_test(configs).await;
        assert!(
            result.is_ok(),
            "server with mixed dns should work: {:?}",
            result.err()
        );

        // Verify servers was expanded to an inline group name
        let validated = result.unwrap();
        if let Config::Server(s) = &validated[0] {
            let group = s.dns.as_ref().unwrap().resolved_group().unwrap();
            assert!(
                group.starts_with("__inline_dns_"),
                "should be inline group: {}",
                group
            );
        }
    }

    #[tokio::test]
    async fn test_server_dns_with_multiple_group_refs() {
        use crate::address::NetLocationPortRange;
        use crate::config::types::dns::DnsConfig;
        use crate::config::types::transport::BindLocation;

        // Server config with multiple group refs that need expansion
        let configs = vec![
            Config::DnsConfigGroup(DnsConfigGroup {
                dns_group: "fast-dns".to_string(),
                dns_servers: NoneOrSome::One(DnsServerSpec::Simple("udp://8.8.8.8".to_string())),
            }),
            Config::DnsConfigGroup(DnsConfigGroup {
                dns_group: "secure-dns".to_string(),
                dns_servers: NoneOrSome::One(DnsServerSpec::Simple("tcp://1.1.1.1".to_string())),
            }),
            Config::Server(ServerConfig {
                bind_location: BindLocation::Address(OneOrSome::One(
                    NetLocationPortRange::new(
                        crate::address::Address::Ipv4(std::net::Ipv4Addr::LOCALHOST),
                        vec![1234],
                    )
                    .unwrap(),
                )),
                protocol: ServerProxyConfig::Http {
                    username: None,
                    password: None,
                },
                transport: Transport::Tcp,
                tcp_settings: None,
                quic_settings: None,
                rules: direct_allow_rule(),
                dns: Some(DnsConfig {
                    servers: NoneOrSome::Some(vec![
                        DnsServerSpec::Simple("fast-dns".to_string()),
                        DnsServerSpec::Simple("secure-dns".to_string()),
                    ]),
                }),
                sniff: None,
            }),
        ];

        let result = validate_configs_test(configs).await;
        assert!(
            result.is_ok(),
            "server with multiple group refs should work: {:?}",
            result.err()
        );

        // Verify servers was expanded to an inline group name
        let validated = result.unwrap();
        if let Config::Server(s) = &validated[0] {
            let group = s.dns.as_ref().unwrap().resolved_group().unwrap();
            assert!(
                group.starts_with("__inline_dns_"),
                "should be inline group: {}",
                group
            );
        }
    }

    #[tokio::test]
    async fn test_server_dns_unknown_group_ref() {
        use crate::address::NetLocationPortRange;
        use crate::config::types::dns::DnsConfig;
        use crate::config::types::transport::BindLocation;

        // Server config references non-existent dns_group
        let configs = vec![Config::Server(ServerConfig {
            bind_location: BindLocation::Address(OneOrSome::One(
                NetLocationPortRange::new(
                    crate::address::Address::Ipv4(std::net::Ipv4Addr::LOCALHOST),
                    vec![1234],
                )
                .unwrap(),
            )),
            protocol: ServerProxyConfig::Http {
                username: None,
                password: None,
            },
            transport: Transport::Tcp,
            tcp_settings: None,
            quic_settings: None,
            rules: direct_allow_rule(),
            dns: Some(DnsConfig {
                servers: NoneOrSome::One(DnsServerSpec::Simple("nonexistent-dns".to_string())),
            }),
            sniff: None,
        })];

        let result = validate_configs_test(configs).await;
        assert!(result.is_err(), "unknown dns group should fail");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("nonexistent-dns"),
            "error should mention group name: {}",
            err
        );
    }
}

#[cfg(test)]
mod rule_set_validation_tests {
    use super::*;

    fn parse(yaml: &str) -> Vec<Config> {
        serde_yaml::from_str(yaml).expect("yaml should parse")
    }

    /// ValidatedConfigs is not Debug, and deriving it just for tests would put
    /// a config dump one `{:?}` away in production code.
    fn expect_error(configs: Vec<Config>) -> String {
        match create_server_configs(configs) {
            Ok(_) => panic!("expected validation to fail"),
            Err(e) => e.to_string(),
        }
    }

    #[test]
    fn sniff_enabled_with_an_empty_protocol_list_is_rejected() {
        let configs: Vec<Config> = serde_yaml::from_str(
            r#"
- address: 127.0.0.1:1080
  protocol:
    type: socks
  sniff:
    enabled: true
    protocols: []
"#,
        )
        .unwrap();

        let error = expect_error(configs);
        assert!(
            error.contains("protocol list is empty"),
            "message was: {error}"
        );
    }

    #[test]
    fn sniff_disabled_with_an_empty_protocol_list_is_accepted() {
        let configs: Vec<Config> = serde_yaml::from_str(
            r#"
- address: 127.0.0.1:1080
  protocol:
    type: socks
  sniff:
    enabled: false
    protocols: []
"#,
        )
        .unwrap();

        create_server_configs(configs).expect("a disabled sniff block is not validated");
    }

    #[test]
    fn sniff_shorthand_parses_on_a_server() {
        let configs: Vec<Config> = serde_yaml::from_str(
            r#"
- address: 127.0.0.1:1080
  protocol:
    type: socks
  sniff: true
"#,
        )
        .unwrap();

        create_server_configs(configs).expect("sniff: true should be accepted");
    }

    #[test]
    fn an_unknown_rule_set_name_is_rejected() {
        let configs = parse(
            "
- address: 0.0.0.0:1080
  protocol:
    type: socks
  rules:
    - masks: \"0.0.0.0/0\"
      rule_sets: [does-not-exist]
      action: allow
",
        );
        let err = expect_error(configs);
        assert!(err.contains("does-not-exist"), "{err}");
    }

    #[test]
    fn a_duplicate_rule_set_name_is_rejected() {
        let configs = parse(
            "
- rule_set: dup
  path: tests/data/rule_sets/geosite-telegram.srs
- rule_set: dup
  path: tests/data/rule_sets/geosite-cloudflare.srs
",
        );
        let err = expect_error(configs);
        assert!(err.contains("dup"), "{err}");
    }

    #[test]
    fn a_missing_rule_set_file_is_a_startup_error() {
        let configs = parse(
            "
- rule_set: missing
  path: tests/data/rule_sets/does-not-exist.srs
",
        );
        let err = expect_error(configs);
        assert!(err.contains("missing"), "{err}");
    }

    #[test]
    fn a_declared_rule_set_is_loaded_and_attached_to_the_rule() {
        let configs = parse(
            "
- rule_set: telegram
  path: tests/data/rule_sets/geosite-telegram.srs
- address: 0.0.0.0:1080
  protocol:
    type: socks
  rules:
    - rule_sets: [telegram]
      action: allow
",
        );
        let validated = create_server_configs(configs).unwrap();

        // ValidatedConfigs carries `configs: Vec<Config>`, so pick the server
        // entry out of it rather than expecting a separate collection.
        let server = validated
            .configs
            .iter()
            .find_map(|config| match config {
                Config::Server(server) => Some(server),
                _ => None,
            })
            .expect("expected a server config");

        let rules = server.rules.clone().into_vec();
        let rule = rules[0].clone().unwrap_config();
        assert_eq!(rule.loaded_rule_sets.len(), 1);
        assert_eq!(rule.loaded_rule_sets[0].name(), "telegram");
    }
}

#[cfg(test)]
mod outbound_set_tests {
    use crate::config::load_config_str;
    use crate::outbound_stats::OutboundSet;

    fn validate(yaml: &str) -> std::io::Result<OutboundSet> {
        let configs = load_config_str(yaml)?;
        super::create_server_configs(configs).map(|v| v.outbounds)
    }

    #[test]
    fn every_configured_outbound_is_in_the_set() {
        let set = validate(
            r#"
- client_group: eu
  client_proxies:
    - name: Frankfurt
      address: "fra1.example:443"
      protocol: {type: socks}
    - name: Amsterdam
      address: "ams1.example:443"
      protocol: {type: socks}
- address: "127.0.0.1:1080"
  protocol: {type: socks}
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain: eu
"#,
        )
        .unwrap();

        assert!(set.contains("Frankfurt"));
        assert!(set.contains("Amsterdam"));
    }

    /// A group nothing references is still a configured server.
    #[test]
    fn an_unreferenced_group_is_still_listed() {
        let set = validate(
            r#"
- client_group: spare
  client_proxies:
    - name: Spare
      address: "spare.example:443"
      protocol: {type: socks}
- address: "127.0.0.1:1080"
  protocol: {type: socks}
"#,
        )
        .unwrap();

        assert!(set.contains("Spare"));
    }

    /// Group expansion clones a config into every referencing group; the
    /// clones are one server.
    #[test]
    fn a_group_referenced_twice_yields_one_entry() {
        let set = validate(
            r#"
- client_group: base
  client_proxies:
    - name: Frankfurt
      address: "fra1.example:443"
      protocol: {type: socks}
- client_group: a
  client_proxies: [base]
- client_group: b
  client_proxies: [base]
- address: "127.0.0.1:1080"
  protocol: {type: socks}
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chains: [a, b]
"#,
        )
        .unwrap();

        // "direct" is always present from the built-in group, so the count is
        // the built-in plus Frankfurt.
        assert!(set.contains("Frankfurt"));
        assert_eq!(set.len(), 2, "{:?}", set.iter().collect::<Vec<_>>());
    }

    /// An inline hop is the more common form and must be listed too.
    #[test]
    fn an_inline_hop_is_in_the_set() {
        let set = validate(
            r#"
- address: "127.0.0.1:1080"
  protocol: {type: socks}
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain:
        name: Inline
        address: "fra1.example:443"
        protocol: {type: socks}
"#,
        )
        .unwrap();

        assert!(set.contains("Inline"));
    }

    #[test]
    fn one_name_on_two_different_servers_is_rejected() {
        let err = validate(
            r#"
- client_group: eu
  client_proxies:
    - name: Frankfurt
      address: "fra1.example:443"
      protocol: {type: socks}
    - name: Frankfurt
      address: "fra2.example:443"
      protocol: {type: socks}
- address: "127.0.0.1:1080"
  protocol: {type: socks}
"#,
        )
        .unwrap_err();

        let msg = err.to_string();
        assert!(msg.contains("Frankfurt"), "must name the name: {msg}");
        assert!(msg.contains("fra1.example:443"), "must name both: {msg}");
        assert!(msg.contains("fra2.example:443"), "must name both: {msg}");
    }

    /// Nearly every config has a direct outbound, and two of them must not
    /// read as a conflict on the unspecified address.
    #[test]
    fn two_direct_outbounds_are_one_entry() {
        let set = validate(
            r#"
- address: "127.0.0.1:1080"
  protocol: {type: socks}
  rules:
    - masks: "10.0.0.0/8"
      action: allow
      client_chain:
        protocol: {type: direct}
    - masks: "0.0.0.0/0"
      action: allow
      client_chain:
        protocol: {type: direct}
"#,
        )
        .unwrap();

        assert!(set.contains("direct"));
        assert_eq!(set.len(), 1);
    }

    /// The dry-run and editor property: validating touches no live state.
    #[cfg(feature = "control-stats")]
    #[test]
    fn validating_does_not_change_the_registry() {
        use crate::outbound_stats::{REGISTRY_TEST_LOCK, reset_for_test, snapshot_all};
        let _guard = REGISTRY_TEST_LOCK.lock().unwrap();
        reset_for_test();

        validate(
            r#"
- address: "127.0.0.1:1080"
  protocol: {type: socks}
  rules:
    - masks: "0.0.0.0/0"
      action: allow
      client_chain:
        name: Draft
        address: "draft.example:443"
        protocol: {type: socks}
"#,
        )
        .unwrap();

        assert!(snapshot_all().is_empty(), "validation must not install");
    }
}

/// The chains that reach `build_client_proxy_chain` without passing through a
/// rule: a ShadowTLS remote handshake and a REALITY dest fallback.
///
/// They are easy to forget precisely because they are not rules, and forgetting
/// them is not cosmetic: an outbound missing from the set is invisible in
/// `stats::snapshot()`, is never conflict-checked, and — since `chain_builder`
/// panics on an unresolved group reference — cannot use a group at all.
#[cfg(test)]
mod handshake_chain_tests {
    use crate::config::load_config_str;
    use crate::outbound_stats::OutboundSet;

    fn validate(yaml: &str) -> std::io::Result<OutboundSet> {
        let configs = load_config_str(yaml)?;
        super::create_server_configs(configs).map(|v| v.outbounds)
    }

    fn shadowtls(chain: &str) -> String {
        format!(
            r#"
- address: "127.0.0.1:8443"
  protocol:
    type: tls
    shadowtls_targets:
      example.com:
        password: pw
        handshake:
          address: example.com:443
          client_chain:
{chain}
        protocol:
          type: socks
"#
        )
    }

    #[test]
    fn a_shadowtls_handshake_chain_is_in_the_set() {
        let set = validate(&shadowtls(
            r#"            - name: HandshakeHop
              address: "hop.example:1080"
              protocol: {type: socks}"#,
        ))
        .unwrap();

        assert!(
            set.contains("HandshakeHop"),
            "got {:?}",
            set.iter().collect::<Vec<_>>()
        );
    }

    /// Without this, the config loads and `chain_builder` aborts the process
    /// when the server starts.
    #[test]
    fn a_blank_name_in_a_shadowtls_handshake_chain_is_rejected() {
        let err = validate(&shadowtls(
            r#"            - name: "   "
              address: "hop.example:1080"
              protocol: {type: socks}"#,
        ))
        .unwrap_err();
        assert!(err.to_string().contains("empty"), "got: {err}");
    }

    /// `chain_builder` panics on an unresolved group reference, so a group in
    /// one of these chains has to be expanded here like any other.
    ///
    /// Asserting on the expanded config rather than on the set: a group member
    /// reaches the set through the group-members loop whether or not the chain
    /// referencing it was ever expanded, so the set proves nothing here.
    #[test]
    fn a_group_reference_in_a_shadowtls_handshake_chain_is_expanded() {
        use crate::config::{ClientChainHop, Config, ConfigSelection, ServerProxyConfig};

        let yaml = format!(
            r#"
- client_group: hs
  client_proxies:
    - name: FromGroup
      address: "hop.example:1080"
      protocol: {{type: socks}}
{}"#,
            shadowtls(r#"            - hs"#)
        );
        let configs = load_config_str(&yaml).unwrap();
        let validated = super::create_server_configs(configs).unwrap();

        let mut checked = false;
        for config in &validated.configs {
            let Config::Server(server) = config else {
                continue;
            };
            let ServerProxyConfig::Tls {
                shadowtls_targets, ..
            } = &server.protocol
            else {
                continue;
            };
            for target in shadowtls_targets.values() {
                let crate::config::ShadowTlsServerHandshakeConfig::Remote(remote) =
                    &target.handshake
                else {
                    continue;
                };
                for hop in remote.client_chain.iter() {
                    let ClientChainHop::Single(selection) = hop else {
                        panic!("expected a single hop, got {hop:?}")
                    };
                    assert!(
                        matches!(selection, ConfigSelection::Config(_)),
                        "group reference survived validation: {selection:?}"
                    );
                    checked = true;
                }
            }
        }
        assert!(checked, "test did not reach the handshake chain");
    }

    #[test]
    fn a_reality_dest_chain_is_in_the_set() {
        let yaml = r#"
- address: "127.0.0.1:8443"
  protocol:
    type: tls
    reality_targets:
      example.com:
        private_key: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
        short_ids: ["01ab"]
        dest: "example.com:443"
        dest_client_chain:
          - name: DestHop
            address: "dest.example:1080"
            protocol: {type: socks}
        protocol:
          type: socks
"#;
        let set = validate(yaml).unwrap();
        assert!(
            set.contains("DestHop"),
            "got {:?}",
            set.iter().collect::<Vec<_>>()
        );
    }
}

#[cfg(test)]
mod redirect_validation_tests {
    use crate::config::load_config_str;

    fn validate(yaml: &str) -> std::io::Result<()> {
        let configs = load_config_str(yaml)?;
        super::create_server_configs(configs).map(|_| ())
    }

    fn refusal(yaml: &str) -> String {
        validate(yaml)
            .expect_err("this redirect listener must be refused")
            .to_string()
    }

    /// The wildcard is the bind a router needs: REDIRECT rewrites to the LAN
    /// interface's address, which a loopback listener never receives.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_redirect_listener_is_accepted_on_loopback_and_on_the_wildcard() {
        for bind in [
            "127.0.0.1:51272",
            "[::1]:51272",
            "0.0.0.0:51272",
            "[::]:51272",
        ] {
            validate(&format!(
                "- address: \"{bind}\"\n  protocol: {{type: redirect}}\n"
            ))
            .unwrap_or_else(|e| panic!("{bind}: {e}"));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_redirect_listener_on_a_unix_socket_is_refused() {
        let err = refusal("- path: /tmp/shoes-redirect.sock\n  protocol: {type: redirect}\n");
        assert!(err.contains("Unix socket"), "{err}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn redirect_on_another_transport_is_refused() {
        let err = refusal(
            "- address: \"127.0.0.1:51272\"\n  transport: udp\n  protocol: {type: redirect}\n",
        );
        assert!(err.contains("TCP only"), "{err}");
    }

    /// Nested, the handler would be handed a WebSocket or TLS wrapper with
    /// no socket option to read, and refuse every connection at runtime.
    #[test]
    fn redirect_as_an_inner_protocol_is_refused() {
        let err = refusal(
            r#"
- address: "127.0.0.1:51272"
  protocol:
    type: ws
    targets:
      - matching_path: /
        protocol: {type: redirect}
"#,
        );
        assert!(err.contains("not an inner one"), "{err}");
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn redirect_is_refused_off_linux_by_name() {
        let err = refusal("- address: \"127.0.0.1:51272\"\n  protocol: {type: redirect}\n");
        assert!(err.contains("Linux"), "{err}");
    }
}

#[cfg(test)]
mod tproxy_validation_tests {
    use crate::config::load_config_str;

    fn validate(yaml: &str) -> std::io::Result<()> {
        let configs = load_config_str(yaml)?;
        super::create_server_configs(configs).map(|_| ())
    }

    fn refusal(yaml: &str) -> String {
        validate(yaml)
            .expect_err("this tproxy listener must be refused")
            .to_string()
    }

    fn tproxy(bind: &str, fields: &str) -> String {
        format!("- address: \"{bind}\"\n  transport: udp\n  protocol: {{type: tproxy{fields}}}\n")
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_tproxy_listener_is_accepted_on_loopback() {
        for bind in ["127.0.0.1:51271", "[::1]:51271"] {
            validate(&tproxy(bind, "")).unwrap_or_else(|e| panic!("{bind}: {e}"));
        }
        validate(&tproxy(
            "127.0.0.1:51271",
            ", udp_timeout: 86400, udp_nat_max: 1",
        ))
        .unwrap();
    }

    /// The loopback rule keeps a transparent socket from relaying ordinarily
    /// delivered datagrams to itself (awg-manager #689, quoted in the spec's
    /// security notes). A datagram from the host itself to the listener is
    /// the demux's to drop, as `redirect` refuses its own address.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_tproxy_listener_off_loopback_is_refused() {
        for bind in ["0.0.0.0:51271", "[::]:51271", "192.168.1.1:51271"] {
            let err = refusal(&tproxy(bind, ""));
            assert!(err.contains("loopback"), "{bind}: {err}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_tproxy_listener_on_a_unix_socket_is_refused() {
        // Refused before the tproxy rules are reached, by the general rule
        // that Unix sockets are TCP only.
        let err = refusal(
            "- path: /tmp/shoes-tproxy.sock\n  transport: udp\n  protocol: {type: tproxy}\n",
        );
        assert!(err.contains("Unix domain socket"), "{err}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn tproxy_needs_transport_udp() {
        let err = refusal("- address: \"127.0.0.1:51271\"\n  protocol: {type: tproxy}\n");
        assert!(err.contains("transport: udp"), "{err}");
    }

    /// `transport: udp` with any other protocol used to pass validation and
    /// then panic on a `todo!()` at startup.
    #[test]
    fn transport_udp_with_another_protocol_is_refused() {
        let err =
            refusal("- address: \"127.0.0.1:1080\"\n  transport: udp\n  protocol: {type: socks}\n");
        assert!(err.contains("tproxy"), "{err}");
    }

    /// Zero would expire every session at once or admit none; past a day the
    /// router's timer panics on a duration it cannot hold.
    #[cfg(target_os = "linux")]
    #[test]
    fn tproxy_limits_out_of_range_are_refused() {
        for (fields, name) in [
            (", udp_timeout: 0", "udp_timeout"),
            (", udp_timeout: 86401", "udp_timeout"),
            (", udp_nat_max: 0", "udp_nat_max"),
            (", udp_nat_max: 1048577", "udp_nat_max"),
            // Past tokio's Semaphore::MAX_PERMITS, which panics at startup.
            (", udp_nat_max: 18446744073709551615", "udp_nat_max"),
        ] {
            let err = refusal(&tproxy("127.0.0.1:51271", fields));
            assert!(err.contains(name), "{fields}: {err}");
        }
    }

    /// Sniffing reads a TCP stream's first bytes; a datagram inbound has no
    /// stream, so the block would be accepted and do nothing.
    #[cfg(target_os = "linux")]
    #[test]
    fn tproxy_with_sniff_is_refused() {
        let err = refusal(&format!("{}  sniff: true\n", tproxy("127.0.0.1:51271", "")));
        assert!(err.contains("sniff"), "{err}");
        validate(&format!(
            "{}  sniff: {{enabled: false}}\n",
            tproxy("127.0.0.1:51271", "")
        ))
        .expect("a disabled sniff block asks for nothing");
    }

    /// A TUIC server with the given extra protocol fields. The PEMs are
    /// named inline data, so nothing is read from disk; their content is
    /// not parsed at validation time.
    fn tuic(fields: &str) -> String {
        format!(
            r#"
- pem: quic-cert
  data: "-----BEGIN CERTIFICATE-----\nTEST CERT CONTENT\n-----END CERTIFICATE-----"
- pem: quic-key
  data: "-----BEGIN PRIVATE KEY-----\nTEST KEY CONTENT\n-----END PRIVATE KEY-----"
- address: "127.0.0.1:51273"
  transport: quic
  quic_settings:
    cert: quic-cert
    key: quic-key
  protocol:
    type: tuic
    uuid: "b0e80a62-8a51-47f0-91f1-f0f7faf8d9d4"
    password: secret{fields}
"#
        )
    }

    /// TU-D3's `udp_timeout` is bounded like tproxy's: zero reaped every
    /// association on the first sweep, and it used to load.
    #[test]
    fn tuic_udp_timeout_out_of_range_is_refused() {
        validate(&tuic("")).unwrap();
        validate(&tuic("\n    udp_timeout: 86400")).unwrap();
        for fields in ["\n    udp_timeout: 0", "\n    udp_timeout: 86401"] {
            let err = refusal(&tuic(fields));
            assert!(err.contains("tuic udp_timeout"), "{fields}: {err}");
        }
    }

    #[test]
    fn tproxy_as_an_inner_protocol_is_refused() {
        let err = refusal(
            r#"
- address: "127.0.0.1:51272"
  protocol:
    type: ws
    targets:
      - matching_path: /
        protocol: {type: tproxy}
"#,
        );
        assert!(err.contains("not an inner one"), "{err}");
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn tproxy_is_refused_off_linux_by_name() {
        let err = refusal(&tproxy("127.0.0.1:51271", ""));
        assert!(err.contains("Linux"), "{err}");
    }
}

#[cfg(test)]
mod amneziawg_mtu_tests {
    use super::*;

    #[test]
    fn the_warning_advises_a_fitting_mtu() {
        assert_eq!(amneziawg_mtu_warning(1420, 20), None, "1500 exactly fits");
        let warning = amneziawg_mtu_warning(1420, 27).unwrap();
        assert!(warning.contains("Lower mtu to 1413"), "{warning}");
    }

    /// awgtun 0.11 widened s4 to 16 bits; past 864 no supported mtu fits,
    /// and the advice must say so rather than underflow.
    #[test]
    fn a_large_s4_gets_advice_not_an_underflow() {
        for s4 in [865u16, 1440, 2000, u16::MAX] {
            let warning = amneziawg_mtu_warning(1420, s4).unwrap();
            assert!(
                warning.contains("reduce s4 to at most 864"),
                "{s4}: {warning}"
            );
        }
    }

    /// Through validation, with warnings enabled so the message is built: a
    /// config with s4 2000 is validated without a panic.
    #[test]
    fn validation_with_a_large_s4_does_not_panic() {
        log::set_max_level(log::LevelFilter::Warn);
        let config: crate::config::types::AmneziaWgClientConfig = serde_yaml::from_str(
            "private_key: \"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=\"\n\
             peer_public_key: \"ISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0A=\"\n\
             local_addresses: \"10.8.0.2/32\"\n\
             allowed_ips: \"0.0.0.0/0\"\n\
             awg:\n  s4: 2000\n",
        )
        .unwrap();
        let _ = validate_amneziawg_config(&config);
    }
}

#[cfg(test)]
mod reality_sni_validation_tests {
    use crate::config::load_config_str;

    fn validate(address: &str, reality: &str) -> std::io::Result<()> {
        let yaml = format!(
            r#"
- address: "127.0.0.1:1080"
  protocol:
    type: socks
  rules:
    - masks: 0.0.0.0/0
      action: allow
      client_chain:
        address: "{address}"
        protocol:
{reality}
"#
        );
        let configs = load_config_str(&yaml)?;
        super::create_server_configs(configs).map(|_| ())
    }

    const REALITY: &str = r#"          type: reality
          public_key: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
          short_id: "01ab"
          protocol:
            type: vless
            user_id: "b831381d-6324-4d53-ad4f-8cda48b30811""#;

    #[test]
    fn a_missing_sni_with_an_ip_address_is_a_config_error() {
        let err = validate("203.0.113.7:443", REALITY)
            .unwrap_err()
            .to_string();
        assert!(err.contains("REALITY client needs sni_hostname"), "{err}");
    }

    #[test]
    fn a_missing_sni_falls_back_to_a_hostname_address() {
        validate("reality.example.com:443", REALITY).unwrap();
    }

    #[test]
    fn an_empty_sni_loads() {
        let reality = format!("{REALITY}\n          sni_hostname: \"\"");
        validate("203.0.113.7:443", &reality).unwrap();
    }

    const TLS_VMESS: &str = r#"          type: tls
          protocol:
            type: vmess
            cipher: aes-128-gcm
            user_id: "b831381d-6324-4d53-ad4f-8cda48b30811""#;

    /// A plain TLS hop used to reach rustls's `ServerName` unwrap with
    /// `""`; now it loads and sends no name, and a name rustls refuses is
    /// a config error rather than a panic later.
    #[test]
    fn a_tls_sni_is_checked_when_the_config_loads() {
        let empty = format!("{TLS_VMESS}\n          sni_hostname: \"\"");
        validate("203.0.113.7:443", &empty).unwrap();
        let ip = format!("{TLS_VMESS}\n          sni_hostname: \"203.0.113.9\"");
        validate("203.0.113.7:443", &ip).unwrap();

        let bad = format!("{TLS_VMESS}\n          sni_hostname: \"not a name\"");
        let err = validate("203.0.113.7:443", &bad).unwrap_err().to_string();
        assert!(err.contains("TLS client sni_hostname"), "{err}");

        let shadowtls = "          type: shadowtls\n          password: secret\n          sni_hostname: \"not a name\"\n          protocol:\n            type: vmess\n            cipher: aes-128-gcm\n            user_id: \"b831381d-6324-4d53-ad4f-8cda48b30811\"";
        let err = validate("203.0.113.7:443", shadowtls)
            .unwrap_err()
            .to_string();
        assert!(err.contains("ShadowTLS client sni_hostname"), "{err}");
    }

    #[test]
    fn a_nested_reality_gets_no_fallback() {
        let nested = format!(
            "          type: websocket\n          protocol:\n{}",
            REALITY
                .lines()
                .map(|l| format!("    {l}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
        let err = validate("reality.example.com:443", &nested)
            .unwrap_err()
            .to_string();
        assert!(err.contains("REALITY client needs sni_hostname"), "{err}");
    }

    fn load(yaml: &str) -> std::io::Result<()> {
        let configs = load_config_str(yaml)?;
        super::create_server_configs(configs).map(|_| ())
    }

    /// The hop a fallback chain carries: REALITY at an IP address, no name.
    const NAMELESS_HOP: &str = r#"
            address: "203.0.113.7:443"
            protocol:
              type: reality
              public_key: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
              short_id: "01ab"
              protocol:
                type: vless
                user_id: "b831381d-6324-4d53-ad4f-8cda48b30811""#;

    #[test]
    fn a_reality_dest_chain_hop_is_validated() {
        let yaml = format!(
            r#"
- address: "127.0.0.1:8443"
  protocol:
    type: tls
    reality_targets:
      example.com:
        private_key: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
        short_ids: ["01ab"]
        dest: "example.com:443"
        dest_client_chain:
          -{NAMELESS_HOP}
        protocol:
          type: socks
"#
        );
        let err = load(&yaml).unwrap_err().to_string();
        assert!(err.contains("REALITY client needs sni_hostname"), "{err}");
    }

    #[test]
    fn a_shadowtls_handshake_chain_hop_is_validated() {
        let yaml = format!(
            r#"
- address: "127.0.0.1:8443"
  protocol:
    type: tls
    shadowtls_targets:
      example.com:
        password: "shadowtls-password"
        handshake:
          address: "example.com:443"
          client_chain:
          -{NAMELESS_HOP}
        protocol:
          type: socks
"#
        );
        let err = load(&yaml).unwrap_err().to_string();
        assert!(err.contains("REALITY client needs sni_hostname"), "{err}");
    }
}
