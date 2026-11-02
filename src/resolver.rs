#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "predates the lint; see the [lints] note in Cargo.toml"
)]

use std::collections::HashMap;
use std::fmt::Debug;
use std::future::Future;
use std::hash::Hash;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use futures::future::FutureExt;
use log::debug;
use lru::LruCache;
use parking_lot::Mutex;
use tokio::sync::{Mutex as AsyncMutex, RwLock, Semaphore, broadcast};

use crate::address::{Address, NetLocation, ResolvedLocation};

type ResolveFuture = Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>>;

const CACHING_NATIVE_RESOLVER_CACHE_CAPACITY: usize = 10_000;
const CACHING_NATIVE_RESOLVER_MAX_PARTICIPANTS: usize = 1_024;
const RESOLVER_CACHE_CAPACITY: usize = 1_024;

/// Constructs a bounded LRU without eagerly reserving storage for every entry.
fn bounded_lru<K: Hash + Eq, V>(capacity: usize) -> LruCache<K, V> {
    let mut cache = LruCache::unbounded();
    cache.resize(NonZeroUsize::new(capacity).unwrap());
    cache
}

pub trait Resolver: Send + Sync + Debug {
    fn resolve_location(&self, location: &NetLocation) -> ResolveFuture;
}

/// Resolver wrapper that enforces a timeout on DNS resolution.
/// Wraps any inner Resolver and fails with TimedOut if resolution takes too long.
pub struct TimeoutResolver<T> {
    inner: T,
    timeout: Duration,
}

impl<T: Resolver> TimeoutResolver<T> {
    #[allow(dead_code)]
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

    #[allow(dead_code)]
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            timeout: Self::DEFAULT_TIMEOUT,
        }
    }

    pub fn with_timeout(inner: T, timeout: Duration) -> Self {
        Self { inner, timeout }
    }
}

impl<T: Resolver> Debug for TimeoutResolver<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TimeoutResolver")
            .field("inner", &self.inner)
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl<T: Resolver> Resolver for TimeoutResolver<T> {
    fn resolve_location(&self, location: &NetLocation) -> ResolveFuture {
        // Fast path: if already an IP address, no resolution needed
        if location.to_socket_addr_nonblocking().is_some() {
            let loc = location.clone();
            return Box::pin(async move { Ok(vec![loc.to_socket_addr_nonblocking().unwrap()]) });
        }

        let inner_future = self.inner.resolve_location(location);
        let timeout_duration = self.timeout;
        let location_str = location.to_string();

        Box::pin(async move {
            match tokio::time::timeout(timeout_duration, inner_future).await {
                Ok(result) => result,
                Err(_) => Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!(
                        "DNS resolution for {} timed out after {:?}",
                        location_str, timeout_duration
                    ),
                )),
            }
        })
    }
}

type ResolverFactoryFuture =
    Pin<Box<dyn Future<Output = std::io::Result<Arc<dyn Resolver>>> + Send>>;

pub type ResolverFactory = Arc<dyn Fn() -> ResolverFactoryFuture + Send + Sync>;

/// How long the per-stream `ResolverCache` uses an answer without asking
/// again (DN-D3); an hour kept a moved host's old address that long. The
/// shared native cache has its own, shorter age
/// (`CachingNativeResolver::DEFAULT_RESULT_TIMEOUT_SECS`).
const CACHED_RESULT_SECS: u64 = 5 * 60;

/// Policy controlling when a RefreshingResolver rebuilds its inner resolver.
#[derive(Debug, Clone, Copy)]
pub struct RefreshPolicy {
    /// Rebuild the inner resolver if it has been idle longer than this.
    pub max_idle: Duration,
    /// Rebuild it once it is this old, however busy (DN-D2): a rebuild
    /// resolves a DoH or DoT server's name again through its bootstrap, and a
    /// resolver that never idles kept the address it started with.
    pub max_age: Duration,
    /// After a failed idle or age rebuild, wait this long before the next
    /// attempt, using the resolver already built in between: a bootstrap that
    /// is down must not make every working lookup wait for it.
    pub retry_after_failure: Duration,
    /// After a refreshable error, rebuild and retry the lookup once.
    pub retry_once_after_refresh: bool,
}

/// Resolver wrapper that rebuilds its inner resolver on idle timeout or
/// connection-related errors. Targets stale pooled connection state in
/// hickory-backed resolvers.
pub struct RefreshingResolver {
    factory: ResolverFactory,
    inner: Arc<RwLock<Arc<dyn Resolver>>>,
    refresh_lock: Arc<AsyncMutex<()>>,
    refresh_state: Arc<Mutex<RefreshState>>,
    policy: RefreshPolicy,
    description: String,
}

struct RefreshState {
    last_activity_at: Option<Instant>,
    built_at: Instant,
    failed_refresh_at: Option<Instant>,
    generation: u64,
}

impl RefreshState {
    fn is_stale(&self, policy: &RefreshPolicy) -> bool {
        if matches!(self.failed_refresh_at, Some(failed) if failed.elapsed() < policy.retry_after_failure)
        {
            return false;
        }
        matches!(self.last_activity_at, Some(last) if last.elapsed() > policy.max_idle)
            || self.built_at.elapsed() > policy.max_age
    }
}

impl Debug for RefreshingResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefreshingResolver")
            .field("description", &self.description)
            .field("max_idle", &self.policy.max_idle)
            .finish()
    }
}

impl RefreshingResolver {
    pub async fn new(
        factory: ResolverFactory,
        policy: RefreshPolicy,
        description: String,
    ) -> std::io::Result<Self> {
        let inner = factory().await?;
        Ok(Self {
            factory,
            inner: Arc::new(RwLock::new(inner)),
            refresh_lock: Arc::new(AsyncMutex::new(())),
            refresh_state: Arc::new(Mutex::new(RefreshState {
                last_activity_at: None,
                built_at: Instant::now(),
                failed_refresh_at: None,
                generation: 0,
            })),
            policy,
            description,
        })
    }

    fn should_refresh_for_error(err: &std::io::Error) -> bool {
        matches!(
            err.kind(),
            std::io::ErrorKind::TimedOut
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::UnexpectedEof
                | std::io::ErrorKind::NotConnected
        )
    }
}

impl Resolver for RefreshingResolver {
    fn resolve_location(&self, location: &NetLocation) -> ResolveFuture {
        if let Some(socket_addr) = location.to_socket_addr_nonblocking() {
            return Box::pin(async move { Ok(vec![socket_addr]) });
        }

        let location = location.clone();
        let inner = self.inner.clone();
        let refresh_lock = self.refresh_lock.clone();
        let factory = self.factory.clone();
        let refresh_state = self.refresh_state.clone();
        let policy = self.policy;
        let description = self.description.clone();

        Box::pin(async move {
            // Refreshes if idle or old too long using double-checked locking.
            if refresh_state.lock().is_stale(&policy) {
                let _guard = refresh_lock.lock().await;
                if refresh_state.lock().is_stale(&policy) {
                    log::info!(
                        "RefreshingResolver ({}): rebuilding after idle timeout ({:?}) or age ({:?})",
                        description,
                        policy.max_idle,
                        policy.max_age
                    );
                    match factory().await {
                        Ok(fresh) => {
                            *inner.write().await = fresh;
                            let mut state = refresh_state.lock();
                            state.last_activity_at = Some(Instant::now());
                            state.built_at = Instant::now();
                            state.failed_refresh_at = None;
                            state.generation = state.generation.wrapping_add(1);
                        }
                        Err(e) => {
                            refresh_state.lock().failed_refresh_at = Some(Instant::now());
                            log::warn!(
                                "RefreshingResolver ({}): idle refresh failed: {}",
                                description,
                                e
                            );
                        }
                    }
                }
            }

            let current_generation = refresh_state.lock().generation;
            let current = inner.read().await.clone();
            match current.resolve_location(&location).await {
                Ok(addrs) => {
                    refresh_state.lock().last_activity_at = Some(Instant::now());
                    Ok(addrs)
                }
                Err(err)
                    if policy.retry_once_after_refresh
                        && RefreshingResolver::should_refresh_for_error(&err) =>
                {
                    let _guard = refresh_lock.lock().await;
                    if refresh_state.lock().generation != current_generation {
                        let current = inner.read().await.clone();
                        let addrs = current.resolve_location(&location).await?;
                        refresh_state.lock().last_activity_at = Some(Instant::now());
                        return Ok(addrs);
                    }
                    log::info!(
                        "RefreshingResolver ({}): refresh-on-error ({}) for {}",
                        description,
                        err.kind(),
                        location
                    );
                    match factory().await {
                        Ok(fresh) => {
                            *inner.write().await = fresh.clone();
                            {
                                let mut state = refresh_state.lock();
                                state.built_at = Instant::now();
                                state.failed_refresh_at = None;
                                state.generation = state.generation.wrapping_add(1);
                            }
                            let addrs = fresh.resolve_location(&location).await?;
                            refresh_state.lock().last_activity_at = Some(Instant::now());
                            Ok(addrs)
                        }
                        Err(factory_err) => {
                            log::warn!(
                                "RefreshingResolver ({}): error-refresh factory failed: {}",
                                description,
                                factory_err
                            );
                            Err(err)
                        }
                    }
                }
                Err(err) => Err(err),
            }
        })
    }
}

#[derive(Debug, Default)]
pub struct NativeResolver;

impl NativeResolver {
    pub fn new() -> Self {
        NativeResolver {}
    }
}

impl Resolver for NativeResolver {
    fn resolve_location(&self, location: &NetLocation) -> ResolveFuture {
        let address = location.address().clone();
        let port = location.port();
        Box::pin(
            tokio::net::lookup_host((address.to_string(), port)).map(move |result| {
                let ret = result.map(|r| {
                    r.filter(|addr| !addr.ip().is_unspecified())
                        .collect::<Vec<_>>()
                });
                debug!("NativeResolver resolved {address}:{port} -> {ret:?}");
                ret
            }),
        )
    }
}

pub async fn resolve_single_address(
    resolver: &Arc<dyn Resolver>,
    location: &NetLocation,
) -> std::io::Result<SocketAddr> {
    if let Some(socket_addr) = location.to_socket_addr_nonblocking() {
        return Ok(socket_addr);
    }
    let resolve_results = resolver.resolve_location(location).await?;
    if resolve_results.is_empty() {
        return Err(std::io::Error::other(format!(
            "could not resolve location: {location}"
        )));
    }
    Ok(resolve_results[0])
}

/// Resolve all addresses for a location. Returns a single-element vec
/// for IP literals, or the full set from the resolver.
pub async fn resolve_addresses(
    resolver: &Arc<dyn Resolver>,
    location: &NetLocation,
) -> std::io::Result<Vec<SocketAddr>> {
    if let Some(socket_addr) = location.to_socket_addr_nonblocking() {
        return Ok(vec![socket_addr]);
    }

    let addrs = resolver.resolve_location(location).await?;
    if addrs.is_empty() {
        return Err(std::io::Error::other(format!(
            "could not resolve location: {location}"
        )));
    }
    Ok(addrs)
}

/// Resolve a ResolvedLocation lazily. If already resolved, returns the cached
/// address. Otherwise resolves, caches the result in the location, and returns it.
/// This is the key function for the lazy resolution pattern.
pub async fn resolve_location(
    location: &mut ResolvedLocation,
    resolver: &Arc<dyn Resolver>,
) -> std::io::Result<SocketAddr> {
    if let Some(addr) = location.resolved_addr() {
        return Ok(addr);
    }
    let addr = resolve_single_address(resolver, location.location()).await?;
    location.set_resolved(addr);
    Ok(addr)
}

/// Native resolver with application-level caching, from upstream cfal/shoes
/// #220 and #227. Used by implicit native resolution, opt-in caching on
/// explicit `system` entries, and (with a zero age, so lookups are shared but
/// never reused) a TUN without a `dns:` block.
/// OS lookups expose no DNS TTL; successful results are reused for at most 60 seconds
/// by default, measured from lookup completion. Errors and empty results are never cached.
///
/// At most 1,024 callers participate in coalesced misses (owners plus subscribers).
/// Excess callers perform independent lookups, preserving existing failure
/// semantics without adding an unbounded admission queue or detached tasks.
/// Cancelling an owner makes surviving subscribers start a new lookup, which
/// may exceed their remaining deadlines. Already-running OS calls cannot be stopped.
pub struct CachingNativeResolver {
    state: Arc<Mutex<NativeResolverState>>,
    participants: Arc<Semaphore>,
    lookup: Arc<dyn Resolver>,
    result_timeout_secs: u64,
}

type NativeLookupResult = Result<Arc<[SocketAddr]>, Arc<std::io::Error>>;

struct NativeResolverState {
    cache: LruCache<Address, CachedResolveResult>,
    inflight: HashMap<Address, broadcast::Sender<NativeLookupResult>>,
}

struct CachedResolveResult {
    completed_at: tokio::time::Instant,
    addrs: Arc<[SocketAddr]>,
}

impl NativeResolverState {
    fn cached(&mut self, address: &Address, max_age: Duration) -> Option<Arc<[SocketAddr]>> {
        if max_age.is_zero() {
            return None;
        }
        if let Some(cached) = self.cache.get(address)
            && cached.completed_at.elapsed() < max_age
        {
            return Some(cached.addrs.clone());
        }
        self.cache.pop(address);
        None
    }
}

struct NativeLookupOwner {
    state: Arc<Mutex<NativeResolverState>>,
    address: Address,
    registered: bool,
}

enum NativeLookupRole {
    Owner(NativeLookupOwner),
    Subscriber(broadcast::Receiver<NativeLookupResult>),
}

impl NativeLookupOwner {
    fn publish(mut self, result: &NativeLookupResult, cache_enabled: bool) {
        let mut state = self.state.lock();
        if cache_enabled && let Ok(addrs) = result {
            state.cache.put(
                self.address.clone(),
                CachedResolveResult {
                    completed_at: tokio::time::Instant::now(),
                    addrs: addrs.clone(),
                },
            );
        }
        // Cache insertion and flight removal are atomic with subscription.
        if self.registered {
            let sender = state.inflight.remove(&self.address).unwrap();
            // A panicking waker must not let Drop remove a replacement flight.
            self.registered = false;
            drop(state);
            let _ = sender.send(result.clone());
        }
    }
}

impl Drop for NativeLookupOwner {
    fn drop(&mut self) {
        if self.registered {
            // Closing outside the lock wakes subscribers to elect a replacement owner.
            let sender = self.state.lock().inflight.remove(&self.address);
            drop(sender);
        }
    }
}

fn native_addrs_with_port(addrs: &[SocketAddr], port: u16) -> Vec<SocketAddr> {
    addrs
        .iter()
        .map(|addr| {
            let mut addr = *addr;
            addr.set_port(port);
            addr
        })
        .collect()
}

fn native_lookup_error(error: Arc<std::io::Error>) -> std::io::Error {
    match error.raw_os_error() {
        Some(errno) => std::io::Error::from_raw_os_error(errno),
        None => std::io::Error::new(error.kind(), error),
    }
}

impl std::fmt::Debug for CachingNativeResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachingNativeResolver")
            .field("result_timeout_secs", &self.result_timeout_secs)
            .finish()
    }
}

impl CachingNativeResolver {
    /// Conservative application result age, not an authoritative DNS record TTL.
    pub const DEFAULT_RESULT_TIMEOUT_SECS: u64 = 60;

    pub fn new() -> Self {
        Self::with_timeout(Self::DEFAULT_RESULT_TIMEOUT_SECS)
    }

    /// Sets the maximum successful result age, not a lookup deadline or DNS TTL.
    /// Zero disables completed-result caching but still coalesces concurrent misses.
    pub fn with_timeout(result_timeout_secs: u64) -> Self {
        Self::with_lookup(Arc::new(NativeResolver::new()), result_timeout_secs)
    }

    pub(crate) fn with_lookup(lookup: Arc<dyn Resolver>, result_timeout_secs: u64) -> Self {
        Self {
            state: Arc::new(Mutex::new(NativeResolverState {
                cache: bounded_lru(CACHING_NATIVE_RESOLVER_CACHE_CAPACITY),
                inflight: HashMap::new(),
            })),
            participants: Arc::new(Semaphore::new(CACHING_NATIVE_RESOLVER_MAX_PARTICIPANTS)),
            lookup,
            result_timeout_secs,
        }
    }
}

impl Default for CachingNativeResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl Resolver for CachingNativeResolver {
    fn resolve_location(&self, location: &NetLocation) -> ResolveFuture {
        let max_age = Duration::from_secs(self.result_timeout_secs);
        let cache_enabled = self.result_timeout_secs > 0;
        let caller_port = location.port();
        if let Some(addrs) = self.state.lock().cached(location.address(), max_age) {
            let addrs = native_addrs_with_port(&addrs, caller_port);
            return Box::pin(async move { Ok(addrs) });
        }

        // Tokio's (host, u16) lookup delegates to std, which passes a null service
        // to getaddrinfo and sets ports afterward. Only the exact host is a key;
        // socket candidates retain order, duplicates, IPv6 scope IDs and flowinfo.
        let query_location = NetLocation::new(location.address().clone(), 0);
        let state = self.state.clone();
        let participants = self.participants.clone();
        let lookup = self.lookup.clone();

        Box::pin(async move {
            let permit = participants.try_acquire().ok();
            loop {
                let role = {
                    let mut locked = state.lock();
                    // Rechecks after future creation or cancellation of an owner.
                    if let Some(addrs) = locked.cached(query_location.address(), max_age) {
                        return Ok(native_addrs_with_port(&addrs, caller_port));
                    }
                    if let Some(sender) = locked.inflight.get(query_location.address())
                        && permit.is_some()
                    {
                        NativeLookupRole::Subscriber(sender.subscribe())
                    } else {
                        let registered = permit.is_some();
                        if registered {
                            let (sender, _) = broadcast::channel(1);
                            locked
                                .inflight
                                .insert(query_location.address().clone(), sender);
                        }
                        NativeLookupRole::Owner(NativeLookupOwner {
                            state: state.clone(),
                            address: query_location.address().clone(),
                            registered,
                        })
                    }
                };

                let result = match role {
                    NativeLookupRole::Subscriber(mut subscriber) => match subscriber.recv().await {
                        Ok(result) => result,
                        Err(_) => continue,
                    },
                    NativeLookupRole::Owner(owner) => {
                        let result = lookup
                            .resolve_location(&query_location)
                            .await
                            .and_then(|mut addrs| {
                                addrs.retain(|addr| !addr.ip().is_unspecified());
                                if addrs.is_empty() {
                                    Err(std::io::Error::other(format!(
                                        "DNS lookup returned no addresses for {}",
                                        query_location.address()
                                    )))
                                } else {
                                    Ok(Arc::from(addrs))
                                }
                            })
                            .map_err(Arc::new);
                        owner.publish(&result, cache_enabled);
                        result
                    }
                };
                let addrs = result.map_err(native_lookup_error)?;
                let addrs = native_addrs_with_port(&addrs, caller_port);
                debug!(
                    "CachingNativeResolver resolved {}:{caller_port} -> {addrs:?}",
                    query_location.address()
                );
                return Ok(addrs);
            }
        })
    }
}

#[cfg(test)]
mod native_tests;

/// Poll-based resolver cache for use in Future/Stream implementations.
/// Wraps any Resolver and provides poll_resolve_location for manual polling.
pub struct ResolverCache {
    resolver: Arc<dyn Resolver>,
    /// Completed resolution results with timestamps
    cache: LruCache<NetLocation, (Instant, SocketAddr)>,
    /// The latest poll-based lookup. A changed target cancels the abandoned lookup.
    pending: Option<(NetLocation, ResolveFuture)>,
    result_timeout_secs: u64,
}

impl ResolverCache {
    pub const DEFAULT_RESULT_TIMEOUT_SECS: u64 = CACHED_RESULT_SECS;

    pub fn new(resolver: Arc<dyn Resolver>) -> Self {
        Self::new_with_timeout(resolver, Self::DEFAULT_RESULT_TIMEOUT_SECS)
    }

    pub fn new_with_timeout(resolver: Arc<dyn Resolver>, result_timeout_secs: u64) -> Self {
        Self {
            resolver,
            cache: bounded_lru(RESOLVER_CACHE_CAPACITY),
            pending: None,
            result_timeout_secs,
        }
    }

    /// Async resolve method for convenience.
    pub async fn resolve_location(&mut self, target: &NetLocation) -> std::io::Result<SocketAddr> {
        self.pending = None;

        // Fast path: IP address
        if let Some(socket_addr) = target.to_socket_addr_nonblocking() {
            return Ok(socket_addr);
        }

        // Check cache
        if let Some((ts, addr)) = self.cache.get(target) {
            if Instant::now().duration_since(*ts) <= Duration::from_secs(self.result_timeout_secs) {
                return Ok(*addr);
            }
            self.cache.pop(target);
        }

        // Resolve
        let addrs = self.resolver.resolve_location(target).await?;
        if addrs.is_empty() {
            return Err(std::io::Error::other(format!(
                "DNS lookup returned no addresses for {target}"
            )));
        }
        let addr = addrs[0];
        self.cache.put(target.clone(), (Instant::now(), addr));
        Ok(addr)
    }

    /// Poll-based resolve for use in Future/Stream poll methods.
    pub fn poll_resolve_location(
        &mut self,
        cx: &mut Context<'_>,
        target: &NetLocation,
    ) -> Poll<std::io::Result<SocketAddr>> {
        if self
            .pending
            .as_ref()
            .is_some_and(|(pending_target, _)| pending_target != target)
        {
            self.pending = None;
        }

        // Fast path: IP address
        if let Some(socket_addr) = target.to_socket_addr_nonblocking() {
            return Poll::Ready(Ok(socket_addr));
        }

        // Check completed cache
        if let Some((ts, addr)) = self.cache.get(target) {
            if Instant::now().duration_since(*ts) <= Duration::from_secs(self.result_timeout_secs) {
                return Poll::Ready(Ok(*addr));
            }
            self.cache.pop(target);
        }

        if self.pending.is_none() {
            self.pending = Some((target.clone(), self.resolver.resolve_location(target)));
        }

        let result = self.pending.as_mut().unwrap().1.as_mut().poll(cx);
        match result {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(addrs)) => {
                self.pending = None;
                if addrs.is_empty() {
                    return Poll::Ready(Err(std::io::Error::other(format!(
                        "DNS lookup returned no addresses for {target}"
                    ))));
                }
                let addr = addrs[0];
                self.cache.put(target.clone(), (Instant::now(), addr));
                Poll::Ready(Ok(addr))
            }
            Poll::Ready(Err(e)) => {
                self.pending = None;
                Poll::Ready(Err(e))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::Address;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Barrier;

    /// A mock resolver that returns configurable results, tracking call count.
    #[derive(Debug)]
    struct MockResolver {
        addrs: Vec<SocketAddr>,
        call_count: AtomicUsize,
        error_kind: Option<std::io::ErrorKind>,
    }

    impl MockResolver {
        fn with_addrs(addrs: Vec<SocketAddr>) -> Self {
            Self {
                addrs,
                call_count: AtomicUsize::new(0),
                error_kind: None,
            }
        }

        fn with_error(kind: std::io::ErrorKind) -> Self {
            Self {
                addrs: vec![],
                call_count: AtomicUsize::new(0),
                error_kind: Some(kind),
            }
        }
    }

    impl Resolver for MockResolver {
        fn resolve_location(&self, _location: &NetLocation) -> ResolveFuture {
            self.call_count.fetch_add(1, Ordering::Relaxed);
            let addrs = self.addrs.clone();
            let error_kind = self.error_kind;
            Box::pin(async move {
                if let Some(kind) = error_kind {
                    Err(std::io::Error::new(kind, "mock error"))
                } else {
                    Ok(addrs)
                }
            })
        }
    }

    #[derive(Debug, Default)]
    struct PendingResolver {
        active: Arc<AtomicUsize>,
        calls: AtomicUsize,
    }

    struct PendingFuture {
        active: Arc<AtomicUsize>,
    }

    impl Future for PendingFuture {
        type Output = std::io::Result<Vec<SocketAddr>>;

        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            Poll::Pending
        }
    }

    impl Drop for PendingFuture {
        fn drop(&mut self) {
            self.active.fetch_sub(1, Ordering::Relaxed);
        }
    }

    impl Resolver for PendingResolver {
        fn resolve_location(&self, _location: &NetLocation) -> ResolveFuture {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.active.fetch_add(1, Ordering::Relaxed);
            Box::pin(PendingFuture {
                active: self.active.clone(),
            })
        }
    }

    fn test_location() -> NetLocation {
        NetLocation::new(Address::Hostname("example.com".to_string()), 80)
    }

    fn test_addrs() -> Vec<SocketAddr> {
        vec!["127.0.0.1:80".parse().unwrap()]
    }

    fn unique_location(index: usize) -> NetLocation {
        NetLocation::new(Address::Hostname(format!("host-{index}.example")), 443)
    }

    #[tokio::test]
    async fn test_resolver_cache_is_bounded() {
        let resolver: Arc<dyn Resolver> = Arc::new(MockResolver::with_addrs(test_addrs()));
        let mut cache = ResolverCache::new(resolver);

        for index in 0..RESOLVER_CACHE_CAPACITY + 1 {
            cache
                .resolve_location(&unique_location(index))
                .await
                .unwrap();
        }

        assert_eq!(cache.cache.len(), RESOLVER_CACHE_CAPACITY);
        assert!(cache.cache.peek(&unique_location(0)).is_none());
    }

    #[test]
    fn test_resolver_cache_cancels_abandoned_pending_result() {
        let resolver = Arc::new(PendingResolver::default());
        let mut cache = ResolverCache::new(resolver.clone());
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        let first = unique_location(0);
        let second = unique_location(1);

        assert!(matches!(
            cache.poll_resolve_location(&mut cx, &first),
            Poll::Pending
        ));
        assert_eq!(resolver.active.load(Ordering::Relaxed), 1);

        assert!(matches!(
            cache.poll_resolve_location(&mut cx, &second),
            Poll::Pending
        ));
        assert_eq!(resolver.active.load(Ordering::Relaxed), 1);
        assert_eq!(resolver.calls.load(Ordering::Relaxed), 2);

        assert!(matches!(
            cache.poll_resolve_location(&mut cx, &second),
            Poll::Pending
        ));
        assert_eq!(resolver.calls.load(Ordering::Relaxed), 2);

        let literal = NetLocation::new(Address::Ipv4(std::net::Ipv4Addr::LOCALHOST), 443);
        assert!(matches!(
            cache.poll_resolve_location(&mut cx, &literal),
            Poll::Ready(Ok(_))
        ));
        assert_eq!(resolver.active.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn test_refreshing_resolver_retries_after_timeout() {
        let success_addrs = test_addrs();
        let call_count = Arc::new(AtomicUsize::new(0));

        let call_count_clone = call_count.clone();
        let addrs = success_addrs.clone();
        let factory: ResolverFactory = Arc::new(move || {
            let n = call_count_clone.fetch_add(1, Ordering::Relaxed);
            let addrs = addrs.clone();
            Box::pin(async move {
                if n == 0 {
                    // First build: return a resolver that times out
                    Ok(
                        Arc::new(MockResolver::with_error(std::io::ErrorKind::TimedOut))
                            as Arc<dyn Resolver>,
                    )
                } else {
                    // Refresh build: return a resolver that succeeds
                    Ok(Arc::new(MockResolver::with_addrs(addrs)) as Arc<dyn Resolver>)
                }
            })
        });

        let policy = RefreshPolicy {
            max_idle: Duration::from_secs(60),
            max_age: Duration::from_secs(3600),
            retry_after_failure: Duration::from_secs(30),
            retry_once_after_refresh: true,
        };

        let resolver = RefreshingResolver::new(factory, policy, "test".to_string())
            .await
            .unwrap();

        let result = resolver.resolve_location(&test_location()).await.unwrap();
        assert_eq!(result, success_addrs);
        // Factory called twice: initial build + refresh-on-error
        assert_eq!(call_count.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn test_refreshing_resolver_no_retry_on_non_refreshable_error() {
        let call_count = Arc::new(AtomicUsize::new(0));

        let call_count_clone = call_count.clone();
        let factory: ResolverFactory = Arc::new(move || {
            call_count_clone.fetch_add(1, Ordering::Relaxed);
            Box::pin(async move {
                // Return a resolver that returns a non-refreshable error
                Ok(
                    Arc::new(MockResolver::with_error(std::io::ErrorKind::Other))
                        as Arc<dyn Resolver>,
                )
            })
        });

        let policy = RefreshPolicy {
            max_idle: Duration::from_secs(60),
            max_age: Duration::from_secs(3600),
            retry_after_failure: Duration::from_secs(30),
            retry_once_after_refresh: true,
        };

        let resolver = RefreshingResolver::new(factory, policy, "test".to_string())
            .await
            .unwrap();

        let result = resolver.resolve_location(&test_location()).await;
        assert!(result.is_err());
        // Factory called only once (initial build, no refresh for non-refreshable errors)
        assert_eq!(call_count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_refreshing_resolver_idle_refresh() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let addrs = test_addrs();

        let call_count_clone = call_count.clone();
        let addrs_clone = addrs.clone();
        let factory: ResolverFactory = Arc::new(move || {
            call_count_clone.fetch_add(1, Ordering::Relaxed);
            let addrs = addrs_clone.clone();
            Box::pin(
                async move { Ok(Arc::new(MockResolver::with_addrs(addrs)) as Arc<dyn Resolver>) },
            )
        });

        let policy = RefreshPolicy {
            max_idle: Duration::from_millis(50),
            max_age: Duration::from_secs(3600),
            retry_after_failure: Duration::from_secs(30),
            retry_once_after_refresh: true,
        };

        let resolver = RefreshingResolver::new(factory, policy, "test".to_string())
            .await
            .unwrap();

        // First resolve records activity.
        let result = resolver.resolve_location(&test_location()).await.unwrap();
        assert_eq!(result, addrs);
        assert_eq!(call_count.load(Ordering::Relaxed), 1);

        // Wait for idle timeout
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Second resolve triggers idle refresh
        let result = resolver.resolve_location(&test_location()).await.unwrap();
        assert_eq!(result, addrs);
        // Factory called twice: initial + idle refresh
        assert_eq!(call_count.load(Ordering::Relaxed), 2);
    }

    /// DN-D2: a resolver in constant use is rebuilt once it reaches its
    /// maximum age, which re-resolves a DoH or DoT server's name.
    #[tokio::test]
    async fn test_refreshing_resolver_rebuilds_a_busy_resolver_at_max_age() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let addrs = test_addrs();

        let call_count_clone = call_count.clone();
        let addrs_clone = addrs.clone();
        let factory: ResolverFactory = Arc::new(move || {
            call_count_clone.fetch_add(1, Ordering::Relaxed);
            let addrs = addrs_clone.clone();
            Box::pin(
                async move { Ok(Arc::new(MockResolver::with_addrs(addrs)) as Arc<dyn Resolver>) },
            )
        });

        let policy = RefreshPolicy {
            max_idle: Duration::from_secs(3600),
            max_age: Duration::from_millis(100),
            retry_after_failure: Duration::from_secs(30),
            retry_once_after_refresh: true,
        };
        let resolver = RefreshingResolver::new(factory, policy, "test".to_string())
            .await
            .unwrap();

        // Never idle: a lookup every 10 ms for at least 250 ms.
        for _ in 0..25 {
            assert_eq!(
                resolver.resolve_location(&test_location()).await.unwrap(),
                addrs
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        // A lower bound only: the sleeps are minimums, so a slow runner can
        // see more age rebuilds, never fewer.
        let builds = call_count.load(Ordering::Relaxed);
        assert!(
            builds >= 2,
            "a busy resolver is rebuilt by age: {builds} builds"
        );
    }

    /// A failed age rebuild keeps the working resolver and waits out the
    /// retry interval, instead of retrying on every lookup.
    #[tokio::test]
    async fn test_refreshing_resolver_waits_after_a_failed_rebuild() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let addrs = test_addrs();

        let call_count_clone = call_count.clone();
        let addrs_clone = addrs.clone();
        let factory: ResolverFactory = Arc::new(move || {
            let call = call_count_clone.fetch_add(1, Ordering::Relaxed);
            let addrs = addrs_clone.clone();
            Box::pin(async move {
                if call == 0 {
                    Ok(Arc::new(MockResolver::with_addrs(addrs)) as Arc<dyn Resolver>)
                } else {
                    Err(std::io::Error::other("bootstrap down"))
                }
            })
        });

        let policy = RefreshPolicy {
            max_idle: Duration::from_secs(3600),
            max_age: Duration::from_millis(20),
            retry_after_failure: Duration::from_secs(3600),
            retry_once_after_refresh: true,
        };
        let resolver = RefreshingResolver::new(factory, policy, "test".to_string())
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(40)).await;
        for _ in 0..10 {
            assert_eq!(
                resolver.resolve_location(&test_location()).await.unwrap(),
                addrs,
                "the resolver already built keeps answering"
            );
        }
        assert_eq!(
            call_count.load(Ordering::Relaxed),
            2,
            "one failed rebuild, then none until the retry interval"
        );
    }

    /// The shared native cache keeps an answer 60 seconds, as upstream does;
    /// the per-stream cache keeps its five minutes (DN-D3).
    #[test]
    fn cached_answer_ages() {
        assert_eq!(CachingNativeResolver::DEFAULT_RESULT_TIMEOUT_SECS, 60);
        assert_eq!(ResolverCache::DEFAULT_RESULT_TIMEOUT_SECS, 300);
    }

    #[tokio::test]
    async fn test_refreshing_resolver_coalesces_concurrent_idle_refresh() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let addrs = test_addrs();

        let call_count_clone = call_count.clone();
        let addrs_clone = addrs.clone();
        let factory: ResolverFactory = Arc::new(move || {
            call_count_clone.fetch_add(1, Ordering::Relaxed);
            let addrs = addrs_clone.clone();
            Box::pin(async move {
                tokio::time::sleep(Duration::from_millis(10)).await;
                Ok(Arc::new(MockResolver::with_addrs(addrs)) as Arc<dyn Resolver>)
            })
        });

        let policy = RefreshPolicy {
            max_idle: Duration::from_millis(20),
            max_age: Duration::from_secs(3600),
            retry_after_failure: Duration::from_secs(30),
            retry_once_after_refresh: true,
        };

        let resolver = Arc::new(
            RefreshingResolver::new(factory, policy, "test".to_string())
                .await
                .unwrap(),
        );

        let result = resolver.resolve_location(&test_location()).await.unwrap();
        assert_eq!(result, addrs);
        assert_eq!(call_count.load(Ordering::Relaxed), 1);

        tokio::time::sleep(Duration::from_millis(50)).await;

        let concurrency = 32;
        let barrier = Arc::new(Barrier::new(concurrency));
        let tasks = (0..concurrency).map(|_| {
            let resolver = resolver.clone();
            let barrier = barrier.clone();
            let location = test_location();
            tokio::spawn(async move {
                barrier.wait().await;
                resolver.resolve_location(&location).await
            })
        });

        for result in futures::future::join_all(tasks).await {
            assert_eq!(result.unwrap().unwrap(), addrs);
        }
        assert_eq!(call_count.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn test_resolve_addresses_returns_all() {
        let addrs: Vec<SocketAddr> = vec![
            "1.1.1.1:80".parse().unwrap(),
            "2.2.2.2:80".parse().unwrap(),
            "3.3.3.3:80".parse().unwrap(),
        ];
        let inner: Arc<dyn Resolver> = Arc::new(MockResolver::with_addrs(addrs.clone()));
        let loc = test_location();

        let result = resolve_addresses(&inner, &loc).await.unwrap();
        assert_eq!(result, addrs);
    }

    #[tokio::test]
    async fn test_resolve_addresses_ip_literal() {
        let inner: Arc<dyn Resolver> = Arc::new(MockResolver::with_addrs(vec![]));
        let loc = NetLocation::new(Address::Ipv4("1.2.3.4".parse().unwrap()), 443);

        let result = resolve_addresses(&inner, &loc).await.unwrap();
        assert_eq!(result, vec!["1.2.3.4:443".parse::<SocketAddr>().unwrap()]);
    }

    #[tokio::test]
    async fn test_timeout_resolver_ip_bypass() {
        let inner = MockResolver::with_addrs(test_addrs());
        let resolver = TimeoutResolver::with_timeout(inner, Duration::from_millis(1));

        // IP literals should return immediately without timeout
        let loc = NetLocation::new(Address::Ipv4("1.2.3.4".parse().unwrap()), 80);
        let result = resolver.resolve_location(&loc).await.unwrap();
        assert_eq!(result[0], "1.2.3.4:80".parse::<SocketAddr>().unwrap());
    }

    /// Regression: a `CachingNativeResolver` cache hit must return the same full
    /// address list as the initial cache miss, not just the first address.
    #[tokio::test]
    async fn test_caching_native_resolver_hit_returns_full_list() {
        let resolver = CachingNativeResolver::new();
        let loc = NetLocation::new(Address::Hostname("localhost".to_string()), 9);

        // First call: cache miss, returns the full resolved list.
        let miss = resolver.resolve_location(&loc).await.unwrap();
        assert!(!miss.is_empty(), "localhost must resolve to >= 1 address");

        // Second call: cache hit, must return the same full list (not addrs[0]).
        let hit = resolver.resolve_location(&loc).await.unwrap();
        assert_eq!(
            hit, miss,
            "cache hit must return the full resolved list, not just the first address"
        );
    }
}
