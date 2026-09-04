//! A [`HostNetwork`] that writes down what it was asked to do.
//!
//! Every ordering rule in `plan.rs` is tested through this, on every platform,
//! with no root and no device. That is deliberate: the sequencing is where a
//! mistake costs a user their network connection, and it is also the part a
//! live run exercises least -- a live run takes the happy path, and the rules
//! here are about what happens when a step fails.

use std::cell::RefCell;
use std::net::IpAddr;

use super::{HostNetwork, Route};

/// One thing the daemon asked the host to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    Gateway,
    AddRoute(Route),
    DeleteRoute(Route),
    PrimaryService,
    ReadDns(String),
    WriteDns(String, Vec<IpAddr>),
    FlushDns,
}

/// Records calls, and can be told to fail one of them.
pub struct Recorder {
    steps: RefCell<Vec<Step>>,
    gateway: Option<IpAddr>,
    /// The live version, so a test can move it mid-session.
    gateway_now: std::sync::Mutex<Option<IpAddr>>,
    existing_dns: Vec<IpAddr>,
    /// Fail `add_route` once this many have succeeded.
    fail_add_after: Option<usize>,
    fail_delete: bool,
    fail_write_dns: bool,
    /// The live version of `fail_write_dns`, shared so a test can flip it
    /// after the recorder has been moved onto the supervisor thread.
    fail_write_dns_now: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl Recorder {
    pub fn new() -> Self {
        Self {
            steps: RefCell::new(Vec::new()),
            gateway: None,
            gateway_now: std::sync::Mutex::new(None),
            existing_dns: Vec::new(),
            fail_add_after: None,
            fail_delete: false,
            fail_write_dns: false,
            fail_write_dns_now: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    pub fn with_gateway(mut self, gateway: Option<IpAddr>) -> Self {
        self.gateway = gateway;
        self.gateway_now
            .lock()
            .map(|mut g| *g = gateway)
            .unwrap_or(());
        self
    }

    /// Move the gateway, as a network change does.
    pub fn set_gateway(&self, gateway: Option<IpAddr>) {
        if let Ok(mut current) = self.gateway_now.lock() {
            *current = gateway;
        }
    }

    /// Resolvers the host already has, which are what a revert must put
    /// back.
    pub fn with_existing_dns(mut self, servers: Vec<IpAddr>) -> Self {
        self.existing_dns = servers;
        self
    }

    pub fn failing_add_route_after(mut self, successes: usize) -> Self {
        self.fail_add_after = Some(successes);
        self
    }

    /// Fail every route deletion with something other than "not in table",
    /// which is what a revert must report rather than swallow.
    pub fn failing_delete_route(mut self) -> Self {
        self.fail_delete = true;
        self
    }

    pub fn failing_write_dns(mut self) -> Self {
        self.fail_write_dns = true;
        self.fail_write_dns_now
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self
    }

    /// A callback that stops the DNS writes failing, usable after the recorder
    /// has been moved onto the supervisor thread.
    ///
    /// The flag is shared rather than owned so that a test can flip it from
    /// outside: a recovery that fails once and succeeds on the retry is the
    /// case that matters, and the recorder itself is gone by then.
    pub fn allow_handle(&self) -> impl Fn() + Send + 'static {
        let flag = self.fail_write_dns_now.clone();
        move || flag.store(false, std::sync::atomic::Ordering::SeqCst)
    }

    pub fn steps(&self) -> Vec<Step> {
        self.steps.borrow().clone()
    }

    pub fn count_added(&self) -> usize {
        self.steps
            .borrow()
            .iter()
            .filter(|s| matches!(s, Step::AddRoute(_)))
            .count()
    }

    pub fn count_deleted(&self) -> usize {
        self.steps
            .borrow()
            .iter()
            .filter(|s| matches!(s, Step::DeleteRoute(_)))
            .count()
    }

    fn record(&self, step: Step) {
        self.steps.borrow_mut().push(step);
    }
}

impl HostNetwork for Recorder {
    fn default_gateway(&self) -> std::io::Result<Option<IpAddr>> {
        self.record(Step::Gateway);
        Ok(self.gateway_now.lock().map(|g| *g).unwrap_or(self.gateway))
    }

    fn add_route(&self, route: &Route) -> std::io::Result<()> {
        if let Some(limit) = self.fail_add_after
            && self.count_added() >= limit
        {
            // Not recorded, because it did not happen -- the host does not
            // have this route. `apply` will still ask for it to be deleted,
            // since it wrote the route down before attempting it, and a real
            // host answers that with "not in table" and success.
            return Err(std::io::Error::other("add_route refused by the test"));
        }
        self.record(Step::AddRoute(route.clone()));
        Ok(())
    }

    fn delete_route(&self, route: &Route) -> std::io::Result<()> {
        // Recorded before the failure check, unlike `add_route`: the test that
        // matters here asks whether every deletion was *attempted* after one
        // of them failed.
        self.record(Step::DeleteRoute(route.clone()));
        if self.fail_delete {
            return Err(std::io::Error::other("delete_route refused by the test"));
        }
        Ok(())
    }

    fn primary_dns_service(&self) -> std::io::Result<String> {
        self.record(Step::PrimaryService);
        Ok("primary".to_string())
    }

    fn read_dns(&self, service: &str) -> std::io::Result<Vec<IpAddr>> {
        self.record(Step::ReadDns(service.to_string()));
        Ok(self.existing_dns.clone())
    }

    fn write_dns(&self, service: &str, servers: &[IpAddr]) -> std::io::Result<()> {
        if self
            .fail_write_dns_now
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(std::io::Error::other("write_dns refused by the test"));
        }
        self.record(Step::WriteDns(service.to_string(), servers.to_vec()));
        Ok(())
    }

    fn flush_dns_cache(&self) -> std::io::Result<()> {
        self.record(Step::FlushDns);
        Ok(())
    }
}
