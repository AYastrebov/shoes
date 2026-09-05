//! DNS through systemd-resolved or `/etc/resolv.conf`.
//!
//! The part with no macOS counterpart, because macOS has one mechanism and
//! Linux has four. Two backends cover the five distributions in scope, and
//! which one this host wants is decided once at startup by [`Dns::probe`].
//!
//! **"systemd-resolved, where it is running" is not the test**, and getting
//! that wrong leaks DNS silently. `systemd-resolved.service(8)`'s
//! `/ETC/RESOLV.CONF` section enumerates four modes, and in two of them --
//! `uplink`, where `/etc/resolv.conf` points at
//! `/run/systemd/resolve/resolv.conf`, and `foreign`, where another package
//! owns the file -- resolved is running, `resolvectl dns <link>` succeeds, and
//! `/etc/resolv.conf` still lists the real upstream servers. The man page says
//! what that costs outright: "local clients that bypass any local DNS API will
//! also bypass systemd-resolved and will talk directly to the known DNS
//! servers." Every glibc client reads that file directly. So the tunnel comes
//! up, the daemon reports `RUNNING`, and DNS goes out of the physical
//! interface -- with nothing anywhere saying so.
//!
//! [`stub_resolver_in_use`] is the condition that closes it, and it is a pure
//! function over the contents of the file precisely because it is the one worth
//! testing. It is also what resolved's own mode detection keys on, so it is not
//! a heuristic standing in for the real question -- it *is* the question.
//!
//! Nothing here interpolates into a shell: every command is a
//! `std::process::Command` with an argv array, every address is a parsed
//! `IpAddr` re-serialised, and both programs are named by absolute path rather
//! than found on `PATH`. The addresses arrive over the control socket.
//!
//! Design: `docs/specs/2026-09-04-linux-privileged-daemon.md`, "DNS".

use std::ffi::{CString, OsStr};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::host::DnsState;

/// Where `resolvectl` may be, in the order the candidates are tried.
///
/// Never searched on `PATH`, for the reason `routes.rs` gives about `ip`: a
/// root process that resolves a program through `PATH` runs whatever the first
/// writable directory on it happens to hold.
const RESOLVECTL_CANDIDATES: [&str; 2] = ["/usr/bin/resolvectl", "/bin/resolvectl"];

/// The file the direct backend owns, and the one the probe reads.
const RESOLV_CONF: &str = "/etc/resolv.conf";

/// resolved's stub listener.
///
/// Only this one. `127.0.0.54` is the *proxy* stub, which forwards to the
/// current upstream servers rather than applying the per-link configuration
/// this daemon writes -- so a host pointed at it is a host our `resolvectl dns
/// <tun>` would not reach, which is the same leak under another address.
const STUB_RESOLVER: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 53));

/// The routing domain that catches every query no longer domain matches.
const DEFAULT_ROUTING_DOMAIN: &str = "~.";

/// `/etc/resolv.conf` is read by every resolver on the machine, so it is
/// world-readable and root-writable. Not negotiable: a private one breaks name
/// resolution for every process that is not root.
const RESOLV_CONF_MODE: u32 = 0o644;

/// What the direct backend calls itself in `DnsBackup::service`.
///
/// A sentinel rather than an empty string so the record says which backend
/// wrote it, and so each backend can *refuse* a record the other one wrote --
/// see [`Dns::write`]. It is deliberately not a bare path: nothing here ever
/// uses the recorded string as a path to write to.
const FILE_SENTINEL_PREFIX: &str = "file:";

/// The backend this host wants, chosen once.
pub enum Dns {
    /// systemd-resolved, configured per link through `resolvectl`.
    Resolved { program: PathBuf },
    /// `/etc/resolv.conf`, replaced and put back.
    Direct { path: PathBuf },
}

impl Dns {
    /// Choose a backend. Infallible, because the direct backend works anywhere.
    ///
    /// Three conditions for resolved, all cheap, all at startup, and all
    /// required. The third is the one an obvious reading leaves out; the module
    /// comment says what leaving it out costs.
    pub fn probe() -> Self {
        let direct = Dns::Direct {
            path: PathBuf::from(RESOLV_CONF),
        };

        let Some(program) = RESOLVECTL_CANDIDATES
            .iter()
            .map(Path::new)
            .find(|candidate| candidate.exists())
        else {
            log::info!(
                "DNS: no resolvectl at {} -- managing {RESOLV_CONF} directly",
                RESOLVECTL_CANDIDATES.join(" or ")
            );
            return direct;
        };

        // The file before the daemon, and the order is deliberate.
        //
        // `org.freedesktop.resolve1` is D-Bus activatable -- its service file
        // carries `SystemdService=dbus-org.freedesktop.resolve1.service` -- so
        // `resolvectl status` *starts* systemd-resolved on a host where it is
        // disabled but not masked. Asking the question would change the answer,
        // and it would start a service the administrator turned off, as a side
        // effect of this daemon booting.
        //
        // Reading `/etc/resolv.conf` first removes that: on any host where
        // resolved is not already the resolver, this condition fails and the
        // D-Bus call is never made. It is also the cheaper of the two, so the
        // common direct-backend case costs one file read rather than a
        // subprocess.
        match std::fs::read_to_string(RESOLV_CONF) {
            Ok(contents) if stub_resolver_in_use(&contents) => {
                // Only now, and `resolvectl status` rather than `systemctl
                // is-active`: positive proof that the daemon answers on D-Bus,
                // rather than a proxy for it. A unit can be active with a
                // resolved that is not yet listening.
                //
                // `--no-pager` because systemd's tools page long output, and
                // this one is long. Their check is whether stdout is a terminal
                // -- it is a pipe here, so no pager runs either way -- but a
                // daemon that could be made to fork `less` by an environment
                // variable is not worth the argument saved.
                if let Err(e) = run(program, &["--no-pager".to_string(), "status".to_string()]) {
                    log::info!(
                        "DNS: {RESOLV_CONF} points at the stub but resolvectl does not answer \
                         ({e}) -- managing {RESOLV_CONF} directly",
                    );
                    return direct;
                }
                warn_about_a_contested_default_domain(program);
                Dns::Resolved {
                    program: program.to_path_buf(),
                }
            }
            Ok(_) => {
                // resolved's `uplink` or `foreign` mode. Configuring it would
                // succeed and change nothing for any glibc client, so the file
                // is what gets managed instead.
                log::info!(
                    "DNS: systemd-resolved is running, but {RESOLV_CONF} does not list \
                     {STUB_RESOLVER} -- so clients read the host's own resolvers straight \
                     out of it and per-link configuration would be bypassed. Managing \
                     {RESOLV_CONF} directly instead"
                );
                direct
            }
            Err(e) => {
                log::info!(
                    "DNS: could not read {RESOLV_CONF} ({e}) -- managing it directly, since \
                     nothing proves clients reach systemd-resolved"
                );
                direct
            }
        }
    }

    /// The file this backend manages, when it manages one.
    ///
    /// `Some` only for the direct backend, and it is what decides whether a
    /// watcher is needed: that file is contended -- NetworkManager rewrites it
    /// on reconnect and `netconfig` on its own schedule -- while the resolved
    /// backend's per-link configuration has no other writer at all.
    pub fn watched_file(&self) -> Option<&Path> {
        match self {
            Dns::Resolved { .. } => None,
            Dns::Direct { path } => Some(path),
        }
    }

    pub fn backend_name(&self) -> &'static str {
        match self {
            Dns::Resolved { .. } => "systemd-resolved",
            Dns::Direct { .. } => "resolv.conf",
        }
    }

    /// What `DnsBackup::service` will name for a session on `interface`.
    ///
    /// The resolved backend answers with the **tunnel's** link, never the
    /// physical one: our resolvers on `eno1` are clobbered by NetworkManager on
    /// the next DHCP renew, and the link's own configuration dies with the link
    /// instead, which is what keeps revert nearly free.
    pub fn primary_service(&self, interface: &str) -> std::io::Result<String> {
        match self {
            Dns::Resolved { .. } => link_arg(interface),
            Dns::Direct { path } => Ok(format!("{FILE_SENTINEL_PREFIX}{}", path.display())),
        }
    }

    /// What to put back later.
    pub fn read(&self, service: &str) -> std::io::Result<DnsState> {
        match self {
            // Empty, and not for want of trying. Two reasons, and the second
            // makes it the only correct answer rather than the simplest one.
            //
            // There is nothing to read: `read` is called on the *tunnel* link,
            // which was created moments ago and carries no resolvers until we
            // set them. And an empty `servers` is precisely what `write` turns
            // into `resolvectl revert`, which is the undo for this backend
            // whatever was there -- so reporting anything non-empty here would
            // make revert *set* those resolvers on a link that is by then gone.
            Dns::Resolved { .. } => {
                link_arg(service)?;
                Ok(DnsState::default())
            }
            Dns::Direct { path } => {
                check_file_service(service, path)?;
                read_file_state(path)
            }
        }
    }

    /// Set the resolvers, or put back what [`Dns::read`] recorded.
    ///
    /// An absent target is success -- and *only* that. Revert runs after the
    /// tunnel link is gone, so this is the ordinary case rather than an edge
    /// one, and an error there would report a revert that failed for ever: the
    /// link is never coming back. A D-Bus refusal, a missing `resolvectl` and a
    /// permission error all propagate, because swallowing one would report a
    /// clean revert, delete the record, and leave the host's DNS pointed into a
    /// tunnel that no longer exists.
    pub fn write(&self, service: &str, state: &DnsState) -> std::io::Result<()> {
        match self {
            Dns::Resolved { program } => {
                let Some(link) = self.own_service(service, link_arg(service).ok()) else {
                    return Ok(());
                };
                if state.servers.is_empty() {
                    // `resolvectl revert` is the undo for both halves at once,
                    // and it is what `resolvectl(1)` documents rather than
                    // something derived from what we set.
                    return forgiving(program, &revert_args(&link), service);
                }
                forgiving(program, &dns_args(&link, &state.servers), service)?;
                // The routing domain, and it is not decoration: without it
                // resolved consults this link only for names matching a domain
                // it was given, and every other query goes to the physical
                // one.
                forgiving(program, &domain_args(&link), service)
            }
            Dns::Direct { path } => {
                // The recorded service is checked, never used as a path. A
                // record written by the resolved backend names a link, and
                // acting on it here would replace this host's `/etc/resolv.conf`
                // -- quite possibly a symlink -- with an empty file, on the
                // strength of a record that describes something else entirely.
                let mine = check_file_service(service, path).is_ok();
                if self.own_service(service, mine.then_some(())).is_none() {
                    return Ok(());
                }
                write_file_state(path, state)
            }
        }
    }

    /// A service this backend wrote, or `None` if the record belongs to the
    /// other one.
    ///
    /// **Not an error, and that distinction is the whole point.** `AppliedState`
    /// survives a restart and the probe's answer can differ across one --
    /// stopping systemd-resolved, or a user troubleshooting their VPN by
    /// replacing `/etc/resolv.conf`, is all it takes. Revert then asks this
    /// backend to undo a record the other one wrote.
    ///
    /// Refusing to act on it is right: acting would flatten `/etc/resolv.conf`
    /// on the strength of a record describing a link. But *erroring* is wrong,
    /// and wrong in a way that does not heal. `Session::revert` would report the
    /// failure, `recover()` would keep the record rather than clearing it, and
    /// the supervisor would set `recovery_pending` -- which makes every `Start`
    /// fail, retrying the same recovery, which fails identically because the
    /// condition is permanent. The daemon would refuse to bring up any tunnel
    /// until someone found and deleted the record by hand.
    ///
    /// So it is the same category as [`is_absent_link`] and `routes.rs`'s absent
    /// route: there is nothing here for *this* backend to undo. Said out loud,
    /// because it means a record is being dropped.
    fn own_service<T>(&self, service: &str, parsed: Option<T>) -> Option<T> {
        if parsed.is_none() {
            log::warn!(
                "the recorded DNS service {service:?} was not written by the {} backend, so \
                 there is nothing here to undo -- the configuration it describes died with \
                 whatever wrote it",
                self.backend_name()
            );
        }
        parsed
    }

    /// Drop cached answers, so what already resolved picks the change up.
    ///
    /// Best effort, and a failure is logged rather than returned. A stale cache
    /// is a wrong answer for up to a TTL; a returned error here is far worse,
    /// because `Session::revert` collects it and the supervisor then keeps the
    /// record and sets `recovery_pending` -- so a masked systemd-resolved would
    /// leave the daemon permanently unable to start a tunnel, with every route
    /// already correctly removed. The resolvers are right either way by the time
    /// this runs; only the cache is not.
    pub fn flush(&self) -> std::io::Result<()> {
        match self {
            Dns::Resolved { program } => {
                if let Err(e) = run(program, &flush_args()) {
                    log::warn!("could not flush the DNS cache ({e}); it will expire on its own");
                }
                Ok(())
            }
            // Nothing to flush. Without resolved there is no system-wide DNS
            // cache on Linux at all: glibc's resolver caches nothing between
            // calls, and each application's own cache is its own business.
            // Saying so here rather than leaving an empty body, because an
            // empty one reads like an omission.
            Dns::Direct { .. } => Ok(()),
        }
    }
}

/// Run a `resolvectl` call, treating "that link is gone" as done.
///
/// Narrow on purpose: [`is_absent_link`] matches one message, and every other
/// failure -- a D-Bus refusal, a missing binary, a permission error -- is
/// returned. See [`Dns::write`] for what swallowing one would cost.
fn forgiving(program: &Path, args: &[String], service: &str) -> std::io::Result<()> {
    match run(program, args) {
        Ok(()) => Ok(()),
        Err(e) if is_absent_link(&e.to_string()) => {
            // Loud for an apply and quiet for a revert. A revert against a
            // link the kernel already took is the ordinary path; an *apply*
            // that lands here set no resolvers at all, and the session is
            // about to run with the host's -- which is worth a line even
            // though the tunnel's own routes will have failed first.
            if args.first().map(String::as_str) == Some("revert") {
                log::debug!("DNS: {service} was already gone");
            } else {
                log::warn!(
                    "DNS: {service} disappeared before its resolvers were set -- \
                         the session is running on the host's"
                );
            }
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Warn if another link already claims every query.
///
/// This is the Tailscale-as-exit-node case. `systemd-resolved.service(8)`'s
/// PROTOCOLS AND ROUTING section says that when several links tie on the
/// best-matching routing domain "the query is sent to all of them in parallel"
/// and the first successful answer wins -- so two links each claiming `~.` is a
/// race with no defined winner, and no configuration on our side settles it.
///
/// A warning rather than an error: the user may have made that trade knowingly.
/// But not silence, which would leave a nondeterministic tunnel looking like a
/// working one. A failure to ask is not itself a reason to refuse to start.
fn warn_about_a_contested_default_domain(program: &Path) {
    let Ok(output) = run_capturing(program, &["--no-pager", "domain"]) else {
        return;
    };
    for link in links_with_default_domain(&output) {
        log::warn!(
            "DNS: link {link} already routes all queries ({DEFAULT_ROUTING_DOMAIN}). \
             systemd-resolved asks every link that ties for the longest matching routing \
             domain and takes the first answer, so this session's DNS will race {link}'s \
             -- most likely a VPN in exit-node mode. Nothing on this side resolves it"
        );
    }
}

/// Whether `/etc/resolv.conf`'s contents mean clients reach resolved.
///
/// Every `nameserver` must be the stub, and there must be one. "Contains the
/// stub" is not enough: a file listing `127.0.0.53` *and* an upstream server is
/// a file glibc falls back to the upstream from the moment resolved is busy,
/// which is a leak that appears under load and nowhere else.
fn stub_resolver_in_use(contents: &str) -> bool {
    let servers = parse_nameservers(contents);
    !servers.is_empty() && servers.iter().all(|server| *server == STUB_RESOLVER)
}

/// The `nameserver` addresses in a `resolv.conf`, in order.
///
/// `resolv.conf(5)`: a line with `#` or `;` in the first column is a comment.
/// Anything that will not parse is dropped rather than failing the read, for
/// the reason the macOS backend gives -- this list is a backup to restore, and
/// one unparseable entry must not stop a session starting.
fn parse_nameservers(contents: &str) -> Vec<IpAddr> {
    contents
        .lines()
        .filter(|line| !line.starts_with('#') && !line.starts_with(';'))
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            if fields.next()? != "nameserver" {
                return None;
            }
            fields.next()
        })
        .filter_map(|server| server.parse().ok())
        .collect()
}

/// A `resolv.conf` body, and nothing else.
///
/// No "generated by shoesd" banner, deliberately: the same renderer writes the
/// session's resolvers and writes the recorded ones back, and a restore must
/// leave a file that looks like the one it replaced rather than one still
/// claiming a daemon owns it.
fn render_resolv_conf(servers: &[IpAddr]) -> String {
    servers
        .iter()
        .map(|server| format!("nameserver {server}\n"))
        .collect()
}

/// The links `resolvectl domain` says carry a `~.` routing domain.
///
/// Its output is a `Global:` line and then `Link N (name): domain...` per link.
/// Anything that does not fit that shape is skipped rather than treated as an
/// error: this feeds a warning, and a future release adding a line would
/// otherwise turn a formatting change into a false alarm.
fn links_with_default_domain(output: &str) -> Vec<String> {
    output
        .lines()
        .filter_map(|line| {
            let (_index, rest) = line.strip_prefix("Link ")?.split_once('(')?;
            let (name, domains) = rest.split_once(')')?;
            domains
                .strip_prefix(':')?
                .split_whitespace()
                .any(|domain| domain == DEFAULT_ROUTING_DOMAIN)
                .then(|| name.to_string())
        })
        .collect()
}

/// Whether a `resolvectl` failure means the link was simply not there.
///
/// Measured: `resolvectl revert nosuchlink0` exits **1** with `Failed to
/// resolve interface "nosuchlink0": No such device`. Matched on the message
/// because the exit status is 1 for every failure alike -- including the ones
/// that must propagate, which is the whole point of matching narrowly. `No such
/// file or directory`, the missing-binary error, does not contain this phrase.
fn is_absent_link(message: &str) -> bool {
    message.to_ascii_lowercase().contains("no such device")
}

/// `resolvectl dns <link> <server>...`
fn dns_args(link: &str, servers: &[IpAddr]) -> Vec<String> {
    let mut args = vec!["dns".to_string(), link.to_string()];
    // Re-serialised from `IpAddr`, never forwarded as the string that arrived
    // over the control socket.
    args.extend(servers.iter().map(IpAddr::to_string));
    args
}

/// `resolvectl domain <link> ~.`
fn domain_args(link: &str) -> Vec<String> {
    vec![
        "domain".to_string(),
        link.to_string(),
        DEFAULT_ROUTING_DOMAIN.to_string(),
    ]
}

/// `resolvectl revert <link>`
fn revert_args(link: &str) -> Vec<String> {
    vec!["revert".to_string(), link.to_string()]
}

/// `resolvectl flush-caches`
fn flush_args() -> Vec<String> {
    vec!["flush-caches".to_string()]
}

/// A link name, checked before it becomes an argument.
///
/// Not because argv can be injected into -- it cannot, which is why nothing
/// here goes near a shell -- but because this string reaches us twice from
/// outside: once as the configured tunnel name and once out of the on-disk
/// record, which a root-owned revert acts on at startup without a client
/// involved. A name shaped like an option or a path is a record that does not
/// describe a link, and running `resolvectl` on it is not the way to find out.
fn link_arg(service: &str) -> std::io::Result<String> {
    let acceptable = |c: char| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.');
    // `IFNAMSIZ` is 16 including the terminator, so 15 characters is the
    // kernel's own limit and nothing longer can name a link.
    if service.is_empty() || service.len() > 15 || !service.chars().all(acceptable) {
        return Err(std::io::Error::other(format!(
            "{service:?} is not a network link name, so nothing here will be run against it"
        )));
    }
    Ok(service.to_string())
}

/// Reject a record the other backend wrote.
///
/// `AppliedState` survives a restart, and the probe's answer can differ across
/// one -- installing or removing systemd-resolved is all it takes. A resolved
/// record names a link and carries no resolvers, so letting it through here
/// would replace `/etc/resolv.conf` with an empty file. That file is a symlink
/// on most hosts, and flattening it is the permanent breakage `symlink_target`
/// exists to prevent, arriving through the door the field does not cover.
fn check_file_service(service: &str, path: &Path) -> std::io::Result<()> {
    let expected = format!("{FILE_SENTINEL_PREFIX}{}", path.display());
    if service != expected {
        return Err(std::io::Error::other(format!(
            "the recorded DNS service {service:?} was not written by the resolv.conf \
             backend, which records {expected:?} -- so it says nothing about what {} \
             should contain",
            path.display()
        )));
    }
    Ok(())
}

/// What the file is now, in enough detail to put it back.
///
/// `symlink_metadata` and `read_link`, never `metadata`: the whole question is
/// what the *path* is, and `metadata` answers about the target instead -- which
/// on a resolved host reports a perfectly ordinary regular file and loses the
/// only fact restore needs.
fn read_file_state(path: &Path) -> std::io::Result<DnsState> {
    let symlink_target = match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Some(std::fs::read_link(path)?),
        Ok(_) => None,
        // No file at all is a state to record, not an error: glibc with no
        // `/etc/resolv.conf` queries localhost, which is what restoring an
        // empty regular file gives back as well.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e),
    };

    let contents = match std::fs::read_to_string(path) {
        Ok(contents) => Some(contents),
        // A dangling symlink, or nothing there. Both restore the same way.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e),
    };

    // The whole file, not only its `nameserver` lines. A `search` or `options`
    // line dropped on revert is a host whose short names stop resolving, and
    // nothing would say why.
    //
    // Only for a regular file that is really there. A symlink is put back as a
    // symlink and its target's contents were never ours; and a path that did
    // not exist stays `None` rather than becoming an empty string, so that
    // "there was no file" and "there was an empty file" do not collapse into
    // one record.
    let verbatim = match (&symlink_target, &contents) {
        (None, Some(contents)) => Some(contents.clone()),
        _ => None,
    };

    Ok(DnsState {
        servers: contents
            .as_deref()
            .map(parse_nameservers)
            .unwrap_or_default(),
        symlink_target,
        verbatim,
    })
}

/// Apply a state to the file, or restore one.
///
/// One function for both directions, because the difference is entirely in the
/// state: applying carries resolvers and no symlink target, restoring carries
/// whatever was read.
fn write_file_state(path: &Path, state: &DnsState) -> std::io::Result<()> {
    // A recorded symlink is restored *as a symlink*, and the resolvers that
    // were read through it are deliberately not written anywhere: they live in
    // the target, which the real manager still owns and still rewrites.
    if let Some(target) = &state.symlink_target {
        remove_if_present(path)?;
        return std::os::unix::fs::symlink(target, path);
    }

    // A recorded regular file is replayed byte for byte rather than rebuilt
    // from `servers`, which would drop every directive that is not a
    // `nameserver` -- `search` above all, whose loss stops short names
    // resolving with nothing to say why. Absent `verbatim` is the apply
    // direction, which has resolvers and nothing to restore.
    match &state.verbatim {
        Some(contents) => replace_with_regular_file(path, contents),
        None => replace_with_regular_file(path, &render_resolv_conf(&state.servers)),
    }
}

/// Replace the path with a regular file holding `contents`.
///
/// `remove_file` first and a rename over the top, never a write to the open
/// path. Writing through a symlink would rewrite the target -- on a resolved
/// host that is `/run/systemd/resolve/stub-resolv.conf`, and the damage
/// outlives the session by as long as it takes someone to notice.
///
/// The rename makes the swap atomic, so no client ever reads a half-written
/// resolver list; it is also what NetworkManager and `netconfig` do, which is
/// why the direct backend's watcher has to watch the directory rather than the
/// file.
fn replace_with_regular_file(path: &Path, contents: &str) -> std::io::Result<()> {
    // Already what we want: do nothing at all, rather than rename an identical
    // file over itself.
    //
    // This is not an optimisation, it breaks a feedback loop. `Session::reapply`
    // writes DNS *unconditionally* on every `NetworkChanged`
    // (`host/plan.rs`), deliberately, because its macOS arm has no signal to
    // compare against. On this backend that write is the rename below -- which
    // is exactly the `IN_MOVED_TO` the direct backend's watcher exists to
    // catch. Manager rewrites the file, we re-apply, our own re-apply wakes the
    // watcher, it reports again, and the daemon rewrites `/etc/resolv.conf`
    // several times a second for the life of the process with nothing in any
    // log saying so.
    //
    // `symlink_metadata`, so replacing a symlink with a regular file of the
    // same contents still happens: the *type* of the path is the thing being
    // changed there, and reading through the link would say they already match.
    if let Ok(metadata) = std::fs::symlink_metadata(path)
        && metadata.file_type().is_file()
        && std::fs::read_to_string(path).is_ok_and(|current| current == contents)
    {
        // The bytes are right; the mode still has to be. Skipping this would
        // leave a `/etc/resolv.conf` that another writer, or an earlier run
        // under a restrictive umask, left at 0600 -- unreadable to every
        // non-root resolver on the machine, and invisible here precisely
        // because the contents already match.
        //
        // Fixed in place rather than by falling through to the rewrite below:
        // a rename would be seen by this backend's own watcher and start the
        // feedback loop this early return exists to prevent. `set_permissions`
        // is not a directory change and wakes nothing.
        if metadata.permissions().mode() & 0o777 != RESOLV_CONF_MODE {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(RESOLV_CONF_MODE))?;
        }
        return Ok(());
    }

    let directory = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "resolv.conf".to_string());
    let temporary = directory.join(format!(".{name}.shoesd"));

    let written = (|| -> std::io::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            // A request, not a guarantee -- see the `set_permissions` below.
            .mode(RESOLV_CONF_MODE)
            .open(&temporary)?;
        file.write_all(contents.as_bytes())?;
        file.set_permissions(std::fs::Permissions::from_mode(RESOLV_CONF_MODE))?;

        // The mode is set explicitly rather than trusted to `open`, because
        // `open`'s is neither reliable nor sufficient here, and this file has
        // to stay world-readable: every resolver on the machine reads it, and
        // one that is not would break DNS for every process that is not root
        // while the daemon went on reporting RUNNING.
        //
        // Two ways `.mode()` alone loses, both measured rather than assumed:
        // it is masked by the process umask, so `shoesd run` started from a
        // shell with `umask 077` -- or under a unit with a restrictive
        // `UMask=` -- creates 0600; and it is ignored outright when the file
        // already exists, which a `.resolv.conf.shoesd` left by an interrupted
        // run does. `install.rs::stage` guards the same hazard from the other
        // direction, and `state.rs::save` and `socket.rs::bind` both set the
        // mode after the fact for the same reason.

        // The one file whose loss between here and a power cut breaks name
        // resolution outright, and the record on disk describes the file we are
        // replacing rather than this one.
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temporary, path)
    })();

    if written.is_err() {
        // Leaving `.resolv.conf.shoesd` behind would be picked up by nothing
        // and explained by nothing.
        let _ = std::fs::remove_file(&temporary);
    }
    written
}

/// Remove a path, treating "it was not there" as done.
///
/// Revert is asked to restore a symlink over a file this daemon may already
/// have removed -- `recover()` re-runs against a record whose revert partly
/// succeeded -- so a `NotFound` here is the idempotence the record needs, not a
/// failure. Every other error propagates.
fn remove_if_present(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// How long to wait after a burst before reporting it.
///
/// The route monitor's 300 ms, for the route monitor's reason: one rewrite of
/// `/etc/resolv.conf` is several events -- the temporary created, written and
/// closed, then renamed over the path -- and answering each would mean a
/// re-apply per event while the file is still moving.
const SETTLE: std::time::Duration = std::time::Duration::from_millis(300);

/// What a rewrite of the watched file looks like from its **directory**.
///
/// The directory, never the file, and this is the whole hazard: NetworkManager
/// and `netconfig` both write a temporary and `rename` over the path -- which
/// is exactly what [`replace_with_regular_file`] does here, for the same
/// atomicity reason -- and a rename does not touch the inode the old watch is
/// attached to. A watch on the file itself would therefore report the first
/// rewrite and then stay silent for ever, which is worse than no watcher at
/// all, because it looks like it is working.
///
/// `IN_MOVED_TO` is the rename landing, and the one that matters.
/// `IN_CREATE` and `IN_CLOSE_WRITE` cover a manager that writes the path in
/// place instead, and `IN_DELETE` one that removes it first.
const WATCH_MASK: u32 =
    libc::IN_MOVED_TO | libc::IN_CREATE | libc::IN_CLOSE_WRITE | libc::IN_DELETE;

/// Watch the file the direct backend manages, calling `on_change` when it moves.
///
/// The gap this closes: `/etc/resolv.conf` is contended in a way the resolved
/// backend's per-link configuration is not. NetworkManager rewrites it on every
/// reconnect and openSUSE's `netconfig` on its own schedule, so a mid-session
/// reconnect reverts DNS to the host's own resolvers while the tunnel stays up
/// and the daemon still reports `RUNNING` -- a leak with no symptom, which is
/// the worst shape a leak has.
///
/// `on_change` must not be the re-apply itself. It posts
/// `Command::NetworkChanged`, exactly as the route monitor's does, so the
/// re-apply is serialised with `Start` and `Stop` rather than racing them.
///
/// The thread runs for the life of the process and is detached for the reason
/// [`monitor::spawn`](super::monitor::spawn) gives: there is nothing to join it
/// for, and shutdown must not wait on a `read` only the kernel can end. It
/// keeps the same recorded consequence too -- a non-recoverable read error ends
/// it, logged, and a daemon up for weeks may no longer be watching.
///
/// This cannot make the losing window zero, only short. Said here so it is a
/// known property rather than a bug report.
pub fn watch(path: &Path, on_change: impl Fn() + Send + 'static) -> std::io::Result<()> {
    let name = path
        .file_name()
        .ok_or_else(|| std::io::Error::other(format!("{} names no file to watch", path.display())))?
        .to_os_string();
    let path = path.to_path_buf();

    let fd = open_directory_watch(&path)?;

    // Owned before the thread exists, so a `spawn` that fails closes the
    // descriptor rather than leaking it. The guard is moved into the closure,
    // which is dropped un-run on that path.
    let guard = FdGuard(fd);

    std::thread::Builder::new()
        .name("shoesd-resolv-watch".to_owned())
        .spawn(move || {
            let _guard = guard;
            // A directory watch reports every file in `/etc`, so one read
            // carries several records. `inotify(7)` gives `sizeof(struct
            // inotify_event) + NAME_MAX + 1` as the minimum that can hold one;
            // this holds a burst of them.
            let mut buffer = [0u8; 4096];
            // What the file held when the watch went on, so the first event is
            // judged against reality rather than against nothing.
            let mut reported = current_bytes(&path);

            loop {
                // SAFETY: `buffer` is valid for `len` bytes for the duration of
                // the call, and `fd` is open until `_guard` drops.
                let read = unsafe {
                    libc::read(fd, buffer.as_mut_ptr() as *mut libc::c_void, buffer.len())
                };

                if read < 0 {
                    let error = std::io::Error::last_os_error();
                    if recoverable(&error) {
                        continue;
                    }
                    // Losing the watcher costs re-application when something
                    // else rewrites the file, not the session.
                    log::error!("the {} watcher stopped: {error}", path.display());
                    return;
                }
                if read == 0 {
                    log::error!("the {} watcher's inotify queue closed", path.display());
                    return;
                }

                if !names_the_file(&buffer[..read as usize], &name) {
                    // Something else in the directory. `/etc` is busy, and
                    // answering every write to it would re-apply DNS on every
                    // package upgrade.
                    continue;
                }

                // Drain whatever else the burst queued before looking, so one
                // rewrite becomes one report.
                std::thread::sleep(SETTLE);
                drain(fd, &mut buffer);

                if !changed_since_last_report(&mut reported, current_bytes(&path)) {
                    continue;
                }
                on_change();
            }
        })?;

    Ok(())
}

/// Create the inotify descriptor and watch the file's directory.
///
/// Separate from [`watch`] because it is the half that can fail before the
/// thread starts, and so the half a test can cover -- see the test below, and
/// `monitor.rs`'s `open_route_socket` for the same split and the same reason.
///
/// `IN_CLOEXEC`, because this daemon forks `resolvectl` and `ip`, and a
/// descriptor inherited by them is one this process cannot account for.
fn open_directory_watch(path: &Path) -> std::io::Result<RawFd> {
    let directory = path.parent().unwrap_or_else(|| Path::new("."));
    let directory = CString::new(directory.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::other(format!(
            "{} cannot be watched: its directory's name contains a NUL",
            path.display()
        ))
    })?;

    // SAFETY: a plain syscall with a constant argument.
    let fd: RawFd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // Owned from here on, so a failing watch does not leak the descriptor.
    let inotify = FdGuard(fd);

    // SAFETY: `directory` is a NUL-terminated C string that outlives the call,
    // and `fd` is open and owned by `inotify`.
    let watch = unsafe { libc::inotify_add_watch(fd, directory.as_ptr(), WATCH_MASK) };
    if watch < 0 {
        // Read errno before `inotify` drops: the close in its `Drop` would be
        // the last syscall otherwise, and errno is per-thread, not per-fd.
        let error = std::io::Error::last_os_error();
        return Err(error);
    }

    Ok(inotify.into_raw())
}

/// Whether a raw inotify buffer says the file we care about was touched.
///
/// Pure, and the only part of this worth testing exhaustively, because the
/// buffer is the one place here that is easy to get wrong. `inotify_event` is a
/// **variable-length** record: a fixed header, then `len` bytes holding a
/// NUL-terminated name padded out for alignment. So the walk advances by
/// `size_of::<inotify_event>() + len` and never by a fixed stride, one read can
/// hold any number of records, and `len` can be zero -- which means the event
/// is about the watched directory itself and carries no name.
///
/// `read_unaligned`, because the kernel packs records back to back and only the
/// first is guaranteed to sit on the struct's alignment.
fn names_the_file(buffer: &[u8], name: &OsStr) -> bool {
    let header = std::mem::size_of::<libc::inotify_event>();
    let mut offset = 0usize;

    while offset + header <= buffer.len() {
        // SAFETY: the slice holds at least `header` bytes from `offset`, and
        // every field of `inotify_event` is an integer -- so any bit pattern of
        // that length is a valid value and the read is initialised. Unaligned
        // because the record's start is wherever the previous one ended.
        let event: libc::inotify_event =
            unsafe { std::ptr::read_unaligned(buffer[offset..].as_ptr().cast()) };

        let start = offset + header;
        let Some(end) = start
            .checked_add(event.len as usize)
            .filter(|end| *end <= buffer.len())
        else {
            // A record that runs past the buffer. Nothing after it can be
            // believed, and indexing on its word would panic in a detached
            // thread.
            return false;
        };

        // The name is NUL-terminated inside its padding, so the bytes `len`
        // describes are longer than it. Comparing all of them matches nothing.
        let padded = &buffer[start..end];
        let named = padded
            .iter()
            .position(|byte| *byte == 0)
            .map_or(padded, |nul| &padded[..nul]);

        // An empty name is the directory itself -- `IN_Q_OVERFLOW` arrives that
        // way -- and never the file.
        if !named.is_empty() && OsStr::from_bytes(named) == name {
            return true;
        }

        offset = end;
    }

    false
}

/// The file's bytes, or `None` if there is nothing to read.
///
/// Bytes rather than a parsed resolver list: the only question asked of this is
/// whether the file is the one we last reported, and a parse would answer a
/// narrower one -- a `search` line replaced under us is a change too.
fn current_bytes(path: &Path) -> Option<Vec<u8>> {
    std::fs::read(path).ok()
}

/// Whether the file now differs from the state this watcher last reported.
///
/// Without this the watcher is a loop, and the reason is that the handler's
/// work is indistinguishable from the event it answers: re-applying DNS on the
/// direct backend *is* a rename over the watched path. Report unconditionally
/// and the sequence is -- manager writes, we report, the supervisor re-applies,
/// the re-apply wakes us, we report again -- about three writes a second to
/// `/etc/resolv.conf` for the life of the process, with nothing in any log
/// saying so.
///
/// Comparing bytes rather than debouncing, because a debounce only narrows the
/// window: `on_change` posts a message, and the supervisor re-writes the file
/// whenever it gets round to it, which may be well after any quiet period this
/// thread could wait out. Bytes converge instead -- a foreign rewrite is
/// reported, the re-apply that answers it is reported once more because it
/// really did change the file back, and the look after that sees the same bytes
/// and stops.
///
/// What it gives up: a rewrite that leaves the contents byte-identical is not
/// reported. Nothing to re-apply in that case, with one exception worth naming
/// -- a manager replacing the file with a symlink to identical contents changes
/// what the *record* should say and this will not notice.
///
/// The durable fix is not here. It is for the re-apply to be a no-op when the
/// file already holds the wanted resolvers, in `Session::reapply`, which writes
/// them unconditionally because its macOS arm has no signal to compare against.
/// This is the local half, and it is in the watcher because that is the file
/// this change may touch.
fn changed_since_last_report(reported: &mut Option<Vec<u8>>, now: Option<Vec<u8>>) -> bool {
    if *reported == now {
        return false;
    }
    *reported = now;
    true
}

/// Whether a read error is one to carry on from.
///
/// `Interrupted` and `WouldBlock`, and there is deliberately no third. inotify
/// has no `ENOBUFS` twin: when the kernel's event queue fills it enqueues an
/// `IN_Q_OVERFLOW` **event** rather than failing the read, so the overrun
/// arrives through the ordinary path and needs no handling here -- this watcher
/// re-reads the file rather than tracking a delta, so the events it lost say
/// nothing that looking cannot. That is the route monitor's `netlink(7)`
/// argument in inotify's spelling.
fn recoverable(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
    )
}

/// Read and discard whatever is queued, without blocking.
///
/// `poll` with a zero timeout rather than an `IN_NONBLOCK` descriptor: the read
/// in the loop above is meant to block, which is the whole of this thread's
/// idle behaviour, and a non-blocking descriptor would turn it into a spin.
fn drain(fd: RawFd, buffer: &mut [u8]) {
    loop {
        let mut waiting = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one initialised `pollfd` is described to `poll`, and `fd` is
        // open for the duration of the call.
        let ready = unsafe { libc::poll(std::ptr::addr_of_mut!(waiting), 1, 0) };
        if ready <= 0 {
            return;
        }

        // SAFETY: as the read above; this only runs when `poll` said the
        // descriptor is readable, so it cannot park the thread.
        let read =
            unsafe { libc::read(fd, buffer.as_mut_ptr() as *mut libc::c_void, buffer.len()) };
        if read <= 0 {
            return;
        }
    }
}

/// Closes the inotify descriptor when the thread ends.
///
/// The twin of `monitor.rs`'s, kept separate rather than shared because that
/// one is private to its module and this file may not reach into it.
struct FdGuard(RawFd);

impl FdGuard {
    /// Hand the descriptor to a caller that will close it instead.
    fn into_raw(self) -> RawFd {
        let fd = self.0;
        std::mem::forget(self);
        fd
    }
}

impl Drop for FdGuard {
    fn drop(&mut self) {
        // SAFETY: the fd was opened here and is not shared.
        unsafe { libc::close(self.0) };
    }
}

/// Run a command, failing if it does.
fn run(program: &Path, args: &[String]) -> std::io::Result<()> {
    let output = Command::new(program).args(args).output().map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!("could not run {} {args:?}: {e}", program.display()),
        )
    })?;

    if output.status.success() {
        return Ok(());
    }
    Err(std::io::Error::other(format!(
        "{} {args:?} failed ({}): {}",
        program.display(),
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    )))
}

/// Run a command and return its stdout.
fn run_capturing(program: &Path, args: &[&str]) -> std::io::Result<String> {
    let output = Command::new(program).args(args).output().map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!("could not run {} {args:?}: {e}", program.display()),
        )
    })?;

    if !output.status.success() {
        return Err(std::io::Error::other(format!(
            "{} {args:?} failed ({})",
            program.display(),
            output.status
        )));
    }
    String::from_utf8(output.stdout).map_err(|e| {
        std::io::Error::other(format!(
            "{} produced non-UTF-8 output: {e}",
            program.display()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::ffi::OsString;
    use std::fs;
    use std::os::unix::fs::symlink;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// Mode 1: `/etc/resolv.conf` -> `/run/systemd/resolve/stub-resolv.conf`.
    const STUB_MODE: &str = "\
# This is /run/systemd/resolve/stub-resolv.conf managed by man:systemd-resolved(8).
# Do not edit.
#
# Third party programs should typically not access this file directly, but only
# through the symlink at /etc/resolv.conf.
nameserver 127.0.0.53
options edns0 trust-ad
search lan
";

    /// Mode 2: `/etc/resolv.conf` -> `/usr/lib/systemd/resolv.conf`.
    const STATIC_MODE: &str = "\
# This is /usr/lib/systemd/resolv.conf managed by man:systemd-resolved(8).
# Do not edit.
nameserver 127.0.0.53
options edns0 trust-ad
";

    /// Mode 3: `/etc/resolv.conf` -> `/run/systemd/resolve/resolv.conf`, which
    /// lists the uplink servers themselves.
    const UPLINK_MODE: &str = "\
# This is /run/systemd/resolve/resolv.conf managed by man:systemd-resolved(8).
# Do not edit.
nameserver 192.168.1.1
nameserver fd57:69ae:43c6::1
search lan
";

    /// Mode 4: someone else's file, with resolved a consumer of it rather than
    /// a provider.
    const FOREIGN_MODE: &str = "\
# Generated by NetworkManager
search lan
nameserver 192.168.1.1
nameserver 1.1.1.1
";

    /// The two modes where per-link configuration reaches every client.
    #[test]
    fn both_stub_modes_select_resolved() {
        assert!(stub_resolver_in_use(STUB_MODE));
        assert!(stub_resolver_in_use(STATIC_MODE));
    }

    /// The test that stops the silent leak, and the reason the probe is three
    /// conditions rather than the two the brief asked for. In both of these
    /// resolved is running and `resolvectl dns <link>` succeeds -- and every
    /// glibc client reads the addresses in the file instead, straight out of
    /// the physical interface.
    #[test]
    fn the_uplink_and_foreign_modes_select_the_direct_backend() {
        assert!(!stub_resolver_in_use(UPLINK_MODE));
        assert!(!stub_resolver_in_use(FOREIGN_MODE));
    }

    /// "Contains the stub" is not the condition. A file listing both is one
    /// glibc falls back from the moment resolved is slow to answer, which is a
    /// leak that shows up under load and nowhere else.
    #[test]
    fn a_real_resolver_beside_the_stub_is_not_the_stub_mode() {
        assert!(!stub_resolver_in_use(
            "nameserver 127.0.0.53\nnameserver 192.168.1.1\n"
        ));
    }

    /// `127.0.0.54` is the proxy stub, which forwards to the current upstream
    /// servers without applying the per-link configuration we write. Accepting
    /// it would select a backend whose writes reach nothing.
    #[test]
    fn the_proxy_stub_is_not_the_stub_resolver() {
        assert!(!stub_resolver_in_use("nameserver 127.0.0.54\n"));
    }

    /// `resolv.conf(5)`: `#` or `;` in the first column is a comment. Every one
    /// of these fixtures' headers mentions the file it came from, and a
    /// substring search for the stub address would find one in a file whose
    /// live resolvers are somebody's LAN router.
    #[test]
    fn a_commented_out_stub_does_not_count() {
        assert!(!stub_resolver_in_use(
            "#nameserver 127.0.0.53\nnameserver 192.168.1.1\n"
        ));
        assert!(!stub_resolver_in_use(";nameserver 127.0.0.53\n"));
        assert!(!stub_resolver_in_use(""));
    }

    /// Order is preserved and both families survive the round trip -- the list
    /// is a backup, and restoring it in a different order changes which
    /// resolver a host prefers.
    #[test]
    fn nameservers_are_parsed_and_rendered() {
        assert_eq!(
            parse_nameservers(UPLINK_MODE),
            vec![ip("192.168.1.1"), ip("fd57:69ae:43c6::1")]
        );
        assert_eq!(
            parse_nameservers(&render_resolv_conf(&[ip("10.0.0.1"), ip("10.0.0.2")])),
            vec![ip("10.0.0.1"), ip("10.0.0.2")]
        );
    }

    /// The shape of every command this daemon runs as root against DNS,
    /// asserted here rather than discovered on a live machine.
    #[test]
    fn the_resolvectl_argv_is_one_element_per_argument() {
        assert_eq!(
            dns_args("shoes0", &[ip("10.0.0.1"), ip("10.0.0.2")]),
            vec!["dns", "shoes0", "10.0.0.1", "10.0.0.2"]
        );
        assert_eq!(domain_args("shoes0"), vec!["domain", "shoes0", "~."]);
        assert_eq!(revert_args("shoes0"), vec!["revert", "shoes0"]);
        assert_eq!(flush_args(), vec!["flush-caches"]);
    }

    /// Nothing a caller sent can become a second argument or a shell token.
    /// The addresses in these arrays arrive over the control socket, and
    /// OpenVPN Connect shipped CVE-2026-9560 by interpolating theirs.
    #[test]
    fn no_resolvectl_argument_carries_a_separator() {
        let commands = [
            dns_args("shoes0", &[ip("10.0.0.1"), ip("2001:db8::1")]),
            domain_args("shoes0"),
            revert_args("shoes0"),
            flush_args(),
        ];
        for argv in &commands {
            for arg in argv {
                assert!(
                    !arg.contains(char::is_whitespace) && !arg.contains(';'),
                    "{arg:?} in {argv:?}"
                );
            }
        }
    }

    /// The link name reaches this module from the on-disk record as well as
    /// from the session, and recovery acts on the record at startup with no
    /// client involved. A name shaped like an option or another backend's
    /// sentinel is a record that does not describe a link.
    #[test]
    fn a_link_name_that_could_become_a_second_argument_is_refused() {
        for bad in ["", "shoes0 --set-dns", "file:/etc/resolv.conf", "a/b"] {
            assert!(link_arg(bad).is_err(), "{bad:?}");
        }
        assert_eq!(link_arg("shoes0").ok(), Some("shoes0".to_string()));
    }

    /// Only "the link is gone" is success, and that case is the ordinary one:
    /// revert runs after the kernel has already taken the tunnel. Everything
    /// else has to reach `Session::revert`, which is what keeps the on-disk
    /// record instead of deleting it and leaving the host's DNS pointed into a
    /// tunnel that no longer exists.
    #[test]
    fn only_an_absent_link_counts_as_already_reverted() {
        assert!(is_absent_link(
            "resolvectl [\"revert\", \"shoes0\"] failed (exit status: 1): \
             Failed to resolve interface \"shoes0\": No such device"
        ));

        for real in [
            "could not run resolvectl [\"revert\", \"shoes0\"]: \
             No such file or directory (os error 2)",
            "resolvectl failed (exit status: 1): Failed to set DNS configuration: \
             Access denied",
            "resolvectl failed (exit status: 1): Failed to set DNS configuration: \
             Permission denied",
        ] {
            assert!(!is_absent_link(real), "{real} must not be swallowed");
        }
    }

    /// Tailscale's default configuration, measured on the development host: it
    /// claims its own domains and the `100.64/10` reverse space, and no `~.`.
    /// There is no contest, and warning about one would train the user to
    /// ignore the warning that matters.
    #[test]
    fn tailscales_default_domains_are_not_a_contest() {
        let output = "\
Global:
Link 2 (eno1): lan
Link 5 (tailscale0): tailf8307c.ts.net ~100.100.in-addr.arpa
Link 6 (docker0):
";
        assert!(links_with_default_domain(output).is_empty());
    }

    /// Exit-node mode, where Tailscale does claim `~.`. resolved then asks both
    /// links in parallel and takes the first answer, which nothing on our side
    /// decides -- so the link is named rather than papered over.
    #[test]
    fn an_exit_node_claiming_everything_is_named() {
        let output = "\
Global:
Link 2 (eno1): lan
Link 5 (tailscale0): ~. tailf8307c.ts.net
";
        assert_eq!(links_with_default_domain(output), vec!["tailscale0"]);
    }

    /// The round trip this backend exists to get right. A restore that wrote
    /// the resolvers back instead of recreating the link would leave a regular
    /// file where `/etc/resolv.conf` was a symlink, and the next time the real
    /// manager rewrote its target nothing would follow -- a host broken until
    /// someone re-links it by hand, long after this daemon is gone.
    #[test]
    fn a_symlink_is_recorded_and_restored_as_a_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("stub-resolv.conf");
        let path = dir.path().join("resolv.conf");
        fs::write(&target, STUB_MODE).unwrap();
        symlink(&target, &path).unwrap();

        let recorded = read_file_state(&path).unwrap();
        assert_eq!(recorded.symlink_target.as_deref(), Some(target.as_path()));
        assert_eq!(recorded.servers, vec![ip("127.0.0.53")]);

        // What a session leaves behind: a regular file where the link was.
        // Written here rather than by calling the apply path, so that this test
        // fails for one reason only -- restoring, which is the half that has to
        // recreate the link rather than write into whatever it finds.
        fs::remove_file(&path).unwrap();
        fs::write(&path, "nameserver 10.0.0.1\n").unwrap();

        write_file_state(&path, &recorded).unwrap();

        assert!(
            fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_symlink(),
            "a recorded symlink must come back as a symlink, not as its contents"
        );
        assert_eq!(fs::read_link(&path).unwrap(), target);
        assert_eq!(fs::read_to_string(&target).unwrap(), STUB_MODE);
    }

    /// And the other half: a host whose `/etc/resolv.conf` is a real file --
    /// Debian with NetworkManager, openSUSE with `netconfig` -- gets a real
    /// file back, with the resolvers it had.
    #[test]
    fn a_regular_file_is_restored_as_a_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resolv.conf");
        fs::write(&path, FOREIGN_MODE).unwrap();

        let recorded = read_file_state(&path).unwrap();
        assert!(recorded.symlink_target.is_none());

        write_file_state(&path, &DnsState::servers(&[ip("10.0.0.1")])).unwrap();
        write_file_state(&path, &recorded).unwrap();

        assert!(fs::symlink_metadata(&path).unwrap().file_type().is_file());
        assert_eq!(
            parse_nameservers(&fs::read_to_string(&path).unwrap()),
            vec![ip("192.168.1.1"), ip("1.1.1.1")]
        );
    }

    /// And it comes back *whole*, not just its resolvers.
    ///
    /// `/etc/resolv.conf` carries `search`, `options` and `sortlist` lines
    /// beside its `nameserver` ones, and a revert rebuilt from the parsed
    /// resolver list drops every one of them. The symptom is a host whose
    /// short names stop resolving after a session ends -- `ssh fileserver`
    /// failing where it worked an hour ago -- with nothing in any log
    /// connecting it to the VPN that was running, and no repair until whatever
    /// manages the file next rewrites it. On a `netconfig` host that is its own
    /// schedule, not ours.
    ///
    /// This is what `DnsState::verbatim` exists for, and the test above cannot
    /// see its absence: it compares only the resolvers, which a rebuilt file
    /// still has. Reintroduce the defect by restoring through
    /// `render_resolv_conf(&state.servers)` and this is the test that reddens.
    #[test]
    fn a_restored_regular_file_keeps_the_directives_that_are_not_resolvers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resolv.conf");
        fs::write(&path, FOREIGN_MODE).unwrap();

        let recorded = read_file_state(&path).unwrap();
        write_file_state(&path, &DnsState::servers(&[ip("10.0.0.1")])).unwrap();
        write_file_state(&path, &recorded).unwrap();

        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            FOREIGN_MODE,
            "the file the host had must come back byte for byte"
        );
    }

    /// `/etc/resolv.conf` must stay readable by everyone, whatever umask the
    /// daemon happened to inherit and whatever a previous run left behind.
    ///
    /// `OpenOptions::mode()` is not enough on its own and this pins both ways
    /// it loses: it is masked by the process umask -- `shoesd run` from a shell
    /// with `umask 077`, or under a unit with a restrictive `UMask=`, gets 0600
    /// -- and it is ignored entirely when the temporary already exists, which a
    /// `.resolv.conf.shoesd` left by an interrupted run does. Either produces a
    /// resolv.conf no non-root process can read, so every application on the
    /// machine stops resolving names while the daemon reports RUNNING and every
    /// route is perfectly correct.
    #[test]
    fn the_written_file_is_readable_by_everyone() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resolv.conf");
        let wanted = DnsState::servers(&[ip("10.0.0.1")]);

        // A leftover temporary from an interrupted run, private and in the way.
        let temporary = dir.path().join(".resolv.conf.shoesd");
        fs::write(&temporary, "stale").unwrap();
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600)).unwrap();

        write_file_state(&path, &wanted).unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644, "got {mode:o}");
    }

    /// Writing what the file already holds must touch nothing.
    ///
    /// Not a performance nicety -- it is what stops the direct backend and its
    /// own watcher driving each other. `Session::reapply` rewrites DNS
    /// unconditionally on every `NetworkChanged`, and on this backend that
    /// write is a rename over the watched path, which is exactly the
    /// `IN_MOVED_TO` the watcher reports. Without this the daemon rewrites
    /// `/etc/resolv.conf` several times a second for the life of the process,
    /// and nothing in any log says so.
    ///
    /// Asserted on the inode, because the contents look identical either way --
    /// which is precisely why the loop would be invisible.
    #[test]
    fn rewriting_identical_contents_does_not_replace_the_file() {
        use std::os::unix::fs::MetadataExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resolv.conf");

        let wanted = DnsState::servers(&[ip("10.0.0.1")]);
        write_file_state(&path, &wanted).unwrap();
        let first = fs::metadata(&path).unwrap().ino();

        write_file_state(&path, &wanted).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().ino(),
            first,
            "an identical rewrite must not rename a new file over the old one"
        );

        // And a real change still lands.
        write_file_state(&path, &DnsState::servers(&[ip("10.0.0.2")])).unwrap();
        assert_ne!(fs::metadata(&path).unwrap().ino(), first);
    }

    /// The mode is repaired even when the contents already match.
    ///
    /// The two guards in `replace_with_regular_file` interact, and this is
    /// where they meet. The early return exists to break the watcher feedback
    /// loop, so it must not rename -- but skipping the whole function also
    /// skips enforcing the mode, and a `/etc/resolv.conf` left at 0600 by
    /// another writer or by an earlier run under a restrictive umask is
    /// unreadable to every non-root resolver on the machine. Invisible from the
    /// contents, which are exactly right.
    ///
    /// So the mode is repaired in place, without a rename, which wakes no
    /// watcher. Both halves are asserted: falling through to the rewrite would
    /// fix the mode and bring the loop back. Reported by Copilot on PR #21.
    #[test]
    fn a_wrong_mode_is_repaired_even_when_the_contents_already_match() {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resolv.conf");
        let wanted = DnsState::servers(&[ip("10.0.0.1")]);

        write_file_state(&path, &wanted).unwrap();
        let inode = fs::metadata(&path).unwrap().ino();

        // Somebody else tightens it, leaving the contents alone.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        write_file_state(&path, &wanted).unwrap();

        let after = fs::metadata(&path).unwrap();
        assert_eq!(
            after.permissions().mode() & 0o777,
            0o644,
            "the mode is repaired"
        );
        assert_eq!(
            after.ino(),
            inode,
            "and repaired in place -- a rename here would wake this backend's own watcher"
        );
    }

    /// The exception the guard must not swallow: replacing a *symlink* with a
    /// regular file of the same contents is a change of the path's type, and
    /// reading through the link would report the two as already equal.
    #[test]
    fn an_identical_rewrite_still_replaces_a_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("stub-resolv.conf");
        let path = dir.path().join("resolv.conf");

        let wanted = DnsState::servers(&[ip("10.0.0.1")]);
        fs::write(&target, render_resolv_conf(&wanted.servers)).unwrap();
        symlink(&target, &path).unwrap();

        write_file_state(&path, &wanted).unwrap();

        assert!(
            fs::symlink_metadata(&path).unwrap().file_type().is_file(),
            "the link must be replaced even though it already read as the wanted contents"
        );
        assert_eq!(
            fs::read_to_string(&target).unwrap(),
            render_resolv_conf(&wanted.servers),
            "and its target must be untouched"
        );
    }

    /// A path that did not exist is not the same record as one holding an
    /// empty file, even though restoring either gives glibc the same answer.
    ///
    /// Collapsing them would make `verbatim` claim there were bytes to replay
    /// when there was no file at all -- a small lie today, and the kind that
    /// decides the wrong branch once "restore" learns to remove the path again.
    #[test]
    fn an_absent_file_records_no_contents_to_replay() {
        let dir = tempfile::tempdir().unwrap();
        let absent = read_file_state(&dir.path().join("resolv.conf")).unwrap();
        assert_eq!(absent.verbatim, None);

        let empty = dir.path().join("empty.conf");
        fs::write(&empty, "").unwrap();
        assert_eq!(
            read_file_state(&empty).unwrap().verbatim,
            Some(String::new())
        );
    }

    /// The apply half of the same hazard, and the one a `fs::write` would fail:
    /// writing the session's resolvers over a symlinked path must replace the
    /// *link*, not rewrite what it points at. Rewriting the target hands
    /// systemd's own `stub-resolv.conf` this daemon's contents, where nothing
    /// this daemon does at revert will ever put them back.
    #[test]
    fn applying_over_a_symlink_does_not_touch_its_target() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("stub-resolv.conf");
        let path = dir.path().join("resolv.conf");
        fs::write(&target, STUB_MODE).unwrap();
        symlink(&target, &path).unwrap();

        write_file_state(&path, &DnsState::servers(&[ip("10.0.0.1")])).unwrap();

        assert_eq!(
            fs::read_to_string(&target).unwrap(),
            STUB_MODE,
            "the link's target must be untouched"
        );
        assert!(fs::symlink_metadata(&path).unwrap().file_type().is_file());
        assert_eq!(
            parse_nameservers(&fs::read_to_string(&path).unwrap()),
            vec![ip("10.0.0.1")]
        );
    }

    /// Restoring twice is restoring once. `recover()` re-runs against a record
    /// whose revert may already have partly succeeded, and the retry is
    /// unbounded -- a revert that is not safe to run twice is not safe.
    #[test]
    fn restoring_twice_is_the_same_as_restoring_once() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("stub-resolv.conf");
        let path = dir.path().join("resolv.conf");
        fs::write(&target, STUB_MODE).unwrap();
        symlink(&target, &path).unwrap();

        let recorded = read_file_state(&path).unwrap();
        write_file_state(&path, &recorded).unwrap();
        write_file_state(&path, &recorded).unwrap();

        assert_eq!(fs::read_link(&path).unwrap(), target);
        // Restoring onto a path that is *already* the symlink must still not
        // write through it: that is the crash-recovery ordering, and a write
        // there hands systemd's own file this daemon's contents.
        assert_eq!(fs::read_to_string(&target).unwrap(), STUB_MODE);
    }

    /// A record the *resolved* backend wrote names a link and carries no
    /// resolvers. Acting on it here would replace `/etc/resolv.conf` -- a
    /// symlink on most hosts -- with an empty regular file, which is the
    /// permanent breakage `symlink_target` exists to prevent arriving through
    /// the one door that field does not cover. The probe's answer can change
    /// across a restart, so this is reachable without anything being tampered
    /// with.
    ///
    /// **It must be a no-op and not an error**, and the difference is not
    /// cosmetic. A returned error propagates through `Session::revert` into
    /// `recover()`, which then keeps the record instead of clearing it, which
    /// makes the supervisor set `recovery_pending` -- and that makes every
    /// `Start` fail while retrying the same recovery, which fails identically
    /// because the condition is permanent. Erring on the safe side here would
    /// wedge the daemon into refusing every tunnel until someone deleted the
    /// record by hand. There is genuinely nothing for this backend to undo: the
    /// link the record names died with the process that made it.
    #[test]
    fn a_record_from_the_other_backend_is_a_no_op_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resolv.conf");
        fs::write(&path, FOREIGN_MODE).unwrap();

        let dns = Dns::Direct { path: path.clone() };
        dns.write("shoes0", &DnsState::default())
            .expect("a foreign record is nothing to undo, not a failure");
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            FOREIGN_MODE,
            "and it must still not touch the file"
        );

        // And the sentinel it does write is the one it accepts back.
        let service = dns.primary_service("shoes0").unwrap();
        assert!(dns.read(&service).is_ok());
    }

    /// The mirror image: the resolved backend handed the direct backend's
    /// `file:` sentinel. Same reasoning, same answer -- nothing to undo, and no
    /// error to wedge recovery with.
    #[test]
    fn the_resolved_backend_ignores_a_file_record() {
        let dns = Dns::Resolved {
            program: PathBuf::from("/usr/bin/resolvectl"),
        };
        dns.write("file:/etc/resolv.conf", &DnsState::default())
            .expect("a foreign record is nothing to undo, not a failure");
    }

    /// The resolved backend names the tunnel's link, not the physical one:
    /// resolvers on `eno1` are clobbered by NetworkManager on the next DHCP
    /// renew, and that is the contention this design exists to avoid.
    #[test]
    fn the_resolved_backend_configures_the_tunnel_link() {
        let dns = Dns::Resolved {
            program: PathBuf::from("/usr/bin/resolvectl"),
        };
        assert_eq!(dns.primary_service("shoes0").unwrap(), "shoes0");
        assert_eq!(dns.backend_name(), "systemd-resolved");

        // And it reads back nothing, which is what makes revert a plain
        // `resolvectl revert` -- see `Dns::read`.
        assert_eq!(dns.read("shoes0").unwrap(), DnsState::default());
    }

    /// The direct backend's sentinel names the file, so `DnsBackup::service`
    /// stays meaningful in the record for both backends.
    #[test]
    fn the_direct_backend_names_the_file_it_manages() {
        let dns = Dns::Direct {
            path: PathBuf::from("/etc/resolv.conf"),
        };
        assert_eq!(
            dns.primary_service("shoes0").unwrap(),
            "file:/etc/resolv.conf"
        );
        assert_eq!(dns.backend_name(), "resolv.conf");
        // Nothing to flush without resolved, and that is success rather than
        // an unimplemented call.
        assert!(dns.flush().is_ok());
    }

    /// A file that is not there is a state to record rather than a failure:
    /// glibc with no `/etc/resolv.conf` queries localhost, which is what the
    /// empty file this restores does too.
    #[test]
    fn an_absent_file_reads_as_an_empty_state() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resolv.conf");

        assert_eq!(read_file_state(&path).unwrap(), DnsState::default());
        write_file_state(&path, &DnsState::default()).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "");
    }

    /// The size this module's buffer walk assumes for the fixed part of a
    /// record, asserted rather than trusted: the whole walk is `HEADER + len`
    /// per record, and a header of a different size would make every record
    /// after the first read from the middle of the previous one.
    const HEADER: usize = std::mem::size_of::<libc::inotify_event>();

    /// One raw record, laid out the way the kernel lays it out.
    ///
    /// The name is NUL-terminated and then padded to a multiple of the struct's
    /// alignment, which is what `inotify(7)` says the kernel does and why `len`
    /// is not the length of the name. Built by hand rather than by asking the
    /// kernel for one, so the walk is tested against the documented layout
    /// rather than against whatever this host happened to produce.
    fn event(mask: u32, name: &str) -> Vec<u8> {
        let padded = if name.is_empty() {
            0
        } else {
            (name.len() + 1).next_multiple_of(16)
        };

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1i32.to_ne_bytes()); // wd
        bytes.extend_from_slice(&mask.to_ne_bytes());
        bytes.extend_from_slice(&0u32.to_ne_bytes()); // cookie
        bytes.extend_from_slice(&(padded as u32).to_ne_bytes());
        assert_eq!(
            bytes.len(),
            HEADER,
            "this fixture must lay out the same header the walk reads"
        );

        bytes.extend_from_slice(name.as_bytes());
        bytes.resize(HEADER + padded, 0);
        bytes
    }

    fn watched(name: &str) -> OsString {
        OsString::from(name)
    }

    /// The ordinary case: NetworkManager renames its temporary over
    /// `/etc/resolv.conf` and the kernel reports `IN_MOVED_TO` with that name.
    #[test]
    fn a_rename_over_the_watched_file_is_a_change() {
        let buffer = event(libc::IN_MOVED_TO, "resolv.conf");
        assert!(names_the_file(&buffer, &watched("resolv.conf")));
    }

    /// `/etc` is busy, and a directory watch reports every file in it. Without
    /// the name filter the daemon re-applies DNS every time anything under
    /// `/etc` is written -- `mtab`, `adjtime`, a package upgrade -- which is a
    /// re-apply loop dressed up as a watcher.
    #[test]
    fn an_event_for_another_file_in_the_directory_is_ignored() {
        for other in ["hosts", "mtab", ".resolv.conf.shoesd"] {
            let buffer = event(libc::IN_MOVED_TO, other);
            assert!(
                !names_the_file(&buffer, &watched("resolv.conf")),
                "{other} is not the watched file"
            );
        }
    }

    /// One read carries as many records as fit, so the walk must not stop at
    /// the first. This is the shape a real rewrite produces -- the temporary
    /// created and closed, then renamed over the path -- and if the walk
    /// stopped early the one event that matters is the one it would miss,
    /// because it is last.
    #[test]
    fn several_records_in_one_read_are_all_walked() {
        let mut buffer = event(libc::IN_CREATE, ".resolv.conf.shoesd");
        buffer.extend(event(libc::IN_CLOSE_WRITE, ".resolv.conf.shoesd"));
        buffer.extend(event(libc::IN_MOVED_TO, "resolv.conf"));

        assert!(names_the_file(&buffer, &watched("resolv.conf")));
    }

    /// And a record whose name is *longer* than the one before it, so a walk
    /// that advanced by a fixed stride rather than by `HEADER + len` would land
    /// mid-record and compare rubbish.
    #[test]
    fn the_walk_advances_by_each_records_own_length() {
        let mut buffer = event(libc::IN_CREATE, "a");
        buffer.extend(event(
            libc::IN_MOVED_TO,
            "a-name-long-enough-to-need-a-second-padding-block",
        ));
        buffer.extend(event(libc::IN_MOVED_TO, "resolv.conf"));

        assert!(names_the_file(&buffer, &watched("resolv.conf")));
        assert!(names_the_file(
            &buffer,
            &watched("a-name-long-enough-to-need-a-second-padding-block")
        ));
    }

    /// A record with `len` 0 carries no name at all: it is about the watched
    /// directory itself, and `IN_Q_OVERFLOW` arrives this way too. Reading a
    /// name out of it means reading the next record's header as a filename.
    #[test]
    fn a_record_with_no_name_is_not_the_watched_file() {
        let buffer = event(libc::IN_Q_OVERFLOW, "");
        assert_eq!(buffer.len(), HEADER);
        assert!(!names_the_file(&buffer, &watched("resolv.conf")));

        // And it does not derail the walk: the record after it still counts.
        let mut queue = buffer.clone();
        queue.extend(event(libc::IN_MOVED_TO, "resolv.conf"));
        assert!(names_the_file(&queue, &watched("resolv.conf")));
    }

    /// The name is NUL-padded, so the bytes `len` describes are longer than the
    /// name. Comparing all of them means never matching anything.
    #[test]
    fn the_nul_padding_is_not_part_of_the_name() {
        let buffer = event(libc::IN_MOVED_TO, "resolv.conf");
        assert!(
            buffer.len() > HEADER + "resolv.conf".len(),
            "the fixture must actually be padded, or this test proves nothing"
        );
        assert!(names_the_file(&buffer, &watched("resolv.conf")));
    }

    /// A prefix is not a match. `resolv.conf.bak` and `resolv.conf~` are what
    /// editors and package managers leave beside the real file, and treating
    /// either as the file itself re-applies DNS for someone else's backup.
    #[test]
    fn a_name_that_merely_starts_the_same_is_not_the_file() {
        for near in ["resolv.conf.bak", "resolv.conf~", "resolv.con"] {
            let buffer = event(libc::IN_MOVED_TO, near);
            assert!(
                !names_the_file(&buffer, &watched("resolv.conf")),
                "{near} is not resolv.conf"
            );
        }
    }

    /// A short read must not be walked past its end. The kernel does not
    /// truncate a record, but the walk indexes a slice with a length that came
    /// out of that slice, and getting it wrong is a panic in a detached thread
    /// -- which on a `panic = "abort"` build is the daemon.
    #[test]
    fn a_truncated_record_does_not_run_off_the_end() {
        let whole = event(libc::IN_MOVED_TO, "resolv.conf");
        for cut in 0..whole.len() {
            assert!(!names_the_file(&whole[..cut], &watched("resolv.conf")));
        }
    }

    /// Adding the watch must work for an unprivileged process, because a
    /// failure here is the daemon's first act on a `netconfig` or
    /// NetworkManager host, and the only consequence is a silent DNS revert
    /// later.
    ///
    /// `open_directory_watch` rather than [`watch`], and never against the real
    /// `/etc/resolv.conf`: the thread [`watch`] starts is detached and blocks in
    /// `read` until the kernel says otherwise, so a test that called it would
    /// leave a thread running for the rest of the binary -- finding 3 of
    /// `shoes-agent-prompt-daemon-review-2.md`, which the macOS route monitor's
    /// test still demonstrates. This covers the half that can fail.
    #[test]
    fn the_directory_watch_is_added_without_privilege() {
        let dir = tempfile::tempdir().unwrap();
        let fd = open_directory_watch(&dir.path().join("resolv.conf"))
            .expect("an inotify watch on a directory this process owns");
        assert!(fd >= 0);
        drop(FdGuard(fd));
    }

    /// The watch is on the *directory*, so it survives the rename that detaches
    /// an inode watch -- which is the one thing no fixture can show, because
    /// the hazard is in the kernel's behaviour rather than in ours.
    ///
    /// Two renames, and the second is the one that matters: a watch added to
    /// the file itself would report the first and then nothing ever again,
    /// silently, which is worse than no watcher because it looks like it is
    /// working. Read on this thread with a bounded `poll` rather than by
    /// starting the watcher's thread, for the reason above.
    #[test]
    fn a_rename_over_the_file_is_still_seen_the_second_time() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resolv.conf");
        fs::write(&path, "nameserver 192.168.1.1\n").unwrap();

        let fd = open_directory_watch(&path).expect("an inotify watch");
        let _guard = FdGuard(fd);

        for round in 0..2 {
            let temporary = dir.path().join(".resolv.conf.manager");
            fs::write(&temporary, "nameserver 10.0.0.1\n").unwrap();
            fs::rename(&temporary, &path).unwrap();

            assert!(
                read_within(fd, &watched("resolv.conf")),
                "round {round}: the rename must be reported"
            );
        }
    }

    /// Read whatever inotify has, for at most a moment, and say whether it
    /// names the file. Bounded so a failure is a failure rather than a hung
    /// suite; a working watch answers in microseconds.
    fn read_within(fd: RawFd, name: &OsStr) -> bool {
        let mut waiting = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one initialised `pollfd` is described to `poll`, and `fd` is
        // open for the duration of the call.
        let ready = unsafe { libc::poll(std::ptr::addr_of_mut!(waiting), 1, 2000) };
        if ready <= 0 {
            return false;
        }

        let mut buffer = [0u8; 4096];
        // SAFETY: `buffer` is valid for its own length for the duration of the
        // call, and `fd` is open.
        let read =
            unsafe { libc::read(fd, buffer.as_mut_ptr() as *mut libc::c_void, buffer.len()) };
        if read <= 0 {
            return false;
        }
        names_the_file(&buffer[..read as usize], name)
    }

    /// The loop this watcher would otherwise be.
    ///
    /// Re-applying DNS on the direct backend *is* a rename over the watched
    /// path, so the handler's work is indistinguishable from the event it
    /// answers. Reporting unconditionally means: manager writes, we re-apply,
    /// our re-apply wakes us, we re-apply again -- three writes a second to
    /// `/etc/resolv.conf` for the life of the process, with nothing in any log
    /// saying so.
    ///
    /// Reintroduce the defect by having the thread call `on_change` without
    /// consulting this, and this is the test that reddens.
    #[test]
    fn our_own_re_apply_is_not_reported_as_another_change() {
        let host = Some(b"nameserver 192.168.1.1\n".to_vec());
        let ours = Some(b"nameserver 10.0.0.1\n".to_vec());

        // The session is running, so the file holds the tunnel's resolvers.
        let mut reported = ours.clone();

        // NetworkManager reconnects and puts the host's back: the leak, and
        // the thing this watcher exists to answer.
        assert!(changed_since_last_report(&mut reported, host));
        // The re-apply that answers it really did change the file, so it is
        // reported once more -- and the supervisor's handler is idempotent.
        assert!(changed_since_last_report(&mut reported, ours.clone()));
        // This is where the loop would start: the same bytes, again, because
        // the write that produced them was our own.
        assert!(!changed_since_last_report(&mut reported, ours.clone()));
        assert!(!changed_since_last_report(&mut reported, ours));

        // A manager taking the file away is a change, and taking it away twice
        // is not two.
        assert!(changed_since_last_report(&mut reported, None));
        assert!(!changed_since_last_report(&mut reported, None));
    }

    /// `Interrupted` and `WouldBlock` only. inotify has no `ENOBUFS` twin --
    /// its overrun arrives as an `IN_Q_OVERFLOW` event rather than an errno --
    /// so anything else from `read` on an inotify descriptor is the descriptor
    /// being gone, which is not something to spin on.
    #[test]
    fn only_an_interrupted_read_is_carried_on_from() {
        assert!(recoverable(&std::io::Error::from(
            std::io::ErrorKind::Interrupted
        )));
        assert!(recoverable(&std::io::Error::from(
            std::io::ErrorKind::WouldBlock
        )));

        assert!(!recoverable(&std::io::Error::from_raw_os_error(
            libc::EBADF
        )));
        assert!(!recoverable(&std::io::Error::from_raw_os_error(
            libc::EINVAL
        )));
    }
}
