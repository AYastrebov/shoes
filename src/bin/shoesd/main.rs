//! `shoesd` -- the privileged desktop daemon.
//!
//! A root launchd daemon that hosts `shoes::control` in-process and serves a
//! desktop GUI over gRPC on a Unix domain socket. It creates the device,
//! installs routes and DNS, reverts them on stop, and reports status,
//! statistics and logs as data rather than as a log to grep.
//!
//! Design: `docs/specs/2026-09-04-macos-privileged-daemon.md`.
//!
//! This binary links the library crate rather than re-declaring the module
//! tree the way `src/main.rs` does, so what it can reach is exactly what
//! `shoes` exports.

// The daemon's dependencies live under target sections, so building it on a
// platform with no arm fails with a pile of unresolved crates. Say why instead.
//
// Not a placeholder for a port: the protocol and the daemon's structure leave
// room for Windows -- `capabilities` is reported rather than inferred precisely
// so a client can ask -- but routes and DNS there are their own design.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
compile_error!(
    "the `daemon` feature builds shoesd, which is macOS and Linux only: its \
     host network configuration (routes, DNS) has no arm for this platform \
     yet. Build without `--features daemon`."
);

mod auth;
mod host;
mod install;
mod service;
mod socket;
mod supervisor;

use std::process::ExitCode;

/// Where the control socket lives. Root-owned, `0660`, group from `--group`.
///
/// In its own directory, which `bind` creates `0750` root:group. That is what
/// closes the instant between the socket being created and its mode being set
/// -- reaching a socket needs search permission on every directory above it.
const DEFAULT_SOCKET_PATH: &str = "/var/run/shoesd/shoesd.sock";

/// Where the revert record lives. Root-only; see `host::AppliedState`.
const DEFAULT_STATE_PATH: &str = "/var/db/shoesd/applied.json";

/// Log lines retained for a client that attaches after the interesting part.
/// A GUI started after a failed tunnel still needs to see why it failed.
const LOG_BACKLOG: usize = 512;

/// The group whose members may talk to the daemon.
///
/// The set of users who could have installed the daemon in the first place, so
/// it grants nothing that was not already available -- but the *name* of that
/// set is not portable. macOS has `admin`; Linux has `wheel` on Fedora, Arch
/// and openSUSE and `sudo` on Debian and Ubuntu, which is why `install` detects
/// it there rather than trusting this constant. See `install::resolve_group`.
///
/// This is the default for `run`, which only needs a name to resolve. `install`
/// never sees it: it takes `RunArgs::group` as the `Option` it is, so that
/// "the operator named a group" stays distinguishable from "the operator named
/// nothing".
#[cfg(target_os = "macos")]
const DEFAULT_GROUP: &str = "admin";
#[cfg(not(target_os = "macos"))]
const DEFAULT_GROUP: &str = "wheel";

fn usage() -> String {
    format!(
        "shoesd {}\n\
         \n\
         USAGE:\n    \
             shoesd run [--socket <path>] [--state <path>] [--group <name>]\n    \
             shoesd install [--socket <path>] [--state <path>] [--group <name>]\n    \
             shoesd uninstall\n\
         \n\
         OPTIONS:\n    \
             --socket <path>  Control socket path (default: {DEFAULT_SOCKET_PATH})\n    \
             --state <path>   Revert record (default: {DEFAULT_STATE_PATH})\n    \
             --group <name>   Group allowed to connect\n                     \
                              (run: default {DEFAULT_GROUP}; install: detected\n                     \
                              from wheel/sudo/adm unless given)\n    \
             -V, --version    Print version and exit\n",
        env!("CARGO_PKG_VERSION"),
    )
}

/// What `run` was asked for.
#[derive(Debug)]
struct RunArgs {
    socket_path: std::path::PathBuf,
    state_path: std::path::PathBuf,
    /// `None` when `--group` was not given.
    ///
    /// Deliberately not defaulted here. `install` has to tell "the operator
    /// named a group" from "the operator named nothing", because on Linux the
    /// second is what turns on detection -- and if this substituted the default
    /// first, an explicit `--group wheel` would be indistinguishable from no
    /// flag at all, so the one value a Fedora administrator is most likely to
    /// type would be the one silently re-derived.
    group: Option<String>,
}

fn parse_run_args(args: &[String]) -> Result<RunArgs, String> {
    let mut socket_path = std::path::PathBuf::from(DEFAULT_SOCKET_PATH);
    let mut state_path = std::path::PathBuf::from(DEFAULT_STATE_PATH);
    let mut group: Option<String> = None;

    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--socket" => {
                socket_path = rest
                    .next()
                    .ok_or_else(|| "--socket needs a path".to_string())?
                    .into();
            }
            "--state" => {
                state_path = rest
                    .next()
                    .ok_or_else(|| "--state needs a path".to_string())?
                    .into();
            }
            "--group" => {
                group = Some(
                    rest.next()
                        .ok_or_else(|| "--group needs a name".to_string())?
                        .clone(),
                );
            }
            other => return Err(format!("unexpected argument {other:?}")),
        }
    }

    Ok(RunArgs {
        socket_path,
        state_path,
        group,
    })
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    match args.first().map(String::as_str) {
        Some("run") => match parse_run_args(&args[1..]) {
            Ok(run) => run_daemon(run),
            Err(e) => {
                eprintln!("shoesd: {e}\n\n{}", usage());
                ExitCode::FAILURE
            }
        },
        // `install` takes the same arguments as `run`, because they are what
        // it writes into the plist -- the job launchd starts must be the one
        // the operator asked for.
        Some("install") => match parse_run_args(&args[1..]) {
            Ok(run) => report(
                &format!(
                    "installed {} and bootstrapped {}",
                    install::INSTALLED_BINARY,
                    install::LABEL
                ),
                install::install(&run.socket_path, &run.state_path, run.group.as_deref()),
            ),
            Err(e) => {
                eprintln!("shoesd: {e}\n\n{}", usage());
                ExitCode::FAILURE
            }
        },
        Some("uninstall") => report(
            &format!("removed {} and its job", install::INSTALLED_BINARY),
            install::uninstall(),
        ),
        Some("-V" | "--version") => {
            println!("shoesd {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        _ => {
            eprint!("{}", usage());
            ExitCode::FAILURE
        }
    }
}

fn report(what: &str, result: std::io::Result<()>) -> ExitCode {
    match result {
        // Said out loud. Only `run` installs a logger, so the `log::info!`
        // lines inside install/uninstall reach nothing, and a command that
        // printed only on failure would exit 0 in silence -- which reads as
        // "nothing happened" for the two subcommands a person runs by hand and
        // watches.
        Ok(()) => {
            println!("shoesd: {what}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("shoesd: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run_daemon(args: RunArgs) -> ExitCode {
    // The daemon's own runtime. It never owns a `ServiceHandle`: stopping one
    // sleeps its caller for up to STOP_TIMEOUT and may drop a runtime inline,
    // which is the last thing that may happen on a gRPC worker. The engine
    // gets its own runtime, owned by the supervisor thread.
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("shoesd: could not start a runtime: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Installed before anything else logs, so a client that attaches later
    // still sees why a start failed. The ring is bounded, which is what makes
    // its memory a number chosen here rather than a leak.
    let logs = std::sync::Arc::new(shoes::control::logs::BroadcastLogWriter::new(LOG_BACKLOG));
    shoes::logging::init_multi_logger(
        vec![
            Box::new(shoes::logging::StderrWriter),
            Box::new(SharedLogWriter(logs.clone())),
        ],
        vec![shoes::logging::Directive {
            name: None,
            level: log::LevelFilter::Info,
        }],
    );

    // Probed before the supervisor, because its answer decides both what the
    // supervisor is handed and what every client is told.
    let setup = HostSetup::probe();
    let host_capabilities = setup.capabilities();
    let watched_file = setup.watched_file();

    let (supervisor, supervisor_thread) =
        match supervisor::Supervisor::spawn(setup.into_factory(), args.state_path.clone()) {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!("shoesd: could not start the supervisor: {e}");
                return ExitCode::FAILURE;
            }
        };

    // The routing table is watched for the life of the process, not the
    // session: a change that lands between sessions is answered by the next
    // start reading the table anyway, and one thread is simpler to reason
    // about than one that comes and goes with the tunnel. Its failure is not
    // fatal -- the session still carries traffic, it just stops re-pointing
    // its exclusions when the gateway moves.
    {
        let supervisor = supervisor.clone();
        if let Err(e) = monitor_spawn(move || supervisor.network_changed()) {
            log::error!(
                "could not watch the routing table ({e}); exclusions will not follow a gateway change"
            );
        }
    }

    // And the DNS file, when the chosen backend manages one. `None` under
    // systemd-resolved, whose per-link configuration has no other writer, and
    // `None` on macOS -- so the `if let` is the whole platform branch and no
    // `cfg` is needed here.
    //
    // The file the direct backend owns is contended in a way that link is not:
    // NetworkManager rewrites it on every reconnect and openSUSE's `netconfig`
    // on its own schedule, and either one reverts the session's resolvers to
    // the host's while the tunnel stays up and this daemon still reports
    // RUNNING. Its failure is not fatal, on the route monitor's precedent: the
    // session still carries traffic, it just stops re-applying DNS if something
    // else rewrites the file.
    if let Some(file) = watched_file {
        let supervisor = supervisor.clone();
        if let Err(e) = watch_dns_file(&file, move || supervisor.network_changed()) {
            log::error!(
                "could not watch {} ({e}); DNS will not be re-applied if something else \
                 rewrites it mid-session",
                file.display()
            );
        }
    }

    // `run` takes the default when nothing was asked for: by then the group is
    // just a name to resolve, and the unit `install` wrote always passes one
    // explicitly.
    let group = args
        .group
        .clone()
        .unwrap_or_else(|| DEFAULT_GROUP.to_string());

    let result = runtime.block_on(service::serve(
        &args.socket_path,
        &group,
        supervisor.clone(),
        logs,
        host_capabilities,
    ));

    // Unconditionally, and before the join: `serve` can fail during setup --
    // an unknown group, a socket it cannot bind -- and the supervisor thread
    // holds a clone of its own command sender, so this is the only thing that
    // ends it. Without it a failed start would hang here forever, having
    // printed nothing, and launchd would see a live process rather than a job
    // to restart.
    supervisor.shutdown();

    // The supervisor reverts the session on its way out, and the process must
    // not exit before it has: routes into an interface this process owns
    // outlive the process itself.
    let _ = supervisor_thread.join();

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("shoesd: {e}");
            ExitCode::FAILURE
        }
    }
}

/// What this platform needs decided before the supervisor starts.
///
/// Probed once, here, rather than inside the host factory -- because on Linux
/// the answer is wanted in three places: the host itself, the `capabilities`
/// every client is told, and whether the direct DNS backend's file needs
/// watching. Probing three times could give three answers, and a session whose
/// `Hello` names one backend while its revert path uses another is a bug with
/// no symptom until the revert.
///
/// The macOS arm carries nothing, which is why this is a struct per platform
/// rather than a shared one with an `Option` in it.
#[cfg(target_os = "linux")]
struct HostSetup {
    dns: crate::host::linux::dns::Dns,
}

#[cfg(target_os = "linux")]
impl HostSetup {
    fn probe() -> Self {
        Self {
            dns: crate::host::linux::dns::Dns::probe(),
        }
    }

    /// The `dns-backend:` line. No client branches on it; it is for whoever
    /// reads the bug report, and it is the first question a Linux DNS problem
    /// needs answered.
    fn capabilities(&self) -> Vec<String> {
        vec![format!("dns-backend:{}", self.dns.backend_name())]
    }

    /// The file the direct backend manages, when that is the chosen one.
    ///
    /// `None` under systemd-resolved: nothing else on the host touches the
    /// tunnel link's own configuration, so there is nothing to contend with.
    fn watched_file(&self) -> Option<std::path::PathBuf> {
        self.dns.watched_file().map(std::path::Path::to_path_buf)
    }

    /// The factory the supervisor runs on its own thread.
    ///
    /// A factory rather than a built host because the macOS twin owns an
    /// `SCDynamicStore`, which is not `Send`; the Linux one would move fine and
    /// keeps the same shape so `run_daemon` stays free of platform branches.
    fn into_factory(
        self,
    ) -> impl FnOnce() -> std::io::Result<crate::host::linux::LinuxHost> + Send + 'static {
        move || crate::host::linux::LinuxHost::with_dns(self.dns)
    }
}

#[cfg(target_os = "macos")]
struct HostSetup;

#[cfg(target_os = "macos")]
impl HostSetup {
    fn probe() -> Self {
        Self
    }

    /// Nothing beyond what the build already says: the one DNS mechanism macOS
    /// has is the one this daemon uses.
    fn capabilities(&self) -> Vec<String> {
        Vec::new()
    }

    /// `SCDynamicStore` is not a file, and the route monitor's second look
    /// already covers the system putting resolvers back on its own schedule.
    fn watched_file(&self) -> Option<std::path::PathBuf> {
        None
    }

    fn into_factory(
        self,
    ) -> impl FnOnce() -> std::io::Result<crate::host::macos::MacosHost> + Send + 'static {
        crate::host::macos::MacosHost::new
    }
}

#[cfg(target_os = "macos")]
fn monitor_spawn(on_change: impl Fn() + Send + 'static) -> std::io::Result<()> {
    crate::host::macos::monitor::spawn(on_change)
}

#[cfg(target_os = "linux")]
fn monitor_spawn(on_change: impl Fn() + Send + 'static) -> std::io::Result<()> {
    crate::host::linux::monitor::spawn(on_change)
}

#[cfg(target_os = "linux")]
fn watch_dns_file(
    path: &std::path::Path,
    on_change: impl Fn() + Send + 'static,
) -> std::io::Result<()> {
    crate::host::linux::dns::watch(path, on_change)
}

/// Unreachable, and an error rather than a silent `Ok`.
///
/// `HostSetup::watched_file` answers `None` on macOS -- DNS there lives in the
/// `SCDynamicStore`, which is not a file -- so nothing calls this. It exists so
/// the call site needs no `cfg` of its own, and it says so out loud rather than
/// reporting a watch that was never installed.
#[cfg(target_os = "macos")]
fn watch_dns_file(
    path: &std::path::Path,
    _on_change: impl Fn() + Send + 'static,
) -> std::io::Result<()> {
    Err(std::io::Error::other(format!(
        "{} is not a file this platform's DNS lives in",
        path.display()
    )))
}

/// A `LogWriter` the daemon can keep a handle on.
///
/// `init_multi_logger` takes ownership of its writers, and `WatchLogs` needs
/// to subscribe to this one afterwards.
struct SharedLogWriter(std::sync::Arc<shoes::control::logs::BroadcastLogWriter>);

impl shoes::logging::LogWriter for SharedLogWriter {
    fn write_log(&self, record: &log::Record, formatted: &str) {
        self.0.write_log(record, formatted);
    }

    fn flush(&self) {
        self.0.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_takes_the_documented_defaults() {
        let args = parse_run_args(&[]).expect("no arguments is the launchd shape");
        assert_eq!(args.socket_path, std::path::Path::new(DEFAULT_SOCKET_PATH));
        assert_eq!(args.state_path, std::path::Path::new(DEFAULT_STATE_PATH));
        // Not the default: *absent*. `install` needs to tell the two apart,
        // and substituting here is exactly what would stop it.
        assert_eq!(args.group, None);
    }

    #[test]
    fn run_takes_an_explicit_socket_and_group() {
        let args = parse_run_args(&[
            "--socket".into(),
            "/tmp/x.sock".into(),
            "--group".into(),
            "staff".into(),
        ])
        .expect("both flags are supported");
        assert_eq!(args.socket_path, std::path::Path::new("/tmp/x.sock"));
        assert_eq!(args.group.as_deref(), Some("staff"));
    }

    /// A flag whose value is missing must not silently take the default: the
    /// socket path decides who can reach a root daemon.
    #[test]
    fn a_flag_without_a_value_is_refused() {
        parse_run_args(&["--socket".into()]).expect_err("--socket needs a path");
        parse_run_args(&["--group".into()]).expect_err("--group needs a name");
    }

    #[test]
    fn an_unknown_argument_is_refused() {
        let err = parse_run_args(&["--sokcet".into(), "/tmp/x".into()])
            .expect_err("a typo must not be ignored");
        assert!(err.contains("--sokcet"), "the message names it: {err}");
    }
}
