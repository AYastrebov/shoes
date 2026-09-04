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

// The daemon's dependencies live under a macOS target section, so building it
// anywhere else fails with a pile of unresolved crates. Say why instead.
//
// Not a placeholder for a port: the protocol and the daemon's structure leave
// room for Linux and Windows -- `capabilities` is reported rather than
// inferred precisely so a client can ask -- but routes and DNS on those
// platforms are their own design, and Linux alone has four mechanisms
// (systemd-resolved, resolvconf, NetworkManager, a bare /etc/resolv.conf).
#[cfg(not(target_os = "macos"))]
compile_error!(
    "the `daemon` feature builds shoesd, which is macOS-only in v1: its host \
     network configuration (routes, DNS) has no arm for this platform yet. \
     Build without `--features daemon`."
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

/// The group whose members may talk to the daemon. Admins by default: on
/// macOS that is the set of users who could install the daemon in the first
/// place, so it grants nothing that was not already available.
const DEFAULT_GROUP: &str = "admin";

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
             --group <name>   Group allowed to connect (default: {DEFAULT_GROUP})\n    \
             -V, --version    Print version and exit\n",
        env!("CARGO_PKG_VERSION"),
    )
}

/// What `run` was asked for.
#[derive(Debug)]
struct RunArgs {
    socket_path: std::path::PathBuf,
    state_path: std::path::PathBuf,
    group: String,
}

fn parse_run_args(args: &[String]) -> Result<RunArgs, String> {
    let mut socket_path = std::path::PathBuf::from(DEFAULT_SOCKET_PATH);
    let mut state_path = std::path::PathBuf::from(DEFAULT_STATE_PATH);
    let mut group = DEFAULT_GROUP.to_string();

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
                group = rest
                    .next()
                    .ok_or_else(|| "--group needs a name".to_string())?
                    .clone();
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
                install::install(&run.socket_path, &run.state_path, &run.group),
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

    let (supervisor, supervisor_thread) = match supervisor::Supervisor::spawn(
        crate::host::macos::MacosHost::new,
        args.state_path.clone(),
    ) {
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
        if let Err(e) = crate::host::macos::monitor::spawn(move || supervisor.network_changed()) {
            log::error!(
                "could not watch the routing table ({e}); exclusions will not follow a gateway change"
            );
        }
    }

    let result = runtime.block_on(service::serve(
        &args.socket_path,
        &args.group,
        supervisor.clone(),
        logs,
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
        assert_eq!(args.group, DEFAULT_GROUP);
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
        assert_eq!(args.group, "staff");
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
