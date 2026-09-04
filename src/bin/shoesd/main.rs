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

mod auth;
mod service;
mod socket;

use std::process::ExitCode;

/// Where the control socket lives. Root-owned, `0660`, group from `--group`.
const DEFAULT_SOCKET_PATH: &str = "/var/run/shoesd.sock";

/// The group whose members may talk to the daemon. Admins by default: on
/// macOS that is the set of users who could install the daemon in the first
/// place, so it grants nothing that was not already available.
const DEFAULT_GROUP: &str = "admin";

fn usage() -> String {
    format!(
        "shoesd {}\n\
         \n\
         USAGE:\n    \
             shoesd run [--socket <path>] [--group <name>]\n\
         \n\
         OPTIONS:\n    \
             --socket <path>  Control socket path (default: {DEFAULT_SOCKET_PATH})\n    \
             --group <name>   Group allowed to connect (default: {DEFAULT_GROUP})\n    \
             -V, --version    Print version and exit\n",
        env!("CARGO_PKG_VERSION"),
    )
}

/// What `run` was asked for.
#[derive(Debug)]
struct RunArgs {
    socket_path: std::path::PathBuf,
    group: String,
}

fn parse_run_args(args: &[String]) -> Result<RunArgs, String> {
    let mut socket_path = std::path::PathBuf::from(DEFAULT_SOCKET_PATH);
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
            "--group" => {
                group = rest
                    .next()
                    .ok_or_else(|| "--group needs a name".to_string())?
                    .clone();
            }
            other => return Err(format!("unexpected argument {other:?}")),
        }
    }

    Ok(RunArgs { socket_path, group })
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

    match runtime.block_on(service::serve(&args.socket_path, &args.group)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("shoesd: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_takes_the_documented_defaults() {
        let args = parse_run_args(&[]).expect("no arguments is the launchd shape");
        assert_eq!(args.socket_path, std::path::Path::new(DEFAULT_SOCKET_PATH));
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
