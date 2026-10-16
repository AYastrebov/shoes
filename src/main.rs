mod address;
mod amneziawg;
mod anytls;
mod async_stream;
mod buf_reader;
mod buffer_sizing;
mod client_proxy_chain;
mod client_proxy_selector;
mod config;
mod copy_bidirectional;
mod copy_bidirectional_message;
mod crypto;
mod dns;
// The tunnel reports into this module in both builds, but only the
// library's control layer subscribes -- the standalone server must not
// die because one outbound lost a socket. So the subscribing half has no
// caller in this binary, which is a property of the build.
#[allow(dead_code)]
mod fatal;
mod h2mux;
mod http_handler;
mod http_parse;
mod httpupgrade;
mod hysteria2;
mod logging;
mod memory;
mod mieru;
mod mixed_handler;
mod naiveproxy;
mod option_util;
#[cfg(feature = "control-stats")]
mod outbound_counting_stream;
mod outbound_stats;
mod port_forward_handler;
mod prepend_stream;
mod quic_outbound;
mod quic_server;
mod quic_stream;
mod quic_transport;
mod reality;
mod reality_client_handler;
mod redirect_handler;
mod resolver;
mod routing;
mod rule_set;
mod rustls_config_util;
mod rustls_connection_util;
mod shadow_tls;
mod shadowsocks;
mod slide_buffer;
mod snell;
mod sniff;
// Consulting a protector happens on every outbound socket; installing one is
// the FFI's job, and the FFI is compiled out of this binary. So the installer
// half of this module has no caller here and never will, which is a property of
// the build rather than something a later change will fix.
#[allow(dead_code)]
mod socket_protector;
mod socket_util;
mod socks5_udp_relay;
mod socks_handler;
#[cfg(target_os = "linux")]
mod splice;
mod stream_reader;
mod sync_adapter;
mod tcp;
mod thread_util;
mod tls_client_handler;
mod tls_server_handler;
mod tproxy;
mod trojan_handler;
mod tuic;
#[cfg(any(unix, windows))]
mod tun;
mod udp_route_cache;
mod uot;
mod util;
mod uuid_util;
mod vless;
mod vmess;
mod websocket;
mod xudp;

#[cfg(not(any(
    target_env = "msvc",
    target_os = "ios",
    target_os = "android",
    target_arch = "mips"
)))]
use tikv_jemallocator::Jemalloc;

// Not on MIPS: see the dependency's note in Cargo.toml.
#[cfg(not(any(
    target_env = "msvc",
    target_os = "ios",
    target_os = "android",
    target_arch = "mips"
)))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

use std::path::Path;

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use base64::engine::{Engine as _, general_purpose::STANDARD};
use log::debug;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tcp_server::start_servers;
use tokio::runtime::Builder;
use tokio::sync::mpsc::{UnboundedReceiver, unbounded_channel};

use crate::reality::generate_keypair;
use crate::shadowsocks::ShadowsocksCipher;
use crate::thread_util::set_num_threads;
use tcp::*;

#[derive(Debug)]
struct ConfigChanged;

/// Watch `paths` for edits. Built after the first configuration has loaded,
/// so every path is one that was just read: a missing file is reported by
/// the load, with the usage text, rather than here.
fn start_notify_thread<'a>(
    paths: impl IntoIterator<Item = &'a str>,
) -> notify::Result<(RecommendedWatcher, UnboundedReceiver<ConfigChanged>)> {
    let (tx, rx) = unbounded_channel();

    let mut watcher = notify::recommended_watcher(move |res: notify::Result<Event>| match res {
        Ok(event) => {
            // The receiver goes only with the serve loop, at exit.
            if matches!(event.kind, EventKind::Modify(..)) {
                let _ = tx.send(ConfigChanged {});
            }
        }
        Err(e) => println!("watch error: {e:?}"),
    })?;

    for path in paths {
        watcher.watch(Path::new(path), RecursiveMode::NonRecursive)?;
    }

    Ok((watcher, rx))
}

/// Add the rule-set files referenced by these configs to the watch set.
///
/// A failure is reported rather than fatal: the file was readable moments ago
/// during validation, and losing the watch is not a reason to refuse to serve.
fn watch_rule_set_paths(watcher: &mut RecommendedWatcher, configs: &[config::Config]) {
    for config in configs {
        if let config::Config::RuleSet(rule_set) = config
            && let Err(e) = watcher.watch(Path::new(&rule_set.path), RecursiveMode::NonRecursive)
        {
            println!("Could not watch rule-set {}: {e}", rule_set.path);
        }
    }
}

fn print_usage_and_exit(arg0: &str) {
    eprintln!("{arg0} [OPTIONS] <config.yaml> [config.yaml...]");
    eprintln!();
    eprintln!("OPTIONS:");
    eprintln!("    -t, --threads NUM    Set the number of worker threads (default: CPU count)");
    eprintln!(
        "    -l, --log-file PATH  Log to file (repeatable; \"-\" means stderr; default: stderr)"
    );
    eprintln!("    -d, --dry-run        Parse the config and exit");
    eprintln!("    --no-reload          Disable automatic config reloading on file changes");
    eprintln!("    -V, --version        Print version information and exit");
    eprintln!();
    eprintln!("COMMANDS:");
    eprintln!(
        "    generate-reality-keypair                       Generate a new Reality X25519 keypair"
    );
    eprintln!("    generate-shadowsocks-2022-password <cipher>    Generate a Shadowsocks password");
    eprintln!(
        "    generate-vless-user-id                         Generate a random VLESS/VMESS user ID (UUID v4)"
    );
    eprintln!(
        "    check <config.yaml> [config.yaml...]           Parse the config and exit (same as --dry-run)"
    );
    eprintln!(
        "    version                                        Print version information and exit"
    );
    std::process::exit(1);
}

fn main() {
    // Ignore SIGHUP from the first instruction until the runtime installs
    // the real handler below. Before that there is nothing to reload, and
    // the OS default for the signal is death -- so an operator's reload sent
    // to a process still parsing its arguments killed it. Dropped rather
    // than buffered for these few milliseconds, which is the right
    // direction: a reload of nothing is nothing.
    #[cfg(unix)]
    // SAFETY: setting a disposition before any thread exists.
    unsafe {
        libc::signal(libc::SIGHUP, libc::SIG_IGN);
    }

    let mut args: Vec<String> = std::env::args().collect();
    let arg0 = args.remove(0);
    let mut num_threads = 0usize;
    let mut dry_run = false;
    let mut no_reload = false;
    let mut log_files: Vec<String> = Vec::new();

    while !args.is_empty() && args[0].starts_with("-") {
        if args[0] == "--threads" || args[0] == "-t" {
            args.remove(0);
            if args.is_empty() {
                eprintln!("Missing threads argument.");
                print_usage_and_exit(&arg0);
                return;
            }
            num_threads = match args.remove(0).parse::<usize>() {
                Ok(n) => n,
                Err(e) => {
                    eprintln!("Invalid thread count: {e}");
                    print_usage_and_exit(&arg0);
                    return;
                }
            };
        } else if args[0] == "--log-file" || args[0] == "-l" {
            args.remove(0);
            if args.is_empty() {
                eprintln!("Missing log-file argument.");
                print_usage_and_exit(&arg0);
                return;
            }
            log_files.push(args.remove(0));
        } else if args[0] == "--dry-run" || args[0] == "-d" {
            args.remove(0);
            dry_run = true;
        } else if args[0] == "--no-reload" {
            args.remove(0);
            no_reload = true;
        } else if args[0] == "--version" || args[0] == "-V" {
            println!("shoes {}", env!("CARGO_PKG_VERSION"));
            return;
        } else {
            eprintln!("Invalid argument: {}", args[0]);
            print_usage_and_exit(&arg0);
            return;
        }
    }

    // Subcommands an operator such as awg-manager already calls by these
    // names: `check <config>` is `--dry-run`, `version` is `--version`.
    // See docs/specs/2026-09-11-awg-manager-engine.md, "Slice 1".
    if args.first().map(String::as_str) == Some("version") {
        println!("shoes {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    if args.first().map(String::as_str) == Some("check") {
        args.remove(0);
        dry_run = true;
    }

    let directives = logging::resolve_directives();
    let mut writers: Vec<Box<dyn logging::LogWriter>> = Vec::new();

    if log_files.is_empty() || log_files.iter().any(|p| p == "-") {
        writers.push(Box::new(logging::StderrWriter));
    }
    for path in &log_files {
        if path == "-" {
            continue;
        }
        match logging::FileLogWriter::new(path) {
            Ok(w) => writers.push(Box::new(w)),
            Err(e) => {
                eprintln!("Failed to open log file {path}: {e}");
                std::process::exit(1);
            }
        }
    }

    logging::init_multi_logger(writers, directives);
    logging::install_panic_hook();

    if args.iter().any(|s| s == "generate-reality-keypair") {
        let (private_key, public_key) = generate_keypair().unwrap_or_else(|e| {
            eprintln!("Could not generate a keypair: {e}");
            std::process::exit(1);
        });
        println!(
            "--------------------------------------------------------------------------------"
        );
        println!("REALITY private key: {}", private_key);
        println!("REALITY public key: {}", public_key);
        println!(
            "--------------------------------------------------------------------------------"
        );
        return;
    }

    if let Some(pos) = args
        .iter()
        .position(|s| s == "generate-shadowsocks-2022-password")
    {
        let cipher = args.get(pos + 1).map(|s| s.as_str());
        match cipher {
            Some(c) => {
                // Strip 2022-blake3- prefix if present for cipher lookup
                let base_cipher = match c.strip_prefix("2022-blake3-") {
                    Some(b) => b,
                    None => {
                        eprintln!(
                            "Password generation is only necessary for shadowsocks 2022 ciphers."
                        );
                        std::process::exit(1);
                    }
                };
                match ShadowsocksCipher::try_from(base_cipher) {
                    Ok(cipher) => {
                        let rng = SystemRandom::new();
                        let mut key_bytes = vec![0u8; cipher.key_len()];
                        if rng.fill(&mut key_bytes).is_err() {
                            eprintln!("The system random number generator failed.");
                            std::process::exit(1);
                        }
                        let password = STANDARD.encode(&key_bytes);
                        println!(
                            "--------------------------------------------------------------------------------"
                        );
                        println!("Cipher: {}", c);
                        println!("Password: {}", password);
                        println!(
                            "--------------------------------------------------------------------------------"
                        );
                    }
                    Err(_) => {
                        eprintln!("Unknown cipher: {}", c);
                        eprintln!("Supported shadowsocks 2022 ciphers:");
                        eprintln!("  2022-blake3-aes-128-gcm");
                        eprintln!("  2022-blake3-aes-256-gcm");
                        eprintln!("  2022-blake3-chacha20-poly1305");
                        std::process::exit(1);
                    }
                }
            }
            None => {
                eprintln!(
                    "Usage: {} generate-shadowsocks-2022-password <cipher>",
                    arg0
                );
                eprintln!("Supported shadowsocks 2022 ciphers:");
                eprintln!("  2022-blake3-aes-128-gcm");
                eprintln!("  2022-blake3-aes-256-gcm");
                eprintln!("  2022-blake3-chacha20-poly1305");
                std::process::exit(1);
            }
        }
        return;
    }

    if args.iter().any(|s| s == "generate-vless-user-id") {
        let uuid = uuid_util::generate_uuid();
        println!(
            "--------------------------------------------------------------------------------"
        );
        println!("VLESS/VMESS User ID: {}", uuid);
        println!(
            "--------------------------------------------------------------------------------"
        );
        return;
    }

    if args.is_empty() {
        println!("No config specified, assuming loading from file config.shoes.yaml");
        args.push("config.shoes.yaml".to_string())
    }

    if dry_run {
        println!("Starting dry run.");
    }

    if num_threads == 0 {
        num_threads = thread_util::get_num_threads();
        debug!("Runtime threads: {num_threads}");
    } else {
        println!("Using custom thread count ({num_threads})");
    }

    // Used by QUIC to figure out the number of endpoints.
    // TODO: can we pass it in instead?
    set_num_threads(num_threads);

    let mut builder = if num_threads == 1 {
        Builder::new_current_thread()
    } else {
        let mut mt = Builder::new_multi_thread();
        mt.worker_threads(num_threads);
        mt
    };

    let runtime = match builder.enable_io().enable_time().build() {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("Could not build the tokio runtime: {e}");
            std::process::exit(1);
        }
    };

    runtime.block_on(async move {
        // No watcher yet: it is built once the first configuration has
        // loaded, below, and never for a validation-only run, which has
        // nothing to reload.
        let mut reload_state: Option<(RecommendedWatcher, UnboundedReceiver<ConfigChanged>)> = None;

        if dry_run {
            // Validation only -- no DNS registry, whose bootstrap resolution
            // would make an offline dry run fail for a valid config.
            let checked = async {
                let configs = config::load_configs(&args)
                    .await
                    .map_err(|e| format!("Failed to load server configs: {e}"))?;
                let (configs, _) = config::convert_cert_paths(configs)
                    .await
                    .map_err(|e| format!("Failed to load cert files: {e}"))?;
                config::create_server_configs(configs)
                    .map_err(|e| format!("Failed to create server configs: {e}"))?;
                Ok::<(), String>(())
            }
            .await;
            match checked {
                Ok(()) => println!("Finishing dry run, config parsed successfully."),
                Err(e) => {
                    eprintln!("Dry run failed: {e}\n");
                    // A non-zero exit is the whole point of a dry run:
                    // tooling validates configs by status, not by prose.
                    std::process::exit(1);
                }
            }
            return;
        }

        // Installed before the first prepare, not after it: until this is
        // installed a SIGHUP has the OS default disposition, which is death.
        // An operator that sends one during a start-up prepare -- a DNS
        // bootstrap stalled on a dead network -- gets it buffered and
        // honoured at the first wait instead. The stop signals stay where
        // they are: buffering a SIGTERM behind a stalled start-up prepare
        // would be the escalation-to-SIGKILL this loop was rewritten to
        // avoid, and there is nothing to clean up before the first launch.
        let mut reload = ReloadSignal::install();

        let mut prepared = match prepare_servers(&args, None).await {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{e}\n");
                print_usage_and_exit(&arg0);
                return;
            }
        };

        // The configs and the rule-sets they name, as just read. A watcher
        // that cannot start costs the reload-on-edit, not the servers: SIGHUP
        // still reloads.
        if !no_reload {
            match start_notify_thread(prepared.sources.paths()) {
                Ok(state) => reload_state = Some(state),
                Err(e) => eprintln!("Not watching the config files ({e}); send SIGHUP to reload."),
            }
        }

        // Registered once, before the serve loop: tokio replaces the OS
        // default disposition for the process's lifetime, so the streams
        // must outlive every wait point -- a one-shot future dropped
        // between waits would leave a window where the signal is neither
        // handled nor fatal. A signal that lands while the loop is busy
        // (the reload debounce, a prepare) is buffered by the stream and
        // handled at the next wait.
        let mut signals = ShutdownSignals::install();

        let mut first_launch = true;
        loop {
            let loaded = std::mem::take(&mut prepared.sources);
            let mut running = None;

            let join_handles = match launch_servers(prepared).await {
                Ok(handles) => {
                    running = Some(loaded);
                    handles
                }
                Err(e) if first_launch => {
                    eprintln!("{e}\n");
                    std::process::exit(1);
                }
                Err(e) => {
                    // A reload that validated but failed to launch -- a bind
                    // conflict, fd exhaustion. The old servers are already
                    // gone, so there is nothing to keep; but the process
                    // survives and the next edit retries.
                    eprintln!("{e}\nNo servers are running; fix the config to retry.");
                    Vec::new()
                }
            };
            first_launch = false;

            // Wait for a reason to reload, then keep trying until an edit
            // produces a config that loads. The running servers keep serving
            // the last-good configuration the whole time: killing a live
            // proxy over a half-saved file punishes the edit before it is
            // done.
            //
            // Two reasons, treated differently. A file change is debounced,
            // because an editor saves in pieces. A SIGHUP is not: the
            // operator that sent it has finished writing, and it arrives
            // whether or not the watcher is on -- `--no-reload` disables the
            // watcher, not the operator.
            //
            // `biased`, in this order: a stop request beats everything, and
            // when a write and a SIGHUP are both pending -- the operator's
            // usual "write, then signal" -- the signal wins, so the reload is
            // immediate rather than debounced.
            prepared = loop {
                let debounce = tokio::select! {
                    biased;
                    (what, code) = signals.recv() => shut_down(what, code, join_handles).await,
                    () = reload.recv() => false,
                    () = async {
                        match reload_state.as_mut() {
                            Some((_, rx)) => {
                                // The watcher is held beside its receiver,
                                // so the sender cannot be gone while this
                                // waits; if it ever were, stop listening.
                                if rx.recv().await.is_none() {
                                    futures::future::pending::<()>().await;
                                }
                            }
                            // No watcher: only a signal can end this wait.
                            None => futures::future::pending::<()>().await,
                        }
                    } => true,
                };

                // The debounce and the prepare stay under the signal
                // select: a SIGTERM during a reload whose DNS bootstrap
                // is stalled on a dead network used to buffer for the
                // whole stall -- long enough for systemd to escalate to
                // SIGKILL, the unflushed death this handler removes.
                let outcome = tokio::select! {
                    outcome = async {
                        if debounce {
                            println!("Configs changed, reloading in 3 seconds..");
                            // The signal cuts the debounce short. In the
                            // usual "write, then signal" the watcher's event
                            // arrives first, in milliseconds, and wins the
                            // select above; a SIGHUP that then sat behind the
                            // full debounce would be the delay it exists to
                            // skip. It is consumed here, and so cannot fire a
                            // second reload after this one.
                            let signalled = tokio::select! {
                                () = tokio::time::sleep(std::time::Duration::from_secs(3)) => false,
                                () = reload.recv() => {
                                    println!("Received SIGHUP, reloading now..");
                                    true
                                }
                            };
                            // Only the watcher's word for it, so check it:
                            // the same bytes are not an edit. A SIGHUP always
                            // reloads -- the operator may mean a file nobody
                            // watches, a certificate say. With no servers
                            // running, the next event retries regardless.
                            if !signalled
                                && let Some(running) = &running
                                && running.reread().await == *running
                            {
                                if let Some((_, rx)) = reload_state.as_mut() {
                                    while rx.try_recv().is_ok() {}
                                }
                                return None;
                            }
                        } else {
                            println!("Received SIGHUP, reloading..");
                        }
                        // One reload for one edit, whichever way it was
                        // announced: a write the watcher saw and a SIGHUP the
                        // operator sent for the same write are both pending
                        // now, and whichever won the select above, the other
                        // must not trigger a second restart afterwards.
                        //
                        // What this does not cover: an event still in flight
                        // in the watcher's callback, or a write that lands
                        // during the prepare. Those start another debounce
                        // later, which then finds the bytes unchanged and
                        // restarts nothing (see `Sources`) -- unless the write
                        // really changed them, when the reload is wanted: an
                        // edit is never lost.
                        if let Some((_, rx)) = reload_state.as_mut() {
                            while rx.try_recv().is_ok() {}
                        }
                        reload.drain();
                        Some(prepare_servers(&args, reload_state.as_mut().map(|(w, _)| w)).await)
                    } => outcome,
                    (what, code) = signals.recv() => shut_down(what, code, join_handles).await,
                };

                match outcome {
                    None => println!("Configs unchanged, keeping the running servers."),
                    Some(Ok(p)) => break p,
                    Some(Err(e)) => {
                        eprintln!(
                            "{e}\nKeeping the previous configuration; fix the file to retry."
                        );
                    }
                }
            };

            println!("Restarting servers..");
            for join_handle in &join_handles {
                join_handle.abort();
            }
            // Awaited, not slept over: abort only schedules cancellation,
            // and the replacements bind these same addresses next.
            for join_handle in join_handles {
                let _ = join_handle.await;
            }
        }
    });
}

/// Stop accepting, flush the logs, and exit with the signal's
/// conventional code.
///
/// The default disposition -- die mid-instruction, log writers unflushed
/// -- was the entire shutdown story. In-flight connections still end with
/// the process (draining them is a policy the config should own someday);
/// what this buys is an orderly stop: no new accepts, buffered log lines
/// on disk. The exit code is 130 for SIGINT and 143 for SIGTERM, as the
/// shell convention (128+signum) has it -- exiting 0 made wrappers that
/// key on "user interrupted" (shell loops, make, CI) restart the proxy
/// they had just asked to stop.
async fn shut_down(
    what: &'static str,
    code: i32,
    join_handles: Vec<tokio::task::JoinHandle<()>>,
) -> ! {
    println!("\nReceived {what}, shutting down..");
    for join_handle in &join_handles {
        join_handle.abort();
    }
    for join_handle in join_handles {
        let _ = join_handle.await;
    }
    log::logger().flush();
    std::process::exit(code);
}

/// The operator's reload request: `SIGHUP` on Unix, nothing elsewhere.
///
/// A resumable stream for the reason `ShutdownSignals` gives: installed once
/// and kept across every wait, so a signal that lands during a prepare is
/// buffered rather than lost.
struct ReloadSignal {
    #[cfg(unix)]
    hangup: Option<tokio::signal::unix::Signal>,
}

impl ReloadSignal {
    fn install() -> Self {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            let hangup = match signal(SignalKind::hangup()) {
                Ok(s) => Some(s),
                Err(e) => {
                    eprintln!("Could not install the SIGHUP handler: {e}");
                    None
                }
            };
            Self { hangup }
        }
        #[cfg(not(unix))]
        {
            Self {}
        }
    }

    /// Discard every `SIGHUP` that has arrived and not been read.
    ///
    /// A poll with a throwaway waker: the stream registers it, and the next
    /// `recv` replaces it, so nothing is lost and nothing is woken twice.
    fn drain(&mut self) {
        #[cfg(unix)]
        if let Some(s) = &mut self.hangup {
            let waker = std::task::Waker::noop();
            let mut cx = std::task::Context::from_waker(waker);
            while let std::task::Poll::Ready(Some(())) = s.poll_recv(&mut cx) {}
        }
    }

    /// Resolves on each `SIGHUP`; pends forever if there is no handler.
    async fn recv(&mut self) {
        #[cfg(unix)]
        match &mut self.hangup {
            Some(s) => {
                s.recv().await;
            }
            None => futures::future::pending::<()>().await,
        }
        #[cfg(not(unix))]
        futures::future::pending::<()>().await
    }
}

/// The OS's stop requests, as resumable streams.
struct ShutdownSignals {
    #[cfg(unix)]
    interrupt: Option<tokio::signal::unix::Signal>,
    #[cfg(unix)]
    terminate: Option<tokio::signal::unix::Signal>,
    /// Persistent, like the unix streams: a fresh `ctrl_c()` future per
    /// wait is the one-shot pattern the comment at the install site
    /// forbids -- dropped between waits, a Ctrl-C during the reload
    /// debounce was hard-killed (handler finds no receiver, OS default)
    /// or silently swallowed.
    #[cfg(windows)]
    ctrl_c: Option<tokio::signal::windows::CtrlC>,
}

impl ShutdownSignals {
    fn install() -> Self {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            // A handler that cannot install is reported and skipped; the
            // OS default (immediate death) then applies, which is the
            // pre-existing behavior rather than a new failure mode.
            let try_install = |kind: SignalKind, name: &str| match signal(kind) {
                Ok(s) => Some(s),
                Err(e) => {
                    eprintln!("Could not install the {name} handler: {e}");
                    None
                }
            };
            Self {
                interrupt: try_install(SignalKind::interrupt(), "SIGINT"),
                terminate: try_install(SignalKind::terminate(), "SIGTERM"),
            }
        }
        #[cfg(windows)]
        {
            match tokio::signal::windows::ctrl_c() {
                Ok(s) => Self { ctrl_c: Some(s) },
                Err(e) => {
                    eprintln!("Could not install the Ctrl-C handler: {e}");
                    Self { ctrl_c: None }
                }
            }
        }
        #[cfg(not(any(unix, windows)))]
        {
            Self {}
        }
    }

    /// Resolves when the OS asks the process to exit, with the name and
    /// the conventional exit code (128+signum); pends forever if no
    /// handler could be installed.
    async fn recv(&mut self) -> (&'static str, i32) {
        #[cfg(unix)]
        {
            async fn wait(s: &mut Option<tokio::signal::unix::Signal>) {
                match s {
                    Some(s) => {
                        s.recv().await;
                    }
                    None => futures::future::pending::<()>().await,
                }
            }
            tokio::select! {
                _ = wait(&mut self.interrupt) => ("SIGINT", 130),
                _ = wait(&mut self.terminate) => ("SIGTERM", 143),
            }
        }
        #[cfg(windows)]
        {
            match &mut self.ctrl_c {
                Some(s) => {
                    s.recv().await;
                    ("Ctrl-C", 130)
                }
                None => futures::future::pending().await,
            }
        }
        #[cfg(not(any(unix, windows)))]
        {
            futures::future::pending().await
        }
    }
}

/// Everything a validated configuration needs to start serving.
struct PreparedServers {
    server_configs: Vec<config::Config>,
    dns_registry: dns::DnsRegistry,
    outbounds: outbound_stats::OutboundSet,
    /// The watched files as they were read for this configuration.
    sources: Sources,
}

/// Each watched file -- the configs and the rule-sets they name -- with a
/// hash of its bytes, or `None` where it could not be read.
///
/// The watcher reports that a file was touched, not that it changed, and
/// FSEvents on macOS can report one write twice, the second time after the
/// reload the first caused. A restart drops every live connection, so a
/// watcher event whose files hash the same as the running configuration's is
/// not a reload. Taken before the files are parsed: a write that lands in
/// between leaves the old hash recorded, which costs one extra reload later
/// rather than a lost edit.
#[derive(Default, PartialEq)]
struct Sources(Vec<(String, Option<u64>)>);

impl Sources {
    async fn read(paths: impl IntoIterator<Item = String>) -> Self {
        use std::hash::{Hash, Hasher};
        let mut sources = Vec::new();
        for path in paths {
            let hash = tokio::fs::read(&path).await.ok().map(|bytes| {
                let mut hasher = std::hash::DefaultHasher::new();
                bytes.hash(&mut hasher);
                hasher.finish()
            });
            sources.push((path, hash));
        }
        Self(sources)
    }

    fn paths(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(|(path, _)| path.as_str())
    }

    /// The same files, read again now.
    async fn reread(&self) -> Self {
        Self::read(self.0.iter().map(|(path, _)| path.clone())).await
    }
}

/// Load, validate, and resolve a configuration without touching the servers
/// that may be running -- the reload path decides what to do with the result.
/// The error is the full message to print.
async fn prepare_servers(
    args: &Vec<String>,
    watcher: Option<&mut RecommendedWatcher>,
) -> Result<PreparedServers, String> {
    let config_sources = Sources::read(args.iter().cloned()).await;
    let configs = config::load_configs(args)
        .await
        .map_err(|e| format!("Failed to load server configs: {e}"))?;

    let (configs, load_file_count) = config::convert_cert_paths(configs)
        .await
        .map_err(|e| format!("Failed to load cert files: {e}"))?;

    if load_file_count > 0 {
        println!("Loaded {load_file_count} certs/keys from files");
    }

    for config in configs.iter() {
        debug!("================================================================================");
        debug!("{config:#?}");
    }
    debug!("================================================================================");

    // Rule-set files are only known once the configs are parsed, and
    // which ones exist can change across a reload, so the watch set is
    // refreshed here rather than built once at startup. A rule-set edit
    // then takes the same reload path a config edit does.
    if let Some(watcher) = watcher {
        watch_rule_set_paths(watcher, &configs);
    }
    let rule_set_sources = Sources::read(configs.iter().filter_map(|config| match config {
        config::Config::RuleSet(rule_set) => Some(rule_set.path.clone()),
        _ => None,
    }))
    .await;
    let mut sources = config_sources;
    sources.0.extend(rule_set_sources.0);

    let config::ValidatedConfigs {
        configs: server_configs,
        dns_groups,
        outbounds,
    } = config::create_server_configs(configs)
        .map_err(|e| format!("Failed to create server configs: {e}"))?;

    // Build DNS registry from expanded groups (async - resolves hostnames)
    let dns_registry = dns::build_dns_registry(dns_groups)
        .await
        .map_err(|e| format!("Failed to build DNS registry: {e}"))?;

    Ok(PreparedServers {
        server_configs,
        dns_registry,
        outbounds,
        sources,
    })
}

/// Commit a prepared configuration: install its outbounds and spawn its
/// servers. Only called with a `PreparedServers` that validated whole.
/// A launch failure -- a bind conflict, fd exhaustion -- aborts whatever
/// did start and returns the message to print, so the serve loop decides
/// what happens next instead of a panic deciding for it.
async fn launch_servers(
    prepared: PreparedServers,
) -> Result<Vec<tokio::task::JoinHandle<()>>, String> {
    let PreparedServers {
        server_configs,
        mut dns_registry,
        outbounds,
        // The serve loop keeps these to judge the next watcher event.
        sources: _,
    } = prepared;

    // Replace, not add: a reload must not carry the previous config's
    // servers into the new list.
    #[cfg(feature = "control-stats")]
    crate::outbound_stats::install(&outbounds);
    #[cfg(not(feature = "control-stats"))]
    let _ = outbounds;

    println!("\nStarting {} server(s)..", server_configs.len());

    let mut join_handles: Vec<tokio::task::JoinHandle<()>> = vec![];
    for server_config in server_configs {
        // Get the resolver for this server from the registry. TUN entries
        // without a dns: block keep the uncached system resolver they
        // always had -- see DnsRegistry::get_for_tun.
        let resolver = match &server_config {
            config::Config::Server(s) => dns_registry.get_for_server(s.dns.as_ref()),
            config::Config::TunServer(t) => dns_registry.get_for_tun(t.dns.as_ref()),
            _ => dns_registry.get_for_server(None),
        };
        match start_servers(server_config, resolver).await {
            Ok(handles) => join_handles.extend(handles),
            Err(e) => {
                // Half a configuration must not keep serving as if whole.
                for handle in &join_handles {
                    handle.abort();
                }
                for handle in join_handles {
                    let _ = handle.await;
                }
                return Err(format!("Failed to start servers: {e}"));
            }
        }
    }
    Ok(join_handles)
}
