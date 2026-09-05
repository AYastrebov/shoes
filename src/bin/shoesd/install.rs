//! `shoesd install` and `shoesd uninstall`.
//!
//! The one rule everything here exists to enforce: **the daemon never runs
//! from the path it was invoked at.** That path is inside a user-writable app
//! bundle, and a root daemon whose binary a user can rewrite is a privilege
//! escalation, not a convenience. `install` copies the executable to a
//! root-owned location and points the service manager at the copy.
//!
//! One arm per service manager -- launchd on macOS, systemd on Linux -- and
//! everything below them shared: staging the copy, the ownership discipline
//! and the root check are where a mistake is a privilege escalation rather
//! than a broken install, so they are written once.

use std::path::Path;
use std::process::Command;

/// Where the daemon's own output goes.
///
/// Inside a directory rather than straight into `/var/log`, because launchd
/// creates the file it is pointed at as 0644 and the directory is the only
/// place the mode can be decided in advance. `WatchLogs` filters per
/// subscriber and deliberately does not raise the global level; a log file
/// every local user can read undoes exactly that care, and the two are the
/// same decision.
#[cfg(target_os = "macos")]
const LOG_DIR: &str = "/var/log/shoesd";
#[cfg(target_os = "macos")]
const LOG_PATH: &str = "/var/log/shoesd/shoesd.log";

/// Root reads and writes, the admin group reads, nobody else sees it.
#[cfg(target_os = "macos")]
const LOG_DIR_MODE: u32 = 0o750;

/// By absolute path: a root process must not resolve a program through a
/// `PATH` it inherited from whoever ran `sudo`.
#[cfg(target_os = "macos")]
const LAUNCHCTL: &str = "/bin/launchctl";

/// Where the daemon runs from once installed. Apple's directory for exactly
/// this: a helper that runs with more privilege than the app that ships it.
#[cfg(target_os = "macos")]
pub const INSTALLED_BINARY: &str = "/Library/PrivilegedHelperTools/shoesd";

/// The launchd job. Same namespace as the JNI entry points already use.
#[cfg(target_os = "macos")]
pub const LABEL: &str = "com.shoesproxy.daemon";

/// Administrator-provided system daemons, per `man launchd.plist`.
#[cfg(target_os = "macos")]
pub const PLIST_PATH: &str = "/Library/LaunchDaemons/com.shoesproxy.daemon.plist";

/// `root:wheel`, and not writable by group or other.
///
/// launchd refuses a job whose plist -- or whose executable -- is group- or
/// world-writable, and says so with a bootstrap error that names neither. This
/// is behaviour rather than documented contract, which is why `install` checks
/// the result of every `chown` and `chmod` rather than assuming they took.
#[cfg(target_os = "macos")]
const PLIST_MODE: u32 = 0o644;

/// The installed binary's mode, on both platforms. Root writes it, everyone
/// executes it, and nobody else writes it -- the last clause is the one that
/// makes the copy worth making.
const BINARY_MODE: u32 = 0o755;

/// The plist, with the arguments this daemon was asked to run with.
///
/// `KeepAlive` implies `RunAtLoad`, so a crash is followed by a restart within
/// seconds -- which is what makes crash recovery reach a machine whose network
/// is down and whose user therefore cannot log in to fix it. Both keys are set
/// anyway, because every plist on a stock system does and a reader should not
/// have to know the implication.
///
/// launchd throttles a job that exits quickly and repeatedly to roughly one
/// launch every ten seconds. That bounds how fast recovery can retry, and is
/// the reason recovery has to be idempotent rather than merely fast.
///
/// systemd does not do this, which is why the Linux unit has a line the plist
/// does not need. See `unit`.
#[cfg(target_os = "macos")]
fn plist(socket_path: &Path, state_path: &Path, group: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{INSTALLED_BINARY}</string>
        <string>run</string>
        <string>--socket</string>
        <string>{socket}</string>
        <string>--state</string>
        <string>{state}</string>
        <string>--group</string>
        <string>{group}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{LOG_PATH}</string>
    <key>StandardErrorPath</key>
    <string>{LOG_PATH}</string>
</dict>
</plist>
"#,
        socket = xml(&socket_path.display().to_string()),
        state = xml(&state_path.display().to_string()),
        group = xml(group),
    )
}

/// Escape a value for an XML text node.
///
/// The paths and the group name come from the command line, and `&` is a legal
/// character in a filename. Interpolated raw, one produces a plist that is not
/// well-formed, and `launchctl bootstrap` then fails with an error naming
/// neither the character nor the key it was in.
#[cfg(target_os = "macos")]
fn xml(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            _ => escaped.push(c),
        }
    }
    escaped
}

/// Copy the running executable into place, write the plist, and bootstrap it.
///
/// `group` is `None` when `--group` was not given. macOS has no detection to
/// do -- `admin` is the answer on every Mac -- so it simply takes the default;
/// the Linux arm is where the distinction earns its keep.
#[cfg(target_os = "macos")]
pub fn install(socket_path: &Path, state_path: &Path, group: Option<&str>) -> std::io::Result<()> {
    require_root("install")?;

    let group = group.unwrap_or(crate::DEFAULT_GROUP);

    // Resolved before anything else: a group that does not exist would give a
    // daemon that runs and refuses everyone, and the failure would look like a
    // broken install rather than a typo.
    let _ = crate::auth::Authorizer::for_group(group)?;

    let source = std::env::current_exe().map_err(|e| {
        std::io::Error::new(e.kind(), format!("could not find this executable: {e}"))
    })?;
    let destination = Path::new(INSTALLED_BINARY);

    if source == destination {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{INSTALLED_BINARY} is already the installed copy; nothing to do"),
        ));
    }

    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Replaced rather than written over: overwriting a running binary in place
    // is how a copy that is half old and half new gets executed.
    //
    // Created at 0600 first, rather than copied and then tightened.
    // `std::fs::copy` carries the source's permission bits across, so a source
    // that is group- or world-writable -- a tarball unpacked with a loose
    // umask -- would exist writable under a root-owned path for the window
    // before the mode was fixed, and the rename below makes it the binary
    // launchd runs as root.
    let staged = destination.with_extension("new");
    stage(&source, &staged)?;
    set_root_owned(&staged, BINARY_MODE)?;
    std::fs::rename(&staged, destination)?;

    // Before the plist that names it: launchd creates the log file itself, at
    // 0644, and only the directory's mode keeps it from every local user.
    std::fs::create_dir_all(LOG_DIR)?;
    set_root_owned(Path::new(LOG_DIR), LOG_DIR_MODE)?;

    std::fs::write(PLIST_PATH, plist(socket_path, state_path, group))?;
    set_root_owned(Path::new(PLIST_PATH), PLIST_MODE)?;

    // Idempotent: an install over an existing one has to remove the old job
    // before bootstrapping the new plist, or launchd refuses it as already
    // loaded. A first install has nothing to remove, so the failure is
    // ignored rather than reported.
    let _ = run(LAUNCHCTL, &["bootout".into(), format!("system/{LABEL}")]);
    run(
        LAUNCHCTL,
        &["bootstrap".into(), "system".into(), PLIST_PATH.into()],
    )?;

    log::info!("installed {INSTALLED_BINARY} and bootstrapped {LABEL}");
    Ok(())
}

/// Stop the job, remove it, and delete both files.
///
/// Every step is attempted even after one fails, for the same reason the
/// revert path never stops early: leaving the plist behind means launchd
/// restarts a daemon whose binary is gone, on a ten-second throttle, forever.
#[cfg(target_os = "macos")]
pub fn uninstall() -> std::io::Result<()> {
    require_root("uninstall")?;

    let mut failures = Vec::new();

    // `bootout` sends the job SIGTERM, which is what makes the daemon revert
    // its routes and DNS before it exits -- so the session is torn down by
    // the same path a shutdown uses rather than a second one written here.
    if let Err(e) = run(LAUNCHCTL, &["bootout".into(), format!("system/{LABEL}")]) {
        // Not loaded is the ordinary case for a partial install.
        log::debug!("bootout reported: {e}");
    }

    for path in [Path::new(PLIST_PATH), Path::new(INSTALLED_BINARY)] {
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => failures.push(format!("removing {}: {e}", path.display())),
        }
    }

    if failures.is_empty() {
        log::info!("removed {LABEL}");
        return Ok(());
    }
    Err(std::io::Error::other(format!(
        "could not fully uninstall: {}",
        failures.join("; ")
    )))
}

/// Where the daemon runs from once installed.
///
/// `/usr/local/libexec` for the same reason macOS uses
/// `/Library/PrivilegedHelperTools`: a program run by other programs rather
/// than by a user, outside the half of the filesystem a package manager owns,
/// so a distribution upgrade cannot replace the binary a root daemon runs.
#[cfg(target_os = "linux")]
pub const INSTALLED_BINARY: &str = "/usr/local/libexec/shoesd";

/// The systemd unit, and the name every `systemctl` call uses. The plist
/// `Label`'s counterpart -- `main.rs` prints both and does not branch.
#[cfg(target_os = "linux")]
pub const LABEL: &str = "shoesd.service";

/// Administrator-provided units, per `systemd.unit(5)`. `/etc/systemd/system`
/// rather than `/usr/lib/systemd/system`, which belongs to the package
/// manager and which a distribution upgrade may rewrite.
#[cfg(target_os = "linux")]
pub const UNIT_PATH: &str = "/etc/systemd/system/shoesd.service";

/// World-readable, root-writable. systemd warns about a unit file that is
/// executable or group-writable and reads it anyway; the mode is set here so
/// that it is decided rather than inherited from whatever umask `pkexec`
/// happened to hand this process.
#[cfg(target_os = "linux")]
const UNIT_MODE: u32 = 0o644;

/// By absolute path, from a fixed list, never `PATH`: a root process must not
/// resolve a program through an environment it inherited from whoever ran
/// `sudo`.
///
/// Two candidates rather than one because merged-`/usr` layouts vary. On
/// Fedora 44 `/bin` is a symlink to `usr/bin` and both hit the same file; on a
/// host that still splits them only one does.
#[cfg(target_os = "linux")]
const SYSTEMCTL: [&str; 2] = ["/usr/bin/systemctl", "/bin/systemctl"];

/// `restorecon`, which lives in `sbin` rather than `bin`. Absent entirely on
/// Debian, Ubuntu and Arch, which is a supported outcome -- see `relabel`.
#[cfg(target_os = "linux")]
const RESTORECON: [&str; 2] = ["/usr/sbin/restorecon", "/sbin/restorecon"];

/// The groups a Linux administrator is plausibly in, in the order they are
/// preferred.
///
/// `admin` -- macOS's answer -- does not exist here. `wheel` is the
/// administrators' group on Fedora, Arch and openSUSE, `sudo` on Debian and
/// Ubuntu, and `adm` is last because on Fedora it is empty and on Debian it
/// holds whoever may read logs, which is a wider set than whoever may
/// reconfigure the machine's routing.
#[cfg(target_os = "linux")]
const GROUP_CANDIDATES: [&str; 3] = ["wheel", "sudo", "adm"];

/// The unit, with the arguments this daemon was asked to run with.
///
/// `Restart=always` is `KeepAlive`'s counterpart and **is not sufficient on
/// its own.** launchd throttles a job that keeps failing and retries forever;
/// systemd gives up. `systemd.unit(5)`: "units which are configured for
/// `Restart=`, and which reach the start limit are not attempted to be
/// restarted anymore", with `DefaultStartLimitBurst=5` inside
/// `DefaultStartLimitIntervalSec=10s` (`systemd-system.conf(5)`).
///
/// A daemon that crash-loops five times in ten seconds would therefore be
/// abandoned with its exclusion routes installed and `/etc/resolv.conf`
/// rewritten, on a machine whose network is down and whose user therefore
/// cannot fetch a fix. Recovery runs at the *start* of the next run, so never
/// starting again is exactly the failure the on-disk revert record exists to
/// prevent, reached through the service manager instead of through the code.
///
/// `StartLimitIntervalSec=0` disables the limit outright and `RestartSec=5`
/// keeps the retry a slow loop rather than a hot one -- launchd's behaviour,
/// restored deliberately. It also keeps launchd's consequence: the retry is
/// unbounded, so a recovery that is not safe to run twice is not safe.
///
/// The comments are in the rendered file on purpose. The symptom of a missing
/// `StartLimitIntervalSec=0` is "the daemon stopped coming back", and the
/// admin reading the unit is the person who has to connect the two.
#[cfg(target_os = "linux")]
fn unit(socket_path: &Path, state_path: &Path, group: &str) -> String {
    let arguments = [
        INSTALLED_BINARY,
        "run",
        "--socket",
        &socket_path.display().to_string(),
        "--state",
        &state_path.display().to_string(),
        "--group",
        group,
    ]
    .map(quote)
    .join(" ");

    format!(
        r#"[Unit]
Description=shoes privileged VPN daemon
Documentation=https://github.com/cfal/shoes/
After=network.target

# systemd stops restarting a unit that reaches the start limit -- five starts
# in ten seconds, by default. This daemon must keep coming back: the routes and
# the resolver configuration it applied outlive the process, and the pass that
# undoes them runs at the start of the next run. Being abandoned mid-crash-loop
# would strand them on a machine whose network is already down.
StartLimitIntervalSec=0

[Service]
# `exec` rather than `simple`: a binary systemd cannot execute -- a wrong mode,
# an SELinux label -- is then a failed start instead of a start that succeeded
# and a process that was never there.
Type=exec
ExecStart={arguments}
Restart=always
RestartSec=5

# Deliberately no RuntimeDirectory= for /run/shoesd: the daemon creates it, and
# its 0750 root:group is what closes the window between the control socket
# being bound and its mode being set. One owner for that decision.
#
# And deliberately no ProtectSystem=, ProtectHome= or NoNewPrivileges=. This
# daemon's job is to rewrite the routing table and /etc/resolv.conf; a sandbox
# that stopped it would present as a tunnel that comes up and carries nothing.

[Install]
WantedBy=multi-user.target
"#
    )
}

/// Quote one `ExecStart` argument per `systemd.service(5)`.
///
/// This is the plist `xml()`'s counterpart, and it exists for the same reason:
/// the paths and the group name come from the command line, and `ExecStart`
/// *is* parsed rather than taken literally. Four things expand or split there,
/// and all four were measured against systemd 259 on the development host by
/// loading a unit and reading `systemctl show -p ExecStart` back:
///
/// - whitespace splits a word, so `/tmp/a b` becomes two arguments;
/// - `"` and `\` are quoting and escaping, and C escapes apply inside quotes,
///   so a raw newline in a path would end the line and truncate the command;
/// - `%` introduces a specifier, expanded when the unit is *loaded* and even
///   inside double quotes: `"%h"` came back as the invoking home directory;
/// - `$` introduces an environment variable, expanded when the command is
///   *executed*: `"$HOME"` survived into the stored argv and would expand
///   later.
///
/// Everything is wrapped in double quotes, and the four characters that still
/// mean something inside them -- `"`, `\`, `%`, `$` -- are escaped, along with
/// the control characters that would break the line the value sits on. An
/// argument that is exactly `;` would otherwise start a second command;
/// quoting it makes it a literal, also measured.
#[cfg(target_os = "linux")]
fn quote(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('"');
    for c in value.chars() {
        match c {
            '"' | '\\' => {
                quoted.push('\\');
                quoted.push(c);
            }
            '%' => quoted.push_str("%%"),
            '$' => quoted.push_str("$$"),
            // A raw newline would end the line and take the rest of the
            // command with it; a raw carriage return or tab is legal but
            // invisible in the file. The C escapes are read back inside the
            // quotes.
            '\n' => quoted.push_str("\\n"),
            '\r' => quoted.push_str("\\r"),
            '\t' => quoted.push_str("\\t"),
            _ => quoted.push(c),
        }
    }
    quoted.push('"');
    quoted
}

/// Which group the control socket ends up owned by, given a predicate that
/// answers "does this group exist *and* contain this uid".
///
/// The predicate is injected because the answer would otherwise depend on the
/// accounts that happen to exist on the machine running the tests -- the same
/// split `auth.rs` makes between `authorize` and `groups_of`, for the same
/// reason.
///
/// Both halves of that conjunction are load-bearing. On the development host
/// `wheel` exists and contains the user, `adm` exists and is *empty*, and
/// `sudo` is absent; a rule that stopped at "the group exists" would be right
/// there by luck and would pick `adm` on a Debian box, installing a control
/// socket the administrator cannot reach. That failure looks exactly like a
/// daemon that is not running, which is the shape this daemon works hardest to
/// avoid producing.
#[cfg(target_os = "linux")]
fn choose_group(uid: u32, contains: impl Fn(&str, u32) -> bool) -> std::io::Result<&'static str> {
    for candidate in GROUP_CANDIDATES {
        if contains(candidate, uid) {
            return Ok(candidate);
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        format!(
            "uid {uid} is in none of {}, so there is no group to give the control socket to. \
             Pass --group <name> to name one.",
            GROUP_CANDIDATES.join(", ")
        ),
    ))
}

/// The uid that asked for this install, from the environment the elevation
/// helper set.
///
/// `PKEXEC_UID` first, because that is how the app elevates -- the GUI runs as
/// the user and `pkexec` is what crosses the boundary -- and `SUDO_UID` for a
/// hand-run `sudo shoesd install`. The daemon is the only side that can see
/// either, which is why group detection belongs here and not in the app.
#[cfg(target_os = "linux")]
fn invoking_uid() -> Option<u32> {
    uid_of(
        std::env::var("PKEXEC_UID").ok().as_deref(),
        std::env::var("SUDO_UID").ok().as_deref(),
    )
}

/// The precedence, as a pure function.
///
/// Separate from `invoking_uid` so it can be tested without `set_var`, which
/// is process-wide and would reach every other test running at that moment --
/// the rule AGENTS.md states about global state in tests.
///
/// A value that does not parse falls through to the other variable rather than
/// failing: `PKEXEC_UID` set to something unreadable is a broken elevation
/// helper, and `SUDO_UID` beside it is still a true answer.
#[cfg(target_os = "linux")]
fn uid_of(pkexec: Option<&str>, sudo: Option<&str>) -> Option<u32> {
    pkexec
        .and_then(|value| value.parse().ok())
        .or_else(|| sudo.and_then(|value| value.parse().ok()))
}

/// Does `name` exist as a group, and is `uid` in it?
///
/// Both halves from one entry, because `getgrnam` answers both: the entry
/// itself proves existence, and membership is either its gid matching the
/// user's primary group or the user's name appearing in its member list. A
/// check that read only the member list would miss a user whose *primary*
/// group is the administrators' one, which is unusual rather than impossible.
///
/// `auth.rs` asks a similar question with `getgrouplist` because it runs per
/// gRPC call with nothing but a uid in hand. This runs once, at install time.
#[cfg(target_os = "linux")]
fn group_contains(name: &str, uid: u32) -> bool {
    // The passwd lookup first, and copied out, because `getgrnam` below
    // returns a pointer into the group database's own static buffer -- read
    // before anything else on this thread can call into it.
    let Some((username, primary_gid)) = passwd_of(uid) else {
        return false;
    };
    let Ok(c_name) = std::ffi::CString::new(name) else {
        return false;
    };

    // SAFETY: `c_name` is a valid NUL-terminated string for the call. The
    // returned pointer is to a static buffer, read below and not stored.
    let entry = unsafe { libc::getgrnam(c_name.as_ptr()) };
    if entry.is_null() {
        return false;
    }

    // SAFETY: checked non-null above.
    let (gid, mut member) = unsafe { ((*entry).gr_gid, (*entry).gr_mem) };
    if gid == primary_gid {
        return true;
    }
    if member.is_null() {
        return false;
    }
    // SAFETY: `gr_mem` is a NULL-terminated array of NUL-terminated strings,
    // per `getgrnam(3)`, valid for as long as the entry above is.
    unsafe {
        while !(*member).is_null() {
            if std::ffi::CStr::from_ptr(*member) == username.as_c_str() {
                return true;
            }
            member = member.add(1);
        }
    }
    false
}

/// The login name and primary gid for a uid.
///
/// `getpwuid` rather than `auth.rs`'s `getpwuid_r`. That one is reentrant
/// because it runs per gRPC call on tonic's worker threads, where two
/// concurrent calls would race the shared static this returns a pointer into.
/// Neither condition holds here: this runs once, from `main`, before the
/// daemon exists.
///
/// `None` for a uid with no account, which the caller turns into "not a
/// member" -- the safe direction, since it can only refuse to detect a group.
#[cfg(target_os = "linux")]
fn passwd_of(uid: u32) -> Option<(std::ffi::CString, u32)> {
    // SAFETY: a scalar argument and no pointers. The returned pointer is to a
    // static buffer, copied out below before anything else can call into the
    // passwd database on this thread.
    let entry = unsafe { libc::getpwuid(uid as libc::uid_t) };
    if entry.is_null() {
        return None;
    }
    // SAFETY: checked non-null; `pw_name` is a NUL-terminated string inside
    // that buffer and `to_owned` copies it.
    unsafe {
        Some((
            std::ffi::CStr::from_ptr((*entry).pw_name).to_owned(),
            (*entry).pw_gid,
        ))
    }
}

/// The group the control socket ends up owned by.
///
/// An explicit `--group` is honoured verbatim, including one the invoker is
/// not in: `install` is the one place an administrator may legitimately set a
/// daemon up for someone else.
///
/// `None` means the flag was absent, and that is what turns detection on.
/// `parse_run_args` deliberately does not substitute `DEFAULT_GROUP`: doing so
/// made an explicit `--group wheel` indistinguishable from no flag at all, so
/// the one value a Fedora administrator is most likely to type was the one
/// silently re-derived -- and on a host where `wheel` exists but does not
/// contain them, naming it explicitly failed with "no candidate group contains
/// you" instead of doing as it was told. `an_explicit_group_is_taken_as_given`
/// pins it.
#[cfg(target_os = "linux")]
fn resolve_group(requested: Option<&str>) -> std::io::Result<String> {
    // An explicit name is always honoured, including one the invoker is not in:
    // `install` is the one place an administrator may legitimately set a daemon
    // up for somebody else.
    if let Some(requested) = requested {
        return Ok(requested.to_string());
    }

    let Some(uid) = invoking_uid() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "cannot tell who asked for this install: neither PKEXEC_UID nor SUDO_UID is set. \
             Run it through pkexec or sudo, or pass --group <name>"
                .to_string(),
        ));
    };

    let group = choose_group(uid, group_contains)?;
    log::info!("uid {uid} is in {group}; the control socket will be group {group}");
    Ok(group.to_string())
}

/// The first candidate that exists, or an error naming all of them.
///
/// Naming all of them matters: "systemctl not found" on a host that has it in
/// the other directory sends the reader looking for a broken install rather
/// than at a list they can check in one command.
#[cfg(target_os = "linux")]
fn find_tool(what: &str, candidates: &[&'static str]) -> std::io::Result<&'static str> {
    candidates
        .iter()
        .copied()
        .find(|candidate| Path::new(candidate).exists())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("could not find {what} at any of {}", candidates.join(", ")),
            )
        })
}

/// Relabel the installed binary for SELinux, where the tool exists.
///
/// Fedora enforces by default and openSUSE recently does too. A file written
/// into `/usr/local/libexec` by a process with some other context can land
/// with a label systemd will not execute, and the symptom is a unit that fails
/// to start with a permission error naming nothing in particular.
///
/// Debian, Ubuntu and Arch have no `restorecon`, and its absence is a
/// supported outcome rather than a failure. Absence is not failure, though: a
/// `restorecon` that is present and exits non-zero is reported, because then
/// the label is unknown rather than known-irrelevant.
#[cfg(target_os = "linux")]
fn relabel(path: &Path) -> std::io::Result<()> {
    let Ok(tool) = find_tool("restorecon", &RESTORECON) else {
        log::debug!("no restorecon on this host; nothing to relabel");
        return Ok(());
    };
    run(tool, &[path.display().to_string()])
}

/// Copy the running executable into place, write the unit, and start it.
///
/// `group` is `None` when `--group` was not given, and that is what turns on
/// detection -- see [`resolve_group`]. Defaulting it at the argument parser
/// would make an explicit `--group wheel` indistinguishable from no flag, so
/// the one value a Fedora administrator is most likely to type would be the
/// one silently re-derived.
#[cfg(target_os = "linux")]
pub fn install(socket_path: &Path, state_path: &Path, group: Option<&str>) -> std::io::Result<()> {
    require_root("install")?;

    // All three before anything is written: a missing `systemctl`, a host
    // where no candidate group contains the invoker, or a `--group` that is a
    // typo would otherwise be discovered with a root-owned binary already in
    // place and no unit naming it. The last of those is why the group is
    // resolved here even though detection has already proved its own answer
    // exists -- an explicit `--group` has not been through anything.
    let systemctl = find_tool("systemctl", &SYSTEMCTL)?;
    let group = resolve_group(group)?;
    let _ = crate::auth::Authorizer::for_group(&group)?;

    let source = std::env::current_exe().map_err(|e| {
        std::io::Error::new(e.kind(), format!("could not find this executable: {e}"))
    })?;
    let destination = Path::new(INSTALLED_BINARY);

    if source == destination {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{INSTALLED_BINARY} is already the installed copy; nothing to do"),
        ));
    }

    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Identical to the macOS arm, and for reasons that are not platform
    // specific: replaced rather than written over, because overwriting a
    // running binary in place is how a copy that is half old and half new gets
    // executed; and created at 0600 first, because `std::fs::copy` carries the
    // source's permission bits across and a source unpacked with a loose umask
    // would exist writable under a root-owned path for the window before the
    // mode was fixed.
    let staged = destination.with_extension("new");
    stage(&source, &staged)?;
    set_root_owned(&staged, BINARY_MODE)?;
    std::fs::rename(&staged, destination)?;
    relabel(destination)?;

    // No `StandardOutPath`: systemd gives the unit's stdout and stderr to the
    // journal, so there is no file whose mode this has to decide in advance --
    // which is the whole reason the macOS arm owns a log directory.
    std::fs::write(UNIT_PATH, unit(socket_path, state_path, &group))?;
    set_root_owned(Path::new(UNIT_PATH), UNIT_MODE)?;

    // systemd caches unit files. Without this, a first install fails with
    // "unit not found" and a second silently keeps running the previous
    // `ExecStart`.
    run(systemctl, &["daemon-reload".into()])?;
    run(systemctl, &["enable".into(), LABEL.into()])?;
    // `restart` rather than `enable --now`: `--now` starts a unit that is
    // stopped and leaves a running one alone, so installing over a running
    // daemon would keep executing the binary that was just replaced.
    // `restart` starts an inactive unit and restarts an active one, which is
    // the idempotence `bootout`-then-`bootstrap` gives on macOS.
    run(systemctl, &["restart".into(), LABEL.into()])?;

    log::info!("installed {INSTALLED_BINARY} and started {LABEL} for group {group}");
    Ok(())
}

/// Stop the unit, disable it, and delete both files.
///
/// Every step is attempted even after one fails, for the same reason the
/// revert path never stops early: leaving the unit behind means systemd
/// restarts a daemon whose binary is gone every five seconds forever -- and
/// `StartLimitIntervalSec=0` is precisely what removes the limit that would
/// otherwise have stopped it.
#[cfg(target_os = "linux")]
pub fn uninstall() -> std::io::Result<()> {
    require_root("uninstall")?;

    let mut failures = Vec::new();

    let systemctl = match find_tool("systemctl", &SYSTEMCTL) {
        Ok(path) => Some(path),
        // Recorded rather than returned: the files can still be removed, and
        // leaving them behind is the worse outcome.
        Err(e) => {
            failures.push(e.to_string());
            None
        }
    };

    if let Some(systemctl) = systemctl {
        // `stop` sends SIGTERM, which is what makes the daemon revert its
        // routes and DNS before it exits -- so the session is torn down by the
        // same path a shutdown uses rather than a second one written here.
        // First, and while the unit file it names still exists.
        if let Err(e) = run(systemctl, &["stop".into(), LABEL.into()]) {
            // Not loaded is the ordinary case for a partial install.
            log::debug!("stop reported: {e}");
        }
        if let Err(e) = run(systemctl, &["disable".into(), LABEL.into()]) {
            log::debug!("disable reported: {e}");
        }
    }

    for path in [Path::new(UNIT_PATH), Path::new(INSTALLED_BINARY)] {
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => failures.push(format!("removing {}: {e}", path.display())),
        }
    }

    // After the files are gone, so systemd forgets the unit rather than
    // holding a loaded one whose fragment no longer exists. Reported rather
    // than logged, unlike `stop` and `disable`: this one succeeds whether or
    // not anything was installed, so a failure here is real.
    if let Some(systemctl) = systemctl
        && let Err(e) = run(systemctl, &["daemon-reload".into()])
    {
        failures.push(e.to_string());
    }

    if failures.is_empty() {
        log::info!("removed {LABEL}");
        return Ok(());
    }
    Err(std::io::Error::other(format!(
        "could not fully uninstall: {}",
        failures.join("; ")
    )))
}

/// Copy `source` to `staged`, created writable by nobody else.
fn stage(source: &Path, staged: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;

    // Removed first, because `create` on an existing file keeps the mode it
    // already has -- which is the mode this exists to control.
    match std::fs::remove_file(staged) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }

    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(staged)
        .map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!("could not create {}: {e}", staged.display()),
            )
        })?;
    let mut input = std::fs::File::open(source).map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!("could not read {}: {e}", source.display()),
        )
    })?;

    std::io::copy(&mut input, &mut output).map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!(
                "could not copy {} to {}: {e}",
                source.display(),
                staged.display()
            ),
        )
    })?;
    Ok(())
}

/// What uid 0 and gid 0 are called, for the error message.
///
/// The same two ids on both platforms, under two names: gid 0 is `wheel` on
/// Darwin and `root` on Linux. The message has to say the one the reader will
/// see in `ls -l`, or it sends them looking for a group their system does not
/// have.
#[cfg(target_os = "macos")]
const ROOT_OWNER: &str = "root:wheel";
#[cfg(target_os = "linux")]
const ROOT_OWNER: &str = "root:root";

/// Owned by root, and the given mode.
fn set_root_owned(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains a NUL byte")
    })?;
    // SAFETY: `c_path` is a valid NUL-terminated string for the call, and both
    // ids are scalars. 0:0 is root and the group gid 0 names.
    if unsafe { libc::chown(c_path.as_ptr(), 0, 0) } != 0 {
        let e = std::io::Error::last_os_error();
        return Err(std::io::Error::new(
            e.kind(),
            format!("could not chown {} to {ROOT_OWNER}: {e}", path.display()),
        ));
    }

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!("could not set mode {mode:o} on {}: {e}", path.display()),
        )
    })
}

/// Refuse early, with a sentence rather than a permission error from
/// whichever step happened to be first.
fn require_root(action: &str) -> std::io::Result<()> {
    // SAFETY: no arguments, no pointers; `geteuid` cannot fail.
    if unsafe { libc::geteuid() } == 0 {
        return Ok(());
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        format!("shoesd {action} must run as root (try sudo)"),
    ))
}

fn run(program: &str, args: &[String]) -> std::io::Result<()> {
    let output = Command::new(program).args(args).output().map_err(|e| {
        std::io::Error::new(e.kind(), format!("could not run {program} {args:?}: {e}"))
    })?;
    if output.status.success() {
        return Ok(());
    }
    Err(std::io::Error::other(format!(
        "{program} {args:?} failed ({}): {}",
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    )))
}

/// What both arms share: the staging discipline and the root check, which are
/// the parts a mistake in is a privilege escalation rather than a broken
/// install.
#[cfg(test)]
mod tests {
    use super::*;

    /// The staged copy is never writable by anyone but its owner, even for the
    /// instant before its mode is set.
    ///
    /// `std::fs::copy` carries the source's permission bits across, so a
    /// source unpacked with a loose umask would exist group- or
    /// world-writable under a root-owned path -- and the next line renames it
    /// into the binary the service manager runs as root.
    #[test]
    fn the_staged_binary_is_never_writable_by_others() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("shoesd-source");
        std::fs::write(&source, b"#!/bin/sh\ntrue\n").unwrap();
        // Deliberately loose, which is what a tarball or a shared build
        // directory can produce.
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o666)).unwrap();

        let staged = dir.path().join("shoesd.new");
        stage(&source, &staged).expect("staging works");

        let mode = std::fs::metadata(&staged).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "got {mode:o}");
        assert_eq!(
            std::fs::read(&staged).unwrap(),
            std::fs::read(&source).unwrap()
        );
    }

    /// And staging over a leftover file from an interrupted install still
    /// gets the mode right, rather than inheriting whatever that file had.
    #[test]
    fn staging_replaces_a_leftover_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("shoesd-source");
        std::fs::write(&source, b"new").unwrap();

        let staged = dir.path().join("shoesd.new");
        std::fs::write(&staged, b"old").unwrap();
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o666)).unwrap();

        stage(&source, &staged).expect("a leftover must not block an install");

        let mode = std::fs::metadata(&staged).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "got {mode:o}");
        assert_eq!(std::fs::read(&staged).unwrap(), b"new");
    }

    /// The installed binary is executable by everyone and writable by nobody
    /// but root. Group-writable would hand the whole point of copying it away.
    #[test]
    fn the_installed_binary_is_writable_only_by_root() {
        assert_eq!(BINARY_MODE & 0o022, 0, "got {BINARY_MODE:o}");
        assert!(INSTALLED_BINARY.starts_with('/'), "{INSTALLED_BINARY}");
    }

    /// Both refuse before touching anything when not root, with a sentence
    /// rather than whichever step's permission error came first.
    #[test]
    fn installing_without_root_is_refused_early() {
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let err = install(
            Path::new("/var/run/shoesd.sock"),
            Path::new("/var/db/shoesd/applied.json"),
            Some(crate::DEFAULT_GROUP),
        )
        .expect_err("a non-root install must be refused");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(err.to_string().contains("sudo"), "got {err}");

        let err = uninstall().expect_err("a non-root uninstall must be refused");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    }
}

#[cfg(all(test, target_os = "linux"))]
mod linux_tests {
    use super::*;

    fn rendered() -> String {
        unit(
            Path::new("/run/shoesd/shoesd.sock"),
            Path::new("/var/db/shoesd/applied.json"),
            "wheel",
        )
    }

    /// systemd's own `ExecStart` parsing, applied to the rendered line, so the
    /// assertions are about the argv systemd will build rather than about what
    /// the string looks like.
    ///
    /// The rules are `systemd.service(5)` and `systemd.syntax(7)`, and each
    /// was checked against systemd 259 on the development host by loading a
    /// unit and reading `systemctl show -p ExecStart` back: words split on
    /// whitespace outside quotes, `"` and `'` quote, `\` escapes C-style, `%%`
    /// is a literal `%` after specifier expansion at load time, and `$$` is a
    /// literal `$` after environment expansion at exec time.
    fn exec_start_argv(unit: &str) -> Vec<String> {
        let line = unit
            .lines()
            .find_map(|line| line.strip_prefix("ExecStart="))
            .expect("the unit has an ExecStart");

        let mut argv: Vec<String> = Vec::new();
        let mut word = String::new();
        let mut started = false;
        let mut quote: Option<char> = None;
        let mut characters = line.chars();
        while let Some(c) = characters.next() {
            match c {
                '\\' => {
                    let escaped = characters
                        .next()
                        .expect("a line ending in a backslash is a continuation, not an escape");
                    word.push(match escaped {
                        'n' => '\n',
                        't' => '\t',
                        'r' => '\r',
                        other => other,
                    });
                    started = true;
                }
                '"' | '\'' if quote.is_none() => {
                    quote = Some(c);
                    started = true;
                }
                c if Some(c) == quote => quote = None,
                c if c.is_whitespace() && quote.is_none() => {
                    if started {
                        argv.push(std::mem::take(&mut word));
                        started = false;
                    }
                }
                c => {
                    word.push(c);
                    started = true;
                }
            }
        }
        assert!(quote.is_none(), "unterminated quote in {line:?}");
        if started {
            argv.push(word);
        }

        argv.iter().map(|argument| expand(argument)).collect()
    }

    /// What the manager does to a word once it has unquoted it: `%` specifiers
    /// when the unit is loaded, `$` variables when the command is executed,
    /// with `%%` and `$$` the escapes for a literal one.
    ///
    /// Modelled rather than skipped, and the reason is a defect this caught: a
    /// version that only turned `%%` back into `%` passed just as happily when
    /// `quote` did not escape `%` at all, because an unescaped `%h` reads back
    /// as `%h` here while systemd turns it into the invoking home directory.
    /// Anything that would expand becomes a marker no expected value matches.
    fn expand(word: &str) -> String {
        let mut expanded = String::with_capacity(word.len());
        let mut characters = word.chars().peekable();
        while let Some(c) = characters.next() {
            match c {
                '%' | '$' if characters.peek() == Some(&c) => {
                    characters.next();
                    expanded.push(c);
                }
                '%' | '$' => {
                    expanded.push_str("<expanded by systemd>");
                    characters.next();
                }
                c => expanded.push(c),
            }
        }
        expanded
    }

    /// The unit runs the installed copy, never wherever the executable
    /// happened to be when `install` ran. That path is inside a user-writable
    /// app bundle, and a root daemon on a user-writable binary is a privilege
    /// escalation.
    #[test]
    fn the_unit_runs_the_installed_copy() {
        let unit = rendered();
        assert_eq!(exec_start_argv(&unit)[0], INSTALLED_BINARY, "{unit}");

        let invoked = std::env::current_exe().expect("the test binary has a path");
        assert!(
            !unit.contains(&invoked.display().to_string()),
            "the invoked path must not appear anywhere in the unit:\n{unit}"
        );
    }

    /// Every argument survives into `ExecStart` as its own word, including a
    /// path with a space and one with a quote.
    ///
    /// `ExecStart` is parsed, not taken literally: unquoted, `/tmp/a b` is two
    /// arguments and the daemon would refuse a socket path it never received.
    #[test]
    fn each_argument_survives_into_exec_start() {
        let unit = unit(
            Path::new("/tmp/a b/shoesd.sock"),
            Path::new("/tmp/it's \"quoted\"/applied.json"),
            "ops admins",
        );
        assert_eq!(
            exec_start_argv(&unit),
            vec![
                INSTALLED_BINARY,
                "run",
                "--socket",
                "/tmp/a b/shoesd.sock",
                "--state",
                "/tmp/it's \"quoted\"/applied.json",
                "--group",
                "ops admins",
            ],
            "{unit}"
        );
    }

    /// And the three characters that expand rather than split.
    ///
    /// `%` is a specifier, expanded when the unit is loaded and even inside
    /// double quotes -- `"%h"` came back as the home directory on systemd 259.
    /// `$` is an environment variable, expanded at exec time. A lone `;`
    /// starts a second command. All three are values a path or a group name
    /// may legally contain, and all three arrive from the command line.
    #[test]
    fn specifiers_variables_and_separators_do_not_expand() {
        let unit = unit(
            Path::new("/tmp/100%h/shoesd.sock"),
            Path::new("/tmp/$HOME/a\\b/applied.json"),
            ";",
        );
        assert_eq!(
            exec_start_argv(&unit),
            vec![
                INSTALLED_BINARY,
                "run",
                "--socket",
                "/tmp/100%h/shoesd.sock",
                "--state",
                "/tmp/$HOME/a\\b/applied.json",
                "--group",
                ";",
            ],
            "{unit}"
        );
    }

    /// A control character in a value never reaches the file raw.
    ///
    /// Unit files are line-based, so a raw newline would end `ExecStart=`
    /// early -- a daemon started with half its arguments, and a `[Service]`
    /// section with a stray key in it. A raw tab or carriage return would
    /// survive but be invisible to anyone reading the file to find out what
    /// the daemon was started with.
    #[test]
    fn control_characters_never_reach_the_line_raw() {
        let path = "/tmp/two\nlines\rand\ta tab.sock";
        let unit = unit(
            Path::new(path),
            Path::new("/var/db/shoesd/applied.json"),
            "wheel",
        );
        let line = unit
            .lines()
            .find(|line| line.starts_with("ExecStart="))
            .expect("one line, not two");
        assert!(line.ends_with('"'), "{line:?}");
        assert!(!line.chars().any(char::is_control), "{line:?}");
        assert_eq!(exec_start_argv(&unit)[3], path, "{unit}");
    }

    /// The start limit is disabled outright.
    ///
    /// Its absence is invisible until a crash loop, and the symptom then is
    /// "the daemon stopped coming back" with nothing pointing at the unit
    /// file. systemd stops restarting a unit that hits the limit -- 5 starts
    /// in 10 s by default -- where launchd throttles and keeps trying, so a
    /// daemon that crash-loops would be abandoned with its exclusion routes
    /// and `/etc/resolv.conf` still applied, on a machine whose network is
    /// down. Recovery runs at the start of the next run, and there would not
    /// be one.
    #[test]
    fn the_unit_never_stops_restarting() {
        let unit = rendered();
        assert!(unit.contains("\nStartLimitIntervalSec=0\n"), "{unit}");

        // In `[Unit]`, which is where `systemd.unit(5)` documents it. In
        // `[Service]` it is a compatibility spelling at best and ignored at
        // worst, which would look identical in a diff and behave like the
        // default.
        let start_limit = unit.find("StartLimitIntervalSec=").expect("present");
        let service = unit.find("[Service]").expect("present");
        assert!(start_limit < service, "{unit}");
    }

    /// And it comes back slowly rather than in a hot loop.
    #[test]
    fn the_unit_restarts_on_its_own() {
        let unit = rendered();
        assert!(unit.contains("\nRestart=always\n"), "{unit}");
        assert!(unit.contains("\nRestartSec=5\n"), "{unit}");
    }

    /// `RuntimeDirectory=` is deliberately absent.
    ///
    /// It would have systemd create `/run/shoesd/` with a mode of its own
    /// choosing before the process starts, and that directory being `0750
    /// root:group` is what closes the window between the socket being bound
    /// and its mode being set -- `socket.rs` owns that decision, and two
    /// owners means neither.
    #[test]
    fn the_unit_does_not_create_the_runtime_directory() {
        let unit = rendered();
        // A directive, not the word: the rendered file carries a comment
        // saying why the directive is absent, and that comment is the thing
        // stopping someone from adding it later.
        assert!(
            !unit
                .lines()
                .any(|line| line.trim_start().starts_with("RuntimeDirectory")),
            "the daemon creates /run/shoesd itself:\n{unit}"
        );
        assert!(
            unit.contains("# Deliberately no RuntimeDirectory="),
            "and the file says why:\n{unit}"
        );
    }

    /// The unit file's name is the name `systemctl` is given, or `install`
    /// enables something other than what it wrote.
    #[test]
    fn the_unit_path_matches_the_label() {
        assert_eq!(UNIT_PATH, format!("/etc/systemd/system/{LABEL}"));
    }

    /// Every tool is named by absolute path: a root process must not resolve a
    /// program through a `PATH` it inherited from whoever ran `sudo`.
    #[test]
    fn every_tool_is_named_absolutely() {
        for candidate in SYSTEMCTL.iter().chain(RESTORECON.iter()) {
            assert!(candidate.starts_with('/'), "{candidate}");
        }
    }

    /// The first candidate that exists wins, and a list that matches nothing
    /// names every path it looked at.
    #[test]
    fn a_tool_is_found_by_existence_and_order() {
        assert_eq!(
            find_tool("null", &["/no/such/tool", "/dev/null"]).expect("/dev/null exists"),
            "/dev/null"
        );
        let err =
            find_tool("nothing", &["/no/such/tool", "/no/such/other"]).expect_err("neither exists");
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
        assert!(err.to_string().contains("/no/such/tool"), "got {err}");
        assert!(err.to_string().contains("/no/such/other"), "got {err}");
    }

    /// A host, as the predicate sees it: which groups exist, and which of
    /// those this uid is in. Written as two lists so a test can express
    /// "exists and is empty", which is the shape a rule stopping at existence
    /// gets wrong.
    fn host(
        exists: &'static [&'static str],
        member_of: &'static [&'static str],
    ) -> impl Fn(&str, u32) -> bool {
        move |name, uid| {
            assert_eq!(uid, 1000, "the predicate is asked about the invoking uid");
            exists.contains(&name) && member_of.contains(&name)
        }
    }

    /// An explicit `--group` is honoured verbatim and never re-derived.
    ///
    /// The bug this pins: `parse_run_args` used to substitute `DEFAULT_GROUP`
    /// when the flag was absent, so by the time the name reached here an
    /// explicit `--group wheel` and no flag at all were the same string. That
    /// made detection run for the one value a Fedora administrator is most
    /// likely to type -- and on a host where `wheel` exists but does not
    /// contain the invoker, an install that named it explicitly would have
    /// failed with "no candidate group contains you" instead of doing as it was
    /// told.
    ///
    /// `install` is the one place someone may legitimately set the daemon up
    /// for a group they are not in themselves, so the explicit path must not
    /// consult the invoker at all.
    #[test]
    fn an_explicit_group_is_taken_as_given() {
        assert_eq!(resolve_group(Some("wheel")).unwrap(), "wheel");
        // Including one no detection would ever choose.
        assert_eq!(resolve_group(Some("staff")).unwrap(), "staff");
    }

    /// The Fedora shape, which is the development host: `wheel` exists and
    /// contains the user, `adm` exists and is empty, `sudo` is absent.
    #[test]
    fn detection_takes_wheel_where_the_user_is_in_it() {
        let chosen = choose_group(1000, host(&["wheel", "adm"], &["wheel"]))
            .expect("wheel contains the user");
        assert_eq!(chosen, "wheel");
    }

    /// The Debian shape: no `wheel` at all, `sudo` is the administrators'
    /// group, and `adm` exists beside it holding whoever may read logs. Order
    /// decides, and `sudo` is the narrower set.
    #[test]
    fn detection_takes_sudo_on_debian() {
        let chosen = choose_group(1000, host(&["sudo", "adm"], &["sudo", "adm"]))
            .expect("sudo contains the user");
        assert_eq!(chosen, "sudo");
    }

    /// The trap: a group that exists and does not contain the user must not be
    /// chosen. `adm` is empty on Fedora, so a rule that stopped at "the group
    /// exists" would answer `adm` here and install a control socket nobody can
    /// reach -- which is indistinguishable, from the app, from a daemon that
    /// is not running.
    #[test]
    fn a_group_that_does_not_contain_the_user_is_not_chosen() {
        let err =
            choose_group(1000, host(&["adm"], &[])).expect_err("an empty adm is not an answer");
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
        assert!(!err.to_string().contains("chose"), "got {err}");
    }

    /// And when nothing matches, the error names all three, because the fix is
    /// to pass one of them -- or a fourth -- to `--group`.
    #[test]
    fn no_candidate_group_names_all_three() {
        let err =
            choose_group(1000, host(&[], &[])).expect_err("a host with none of them must fail");
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
        for candidate in GROUP_CANDIDATES {
            assert!(err.to_string().contains(candidate), "{candidate}: {err}");
        }
    }

    /// `PKEXEC_UID` wins, `SUDO_UID` is the fallback, and something
    /// unreadable in either is not an answer.
    ///
    /// Pure rather than reading the environment, because `set_var` is
    /// process-wide and every other test in the binary is running beside this
    /// one.
    #[test]
    fn the_invoking_uid_prefers_pkexec() {
        assert_eq!(uid_of(Some("1000"), Some("501")), Some(1000));
        assert_eq!(uid_of(None, Some("501")), Some(501));
        assert_eq!(uid_of(Some(""), Some("501")), Some(501));
        assert_eq!(uid_of(Some("nobody"), Some("501")), Some(501));
        assert_eq!(uid_of(None, None), None);
        assert_eq!(uid_of(Some("-1"), None), None);
    }

    /// The real predicate, on the primary-group half: root's primary group is
    /// gid 0, which every Linux calls `root`.
    #[test]
    fn the_real_predicate_answers_for_root() {
        assert!(group_contains("root", 0), "root is in its own group");
        assert!(!group_contains("no-such-group-exists-here", 0));
    }

    /// And on the member-list half, which is the one that matters: an
    /// administrator's *supplementary* groups are where `wheel` and `sudo`
    /// actually are. Skipped on a host running the tests as a user with no
    /// supplementary group -- a CI container as root -- because there is then
    /// nothing to ask about.
    #[test]
    fn the_real_predicate_answers_for_a_supplementary_group() {
        // SAFETY: `getgroups` with a null pointer and count 0 returns how many
        // there are without writing anything; the second call writes exactly
        // that many into a buffer with room for them.
        let (uid, primary, groups) = unsafe {
            let count = libc::getgroups(0, std::ptr::null_mut());
            assert!(count >= 0, "getgroups failed");
            let mut groups = vec![0 as libc::gid_t; count as usize];
            assert_eq!(libc::getgroups(count, groups.as_mut_ptr()), count);
            (libc::geteuid(), libc::getegid(), groups)
        };

        let Some(supplementary) = groups.into_iter().find(|gid| *gid != primary) else {
            return;
        };

        // Copied out before `group_contains` calls into the group database
        // again, which would invalidate this pointer.
        // SAFETY: a gid this process is a member of, so the entry exists; the
        // name is copied before anything else can call into the database.
        let name = unsafe {
            let entry = libc::getgrgid(supplementary);
            assert!(!entry.is_null(), "gid {supplementary} has no group entry");
            std::ffi::CStr::from_ptr((*entry).gr_name).to_owned()
        };
        let name = name.to_str().expect("a group name is UTF-8");

        assert!(
            group_contains(name, uid),
            "uid {uid} is in {name} by getgroups, so the predicate must say so"
        );
    }
}

#[cfg(all(test, target_os = "macos"))]
mod macos_tests {
    use super::*;

    fn rendered() -> String {
        plist(
            Path::new("/var/run/shoesd.sock"),
            Path::new("/var/db/shoesd/applied.json"),
            "admin",
        )
    }

    /// The plist points at the installed copy, never at wherever the
    /// executable happened to be when `install` ran. That path is inside a
    /// user-writable app bundle, and a root daemon on a user-writable binary
    /// is a privilege escalation.
    #[test]
    fn the_plist_runs_the_installed_copy() {
        let plist = rendered();
        assert!(
            plist.contains(&format!("<string>{INSTALLED_BINARY}</string>")),
            "{plist}"
        );
    }

    /// Each argument is its own `<string>`. A single element holding
    /// "run --socket /var/run/shoesd.sock" is one argument containing spaces,
    /// which the daemon would reject -- and the shape that invites someone to
    /// build it by concatenation later.
    #[test]
    fn each_argument_is_a_separate_element() {
        let plist = rendered();
        for argument in [
            "run",
            "--socket",
            "/var/run/shoesd.sock",
            "--state",
            "/var/db/shoesd/applied.json",
            "--group",
            "admin",
        ] {
            assert!(
                plist.contains(&format!("<string>{argument}</string>")),
                "{argument} is not its own element:\n{plist}"
            );
        }
    }

    /// KeepAlive is what makes crash recovery reach a machine whose network is
    /// down -- launchd restarts the daemon within seconds, and recovery runs
    /// before it accepts anything.
    #[test]
    fn the_job_is_kept_alive_and_runs_at_load() {
        let plist = rendered();
        assert!(
            plist.contains("<key>KeepAlive</key>\n    <true/>"),
            "{plist}"
        );
        assert!(
            plist.contains("<key>RunAtLoad</key>\n    <true/>"),
            "{plist}"
        );
    }

    #[test]
    fn the_label_matches_the_plist_filename() {
        assert_eq!(PLIST_PATH, format!("/Library/LaunchDaemons/{LABEL}.plist"));
        assert!(rendered().contains(&format!("<string>{LABEL}</string>")));
    }

    /// The arguments come from what the operator asked for, so a non-default
    /// socket or group has to survive into the job launchd runs.
    #[test]
    fn the_plist_carries_the_arguments_it_was_given() {
        let plist = plist(
            Path::new("/tmp/other.sock"),
            Path::new("/tmp/other.json"),
            "staff",
        );
        assert!(
            plist.contains("<string>/tmp/other.sock</string>"),
            "{plist}"
        );
        assert!(
            plist.contains("<string>/tmp/other.json</string>"),
            "{plist}"
        );
        assert!(plist.contains("<string>staff</string>"), "{plist}");
    }

    /// A path or group name is escaped rather than interpolated raw. `&` is a
    /// legal character in a filename, and a plist that is not well-formed
    /// fails `launchctl bootstrap` with an error naming neither the character
    /// nor the key.
    #[test]
    fn values_are_escaped_into_the_xml() {
        let rendered = plist(
            Path::new("/var/run/a&b.sock"),
            Path::new("/var/db/<state>.json"),
            "ops&admins",
        );
        assert!(
            rendered.contains("<string>/var/run/a&amp;b.sock</string>"),
            "{rendered}"
        );
        assert!(
            rendered.contains("<string>/var/db/&lt;state&gt;.json</string>"),
            "{rendered}"
        );
        assert!(
            rendered.contains("<string>ops&amp;admins</string>"),
            "{rendered}"
        );
        // And nothing raw survives that would break the parse.
        assert!(!rendered.contains("a&b"), "{rendered}");
    }

    /// The log must not be world-readable.
    ///
    /// launchd creates the file it is pointed at as 0644, so the directory is
    /// the only place the mode can be decided in advance. `WatchLogs` filters
    /// per subscriber and does not raise the global level; a log every local
    /// user can read undoes exactly that care.
    #[test]
    fn the_log_lives_in_a_directory_others_cannot_read() {
        assert_eq!(
            LOG_DIR_MODE & 0o007,
            0,
            "world has no access: {LOG_DIR_MODE:o}"
        );
        assert!(
            LOG_PATH.starts_with(&format!("{LOG_DIR}/")),
            "the log has to be inside the directory whose mode is set: {LOG_PATH}"
        );
        assert!(rendered().contains(&format!("<string>{LOG_PATH}</string>")));
        assert!(
            !rendered().contains("<string>/var/log/shoesd.log</string>"),
            "not straight into /var/log, where only launchd decides the mode"
        );
    }

    /// Every tool is named by absolute path: a root process must not resolve a
    /// program through a `PATH` it inherited from whoever ran `sudo`.
    #[test]
    fn launchctl_is_named_absolutely() {
        assert!(LAUNCHCTL.starts_with('/'), "{LAUNCHCTL}");
    }
}
