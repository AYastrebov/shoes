//! `shoesd install` and `shoesd uninstall`.
//!
//! The one rule everything here exists to enforce: **the daemon never runs
//! from the path it was invoked at.** That path is inside a user-writable app
//! bundle, and a root daemon whose binary a user can rewrite is a privilege
//! escalation, not a convenience. `install` copies the executable to a
//! root-owned location and points launchd at the copy.

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
const LOG_DIR: &str = "/var/log/shoesd";
const LOG_PATH: &str = "/var/log/shoesd/shoesd.log";

/// Root reads and writes, the admin group reads, nobody else sees it.
const LOG_DIR_MODE: u32 = 0o750;

/// By absolute path: a root process must not resolve a program through a
/// `PATH` it inherited from whoever ran `sudo`.
const LAUNCHCTL: &str = "/bin/launchctl";

/// Where the daemon runs from once installed. Apple's directory for exactly
/// this: a helper that runs with more privilege than the app that ships it.
pub const INSTALLED_BINARY: &str = "/Library/PrivilegedHelperTools/shoesd";

/// The launchd job. Same namespace as the JNI entry points already use.
pub const LABEL: &str = "com.shoesproxy.daemon";

/// Administrator-provided system daemons, per `man launchd.plist`.
pub const PLIST_PATH: &str = "/Library/LaunchDaemons/com.shoesproxy.daemon.plist";

/// `root:wheel`, and not writable by group or other.
///
/// launchd refuses a job whose plist -- or whose executable -- is group- or
/// world-writable, and says so with a bootstrap error that names neither. This
/// is behaviour rather than documented contract, which is why `install` checks
/// the result of every `chown` and `chmod` rather than assuming they took.
const PLIST_MODE: u32 = 0o644;
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
pub fn install(socket_path: &Path, state_path: &Path, group: &str) -> std::io::Result<()> {
    require_root("install")?;

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

/// `root:wheel`, and the given mode.
fn set_root_owned(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains a NUL byte")
    })?;
    // SAFETY: `c_path` is a valid NUL-terminated string for the call, and both
    // ids are scalars. 0:0 is root:wheel.
    if unsafe { libc::chown(c_path.as_ptr(), 0, 0) } != 0 {
        let e = std::io::Error::last_os_error();
        return Err(std::io::Error::new(
            e.kind(),
            format!("could not chown {} to root:wheel: {e}", path.display()),
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

#[cfg(test)]
mod tests {
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

    /// The staged copy is never writable by anyone but its owner, even for the
    /// instant before its mode is set.
    ///
    /// `std::fs::copy` carries the source's permission bits across, so a
    /// source unpacked with a loose umask would exist group- or
    /// world-writable under a root-owned path -- and the next line renames it
    /// into the binary launchd runs as root.
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

    /// Every tool is named by absolute path: a root process must not resolve a
    /// program through a `PATH` it inherited from whoever ran `sudo`.
    #[test]
    fn launchctl_is_named_absolutely() {
        assert!(LAUNCHCTL.starts_with('/'), "{LAUNCHCTL}");
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
            "admin",
        )
        .expect_err("a non-root install must be refused");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(err.to_string().contains("sudo"), "got {err}");

        let err = uninstall().expect_err("a non-root uninstall must be refused");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    }
}
