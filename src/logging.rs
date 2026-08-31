//! Multi-output logging infrastructure.
//!
//! Provides `MultiLogger` which dispatches pre-formatted log lines to multiple
//! `LogWriter` destinations. Formats each record once into a thread-local buffer,
//! then passes the resulting `&str` to all writers.

use std::cell::Cell;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};

use log::{Level, LevelFilter, Log, Metadata, Record};

/// Receives pre-formatted log lines. Implementations handle one output destination.
pub trait LogWriter: Send + Sync {
    /// Writes a pre-formatted log line. `formatted` does NOT include a trailing newline.
    fn write_log(&self, record: &Record, formatted: &str);
    fn flush(&self);
}

/// Writes to stderr with ASCII sanitization to prevent terminal escape sequences.
pub struct StderrWriter;

impl LogWriter for StderrWriter {
    fn write_log(&self, _record: &Record, formatted: &str) {
        let sanitized: String = formatted
            .chars()
            .map(|c| {
                if c.is_ascii_graphic() || c == ' ' {
                    c
                } else {
                    '?'
                }
            })
            .collect();
        let _ = writeln!(std::io::stderr(), "{sanitized}");
    }

    fn flush(&self) {
        let _ = std::io::stderr().flush();
    }
}

/// Bytes a log file may reach before it is rotated to `<path>.old`,
/// replacing the previous rotation. Two files bound the disk cost at about
/// twice this: an unattended machine that wakes into a broken network used
/// to append error lines without limit for as long as nobody looked.
const LOG_ROTATE_BYTES: u64 = 32 * 1024 * 1024;

/// Writes to a file opened at init time. Each log line is a single write() syscall
/// to the kernel page cache (no BufWriter needed -- the kernel handles writeback).
/// Rotates at [`LOG_ROTATE_BYTES`].
pub struct FileLogWriter {
    state: parking_lot::Mutex<FileLogState>,
    path: String,
    rotate_at: u64,
}

struct FileLogState {
    file: File,
    written: u64,
    /// Rotation hit a condition it cannot fix (a symlinked path, a
    /// directory that refuses the rename). Announced once on stderr --
    /// the broken piece here IS the logger -- then rotation stands down
    /// rather than retrying per threshold or, worse, quietly redirecting
    /// the stream into `<path>.old`.
    rotation_broken: bool,
}

impl FileLogWriter {
    pub fn new(path: &str) -> std::io::Result<Self> {
        Self::with_rotation(path, LOG_ROTATE_BYTES)
    }

    /// The threshold is a parameter so tests rotate in bytes, not
    /// megabytes.
    fn with_rotation(path: &str, rotate_at: u64) -> std::io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        // Counted from the existing size: appending to a file already at
        // the cap must rotate on the first write, not a full cap later.
        let written = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(Self {
            state: parking_lot::Mutex::new(FileLogState {
                file,
                written,
                rotation_broken: false,
            }),
            path: path.to_owned(),
            rotate_at,
        })
    }

    fn rotate(&self, state: &mut FileLogState) {
        // A symlinked -l path is a deliberate operator arrangement (a
        // collector, a volume mount): fs::rename would rotate the LINK
        // itself away and plant a plain file at the configured path,
        // permanently silencing whatever tails the real destination.
        // Refuse, announce once, and let the file grow -- the operator
        // who linked it manages it.
        let is_symlink = std::fs::symlink_metadata(&self.path)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false);
        if is_symlink {
            self.break_rotation(state, "the path is a symlink");
            return;
        }

        // The stale rotation goes first: on Windows, fs::rename refuses
        // an existing destination, so without this the SECOND rotation
        // ever would fail and stand rotation down for good -- "replacing
        // the previous rotation" held for exactly one cycle. On Unix the
        // rename replaces anyway and the remove is a harmless no-op.
        let old = format!("{}.old", self.path);
        let _ = std::fs::remove_file(&old);

        // Rename-then-reopen: on Unix the rename succeeds under the open
        // descriptor; failures here mean the DIRECTORY refuses it (a 0755
        // root-owned dir, Windows lock semantics). Standing down beats
        // pretending: resetting the counter regardless grew the file
        // without bound in silent 32 MiB steps.
        if let Err(e) = std::fs::rename(&self.path, &old) {
            self.break_rotation(state, &format!("rename failed: {e}"));
            return;
        }
        match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            Ok(file) => {
                state.file = file;
                state.written = 0;
            }
            Err(e) => {
                // The stream currently points at the inode now named
                // `.old`; undo the rename so the configured path stays
                // the live log. If even that fails, the old handle keeps
                // every line -- misnamed but not lost -- and rotation
                // stands down either way.
                let _ = std::fs::rename(&old, &self.path);
                self.break_rotation(state, &format!("reopen failed: {e}"));
            }
        }
    }

    /// Give up on rotating this file, once and audibly.
    fn break_rotation(&self, state: &mut FileLogState, why: &str) {
        if !state.rotation_broken {
            state.rotation_broken = true;
            eprintln!(
                "shoes: log rotation disabled for {}: {why}; the file will grow unbounded",
                self.path
            );
        }
    }
}

impl LogWriter for FileLogWriter {
    fn write_log(&self, _record: &Record, formatted: &str) {
        let mut guard = self.state.lock();
        let mut line = formatted.to_string();
        line.push('\n');
        // Counted only when the write landed: 32 MiB of ENOSPC failures
        // advancing the counter rotated a stale file over the .old that
        // held the last lines written before the disk filled -- the
        // evidence of the outage, destroyed to make room for nothing.
        if guard.file.write_all(line.as_bytes()).is_ok() {
            guard.written += line.len() as u64;
        }
        if guard.written >= self.rotate_at && !guard.rotation_broken {
            self.rotate(&mut guard);
        }
    }

    fn flush(&self) {
        let _ = self.state.lock().file.flush();
    }
}

/// Writes to a file that may be set after logger init (FFI use case).
/// References a global `OnceLock<parking_lot::Mutex<Option<File>>>`.
// Used by iOS/Android FFI targets (ffi/ios.rs, ffi/android.rs).
#[allow(dead_code)]
pub struct DynamicFileLogWriter {
    file: &'static std::sync::OnceLock<parking_lot::Mutex<Option<File>>>,
}

// Used by iOS/Android FFI targets (ffi/ios.rs, ffi/android.rs).
#[allow(dead_code)]
impl DynamicFileLogWriter {
    pub fn new(file: &'static std::sync::OnceLock<parking_lot::Mutex<Option<File>>>) -> Self {
        Self { file }
    }
}

impl LogWriter for DynamicFileLogWriter {
    fn write_log(&self, _record: &Record, formatted: &str) {
        if let Some(mutex) = self.file.get() {
            let mut guard = mutex.lock();
            if let Some(ref mut file) = *guard {
                let mut line = formatted.to_string();
                line.push('\n');
                let _ = file.write_all(line.as_bytes());
            }
        }
    }

    fn flush(&self) {
        if let Some(mutex) = self.file.get() {
            let mut guard = mutex.lock();
            if let Some(ref mut file) = *guard {
                let _ = file.flush();
            }
        }
    }
}

thread_local! {
    static FMT_BUF: Cell<String> = Cell::new(String::with_capacity(256));
}

/// A filter directive: optional target prefix + level.
/// When `name` is None, matches all targets (acts as the default level).
pub struct Directive {
    pub name: Option<String>,
    pub level: LevelFilter,
}

/// A level that replaces the configured directives while it is set.
///
/// Stored as `level as usize + 1` so that zero can mean "not set". Only the
/// mobile FFI writes it: an app that has to reproduce a bug with debug logging
/// on would otherwise have to be killed and relaunched, because `init` reads
/// the level exactly once.
static LEVEL_OVERRIDE: AtomicUsize = AtomicUsize::new(0);

/// Override the configured levels for every target.
///
/// Note that `log` is built with `release_max_level_info`, so `Debug` and
/// `Trace` are compiled out of release binaries; raising the level past `Info`
/// only does anything in a build that keeps them.
// Called from the mobile FFI, which the desktop binary does not compile.
#[allow(dead_code)]
pub fn set_log_level(level: LevelFilter) {
    LEVEL_OVERRIDE.store(level as usize + 1, Ordering::Relaxed);
    log::set_max_level(level);
    // The host app cannot see stderr, so this goes through the log pipeline it
    // is already reading. Warn is at or below the compiled ceiling in every
    // build, so the message itself always survives - otherwise the one line
    // explaining the silence would be compiled out along with the debug logs.
    if level > log::STATIC_MAX_LEVEL {
        log::warn!(
            "Log level {level} is set, but this build compiles out anything above {}, so no additional lines will appear.",
            log::STATIC_MAX_LEVEL
        );
    }
}

fn level_override() -> Option<LevelFilter> {
    match LEVEL_OVERRIDE.load(Ordering::Relaxed) {
        0 => None,
        raw => LevelFilter::iter().nth(raw - 1),
    }
}

/// Dispatches formatted log lines to multiple `LogWriter` destinations.
/// Filters records using env_logger-compatible directive matching.
pub struct MultiLogger {
    writers: Vec<Box<dyn LogWriter>>,
    /// Sorted by name length ascending; walked in reverse for longest-prefix match.
    directives: Vec<Directive>,
}

impl MultiLogger {
    fn matches(&self, level: Level, target: &str) -> bool {
        if let Some(override_level) = level_override() {
            return level <= override_level;
        }

        for directive in self.directives.iter().rev() {
            match &directive.name {
                Some(name) if !target.starts_with(name.as_str()) => continue,
                _ => return level <= directive.level,
            }
        }
        false
    }
}

impl Log for MultiLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        self.matches(metadata.level(), metadata.target())
    }

    fn log(&self, record: &Record) {
        if !self.matches(record.level(), record.target()) {
            return;
        }

        FMT_BUF.with(|cell| {
            let mut buf = cell.take();
            buf.clear();

            use std::fmt::Write as FmtWrite;
            let timestamp = chrono::Local::now().format("%Y-%m-%dT%H:%M:%S%.3f");
            let _ = write!(
                buf,
                "[{} {} {}] {}",
                timestamp,
                record.level(),
                record.target(),
                record.args()
            );

            for writer in &self.writers {
                writer.write_log(record, &buf);
            }

            cell.set(buf);
        });
    }

    fn flush(&self) {
        for writer in &self.writers {
            writer.flush();
        }
    }
}

/// Installs a `MultiLogger` as the global logger.
/// Directives are sorted by name length; `log::set_max_level` is set to the
/// maximum level across all directives so records reach our `log()` method.
pub fn init_multi_logger(writers: Vec<Box<dyn LogWriter>>, mut directives: Vec<Directive>) {
    directives.sort_by_key(|d| d.name.as_ref().map_or(0, |n| n.len()));
    let max_level = directives
        .iter()
        .map(|d| d.level)
        .max()
        .unwrap_or(LevelFilter::Off);
    warn_if_level_is_compiled_out(max_level);
    let logger = MultiLogger {
        writers,
        directives,
    };
    log::set_boxed_logger(Box::new(logger)).expect("logger already initialized");
    log::set_max_level(max_level);
}

/// Say so when the requested level cannot be emitted by this build.
///
/// `log` is built with `release_max_level_info`, so a release binary has its
/// `debug!` and `trace!` calls compiled out entirely — asking for them through
/// `RUST_LOG` or a marker file changes the filter and still produces nothing.
/// Without this warning the binary reports "setting log level to DEBUG" and
/// then stays silent, which reads as a broken logger rather than a build that
/// cannot carry those levels. Diagnosing that from the outside costs an hour.
fn warn_if_level_is_compiled_out(requested: LevelFilter) {
    let compiled_in = log::STATIC_MAX_LEVEL;
    if requested > compiled_in {
        eprintln!(
            "Requested log level {requested} is not available in this build: log is compiled \
             with a maximum of {compiled_in}, so debug and trace calls do not exist in the \
             binary. Build without the release_max_level_info feature, or use a debug build, \
             to see them."
        );
    }
}

/// Routes panics through the logger instead of stderr, then flushes.
///
/// The default hook writes to stderr, which on Android goes nowhere and on iOS
/// goes somewhere nobody reads. Under the `release-mobile` profile the process
/// aborts the instant this returns, so anything still sitting in the log file's
/// buffer is lost — hence the explicit flush.
///
/// Call this after `init_multi_logger`; a panic before the logger exists still
/// reaches stderr through the default hook.
pub fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        match info.location() {
            Some(location) => log::error!(
                "panic at {}:{}:{}: {}",
                location.file(),
                location.line(),
                location.column(),
                panic_message(info.payload())
            ),
            None => log::error!(
                "panic at an unknown location: {}",
                panic_message(info.payload())
            ),
        }

        log::logger().flush();
    }));
}

/// Recovers the text of a panic payload.
///
/// `PanicHookInfo::message()` is unstable, so the payload has to be downcast by
/// hand. `&str` covers `panic!("literal")` and the messages `unwrap` and
/// `expect` produce; `String` covers `panic!("{}", x)`. A payload from
/// `panic_any` can be any type at all, and there is nothing to print for it.
fn panic_message(payload: &(dyn std::any::Any + Send)) -> &str {
    payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("<non-string panic payload>")
}

/// Parses a level string (case-insensitive). Returns `None` for unrecognized values.
pub fn parse_log_level(s: &str) -> Option<LevelFilter> {
    match s.to_lowercase().as_str() {
        "error" => Some(LevelFilter::Error),
        "warn" => Some(LevelFilter::Warn),
        "info" => Some(LevelFilter::Info),
        "debug" => Some(LevelFilter::Debug),
        "trace" => Some(LevelFilter::Trace),
        "off" => Some(LevelFilter::Off),
        _ => None,
    }
}

/// Parses a RUST_LOG-style directive string.
/// Examples: "info", "shoes=info", "warn,shoes=debug,quinn=error"
fn parse_directives(spec: &str) -> Vec<Directive> {
    let mut directives = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((name, level_str)) = part.split_once('=') {
            if let Some(level) = parse_log_level(level_str) {
                directives.push(Directive {
                    name: Some(name.to_owned()),
                    level,
                });
            }
        } else if let Some(level) = parse_log_level(part) {
            directives.push(Directive { name: None, level });
        }
    }
    if directives.is_empty() {
        directives.push(Directive {
            name: None,
            level: LevelFilter::Error,
        });
    }
    directives
}

/// Determines filter directives from (in priority order):
/// 1. `.shoes-trace` / `.shoes-debug` marker files next to the binary
/// 2. `RUST_LOG` environment variable (supports `target=level` syntax)
/// 3. Default: error only (matches env_logger)
pub fn resolve_directives() -> Vec<Directive> {
    if let Some(dir) = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
    {
        if dir.join(".shoes-trace").exists() {
            eprintln!("Found marker file .shoes-trace, setting log level to TRACE");
            return vec![Directive {
                name: None,
                level: LevelFilter::Trace,
            }];
        }
        if dir.join(".shoes-debug").exists() {
            eprintln!("Found marker file .shoes-debug, setting log level to DEBUG");
            return vec![Directive {
                name: None,
                level: LevelFilter::Debug,
            }];
        }
    }

    if let Ok(val) = std::env::var("RUST_LOG") {
        return parse_directives(&val);
    }

    vec![Directive {
        name: None,
        level: LevelFilter::Error,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use log::Level;

    /// Builds a MultiLogger (no writers) from directives for testing matches().
    fn logger_from(mut directives: Vec<Directive>) -> MultiLogger {
        directives.sort_by_key(|d| d.name.as_ref().map_or(0, |n| n.len()));
        MultiLogger {
            writers: vec![],
            directives,
        }
    }

    #[test]
    fn parse_log_level_valid() {
        assert_eq!(parse_log_level("info"), Some(LevelFilter::Info));
        assert_eq!(parse_log_level("ERROR"), Some(LevelFilter::Error));
        assert_eq!(parse_log_level("Debug"), Some(LevelFilter::Debug));
        assert_eq!(parse_log_level("off"), Some(LevelFilter::Off));
    }

    #[test]
    fn parse_log_level_invalid() {
        assert_eq!(parse_log_level(""), None);
        assert_eq!(parse_log_level("verbose"), None);
        assert_eq!(parse_log_level("inf"), None);
    }

    #[test]
    fn parse_directives_blanket_level() {
        let dirs = parse_directives("info");
        assert_eq!(dirs.len(), 1);
        assert!(dirs[0].name.is_none());
        assert_eq!(dirs[0].level, LevelFilter::Info);
    }

    #[test]
    fn parse_directives_single_target() {
        let dirs = parse_directives("shoes=debug");
        assert_eq!(dirs.len(), 1);
        assert_eq!(dirs[0].name.as_deref(), Some("shoes"));
        assert_eq!(dirs[0].level, LevelFilter::Debug);
    }

    #[test]
    fn parse_directives_mixed() {
        let dirs = parse_directives("warn,shoes=info,quinn=error");
        assert_eq!(dirs.len(), 3);
        // Should contain a blanket warn and two targeted directives
        let blanket = dirs.iter().find(|d| d.name.is_none()).unwrap();
        assert_eq!(blanket.level, LevelFilter::Warn);
        let shoes = dirs
            .iter()
            .find(|d| d.name.as_deref() == Some("shoes"))
            .unwrap();
        assert_eq!(shoes.level, LevelFilter::Info);
        let quinn = dirs
            .iter()
            .find(|d| d.name.as_deref() == Some("quinn"))
            .unwrap();
        assert_eq!(quinn.level, LevelFilter::Error);
    }

    #[test]
    fn parse_directives_empty_falls_back_to_error() {
        let dirs = parse_directives("");
        assert_eq!(dirs.len(), 1);
        assert!(dirs[0].name.is_none());
        assert_eq!(dirs[0].level, LevelFilter::Error);
    }

    #[test]
    fn parse_directives_invalid_level_skipped() {
        let dirs = parse_directives("shoes=bogus,info");
        // "shoes=bogus" is skipped, "info" is kept
        assert_eq!(dirs.len(), 1);
        assert!(dirs[0].name.is_none());
        assert_eq!(dirs[0].level, LevelFilter::Info);
    }

    #[test]
    fn matches_blanket_error_default() {
        let logger = logger_from(vec![Directive {
            name: None,
            level: LevelFilter::Error,
        }]);
        assert!(logger.matches(Level::Error, "shoes::tcp"));
        assert!(!logger.matches(Level::Warn, "shoes::tcp"));
        assert!(!logger.matches(Level::Info, "shoes::tcp"));
        assert!(logger.matches(Level::Error, "quinn::connection"));
    }

    #[test]
    fn matches_blanket_info() {
        let logger = logger_from(vec![Directive {
            name: None,
            level: LevelFilter::Info,
        }]);
        assert!(logger.matches(Level::Error, "shoes"));
        assert!(logger.matches(Level::Warn, "quinn"));
        assert!(logger.matches(Level::Info, "shoes::tcp"));
        assert!(!logger.matches(Level::Debug, "shoes::tcp"));
    }

    #[test]
    fn matches_targeted_only() {
        // shoes=info with no blanket → only shoes passes, others filtered out
        let logger = logger_from(vec![Directive {
            name: Some("shoes".into()),
            level: LevelFilter::Info,
        }]);
        assert!(logger.matches(Level::Info, "shoes::tcp"));
        assert!(logger.matches(Level::Error, "shoes"));
        assert!(!logger.matches(Level::Info, "quinn::connection"));
        assert!(!logger.matches(Level::Error, "rustls"));
    }

    #[test]
    fn matches_blanket_plus_override() {
        // warn,shoes=debug → shoes gets debug, everything else gets warn
        let logger = logger_from(parse_directives("warn,shoes=debug"));
        assert!(logger.matches(Level::Debug, "shoes::tcp"));
        assert!(logger.matches(Level::Info, "shoes"));
        assert!(logger.matches(Level::Warn, "quinn"));
        assert!(!logger.matches(Level::Info, "quinn"));
        assert!(!logger.matches(Level::Debug, "rustls"));
        assert!(logger.matches(Level::Error, "rustls"));
    }

    #[test]
    fn matches_longest_prefix_wins() {
        // shoes=warn,shoes::tcp=debug → shoes::tcp gets debug, shoes gets warn
        let logger = logger_from(parse_directives("shoes=warn,shoes::tcp=debug"));
        assert!(logger.matches(Level::Debug, "shoes::tcp"));
        assert!(logger.matches(Level::Debug, "shoes::tcp::handler"));
        assert!(!logger.matches(Level::Debug, "shoes::config"));
        assert!(logger.matches(Level::Warn, "shoes::config"));
        assert!(!logger.matches(Level::Info, "shoes::config"));
    }

    #[test]
    fn matches_off_suppresses() {
        let logger = logger_from(vec![Directive {
            name: None,
            level: LevelFilter::Off,
        }]);
        assert!(!logger.matches(Level::Error, "shoes"));
        assert!(!logger.matches(Level::Error, "anything"));
    }

    #[test]
    fn matches_no_directives() {
        let logger = logger_from(vec![]);
        assert!(!logger.matches(Level::Error, "shoes"));
    }

    /// The payloads the hook has to render. Under `panic = "abort"` this text
    /// is the only account of why the process died, so an unwrap that reports
    /// nothing but "<non-string panic payload>" would be a silent loss.
    #[test]
    // The literal `None.unwrap()` and `None.expect()` below are the point of
    // the test — they are how the panics this hook has to render actually get
    // produced — so clippy's advice to replace them with `panic!` is backwards
    // here.
    #[allow(clippy::unnecessary_literal_unwrap)]
    fn panic_message_recovers_the_payload_text() {
        let from_literal = std::panic::catch_unwind(|| panic!("a string literal")).unwrap_err();
        assert_eq!(panic_message(from_literal.as_ref()), "a string literal");

        let value = 7;
        let formatted = std::panic::catch_unwind(move || panic!("formatted {value}")).unwrap_err();
        assert_eq!(panic_message(formatted.as_ref()), "formatted 7");

        let from_expect = std::panic::catch_unwind(|| {
            Option::<u8>::None.expect("the expect message");
        })
        .unwrap_err();
        assert_eq!(panic_message(from_expect.as_ref()), "the expect message");

        let from_unwrap = std::panic::catch_unwind(|| Option::<u8>::None.unwrap()).unwrap_err();
        assert!(
            panic_message(from_unwrap.as_ref()).contains("unwrap"),
            "an unwrap should still describe itself"
        );
    }

    #[test]
    fn panic_message_falls_back_for_a_foreign_payload() {
        let payload = std::panic::catch_unwind(|| std::panic::panic_any(42u32)).unwrap_err();
        assert_eq!(
            panic_message(payload.as_ref()),
            "<non-string panic payload>"
        );
    }

    /// The build's compiled-in ceiling is what decides whether a requested
    /// level can produce output at all. In a test build debug and trace exist,
    /// so nothing is above the ceiling; in a release build they do not, and
    /// asking for them warrants the warning. Pin the comparison rather than
    /// the message, so the rule survives a reword.
    #[test]
    fn test_a_level_above_the_compiled_ceiling_is_detected() {
        let ceiling = log::STATIC_MAX_LEVEL;
        assert!(
            LevelFilter::Error <= ceiling,
            "error must always be emittable"
        );

        // Whatever the ceiling is, one step past it is not emittable.
        let past_ceiling = LevelFilter::iter().find(|level| *level > ceiling);
        match past_ceiling {
            Some(level) => assert!(level > ceiling),
            // A build with Trace compiled in has nothing past the ceiling.
            None => assert_eq!(ceiling, LevelFilter::Trace),
        }
    }

    /// -l wrote a file that grew forever; the writer must rotate at its
    /// threshold and keep writing to a fresh file.
    #[test]
    fn the_file_writer_rotates_at_the_threshold() {
        let dir = std::env::temp_dir().join(format!("shoes-log-rotate-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.log");
        let path_str = path.to_str().unwrap();

        let writer = FileLogWriter::with_rotation(path_str, 64).unwrap();
        for _ in 0..10 {
            writer.write_log(
                &Record::builder().args(format_args!("")).build(),
                "a-sixteen-byte-l",
            );
        }

        let old = format!("{path_str}.old");
        assert!(
            std::path::Path::new(&old).exists(),
            "rotation never happened"
        );
        // The live file was reopened fresh: smaller than the threshold even
        // though ten times it was written in total.
        assert!(std::fs::metadata(path_str).unwrap().len() < 64);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The second rotation must succeed too: it replaces the previous
    /// `.old`, which on Windows requires removing it first -- fs::rename
    /// there refuses an existing destination, and without the removal
    /// rotation worked for exactly one cycle before standing down.
    #[test]
    fn the_second_rotation_replaces_the_first() {
        let dir = std::env::temp_dir().join(format!("shoes-log-rot2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.log");
        let path_str = path.to_str().unwrap();

        let writer = FileLogWriter::with_rotation(path_str, 64).unwrap();
        for _ in 0..10 {
            writer.write_log(
                &Record::builder().args(format_args!("")).build(),
                "a-sixteen-byte-l",
            );
        }
        let first_old = std::fs::metadata(format!("{path_str}.old"))
            .unwrap()
            .modified()
            .unwrap();
        for _ in 0..10 {
            writer.write_log(
                &Record::builder().args(format_args!("")).build(),
                "a-sixteen-byte-l",
            );
        }

        let second_old = std::fs::metadata(format!("{path_str}.old"))
            .unwrap()
            .modified()
            .unwrap();
        assert!(second_old >= first_old, "the .old was not replaced");
        // Rotation is still live, not stood down.
        assert!(std::fs::metadata(path_str).unwrap().len() < 64);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A symlinked -l path must never be rotated: renaming the LINK away
    /// plants a plain file at the configured path and permanently
    /// silences whatever tails the real destination.
    #[test]
    #[cfg(unix)]
    fn a_symlinked_log_path_is_never_rotated() {
        let dir = std::env::temp_dir().join(format!("shoes-log-symlink-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("real.log");
        let link = dir.join("link.log");
        std::fs::write(&target, b"").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let writer = FileLogWriter::with_rotation(link.to_str().unwrap(), 64).unwrap();
        for _ in 0..10 {
            writer.write_log(
                &Record::builder().args(format_args!("")).build(),
                "a-sixteen-byte-l",
            );
        }

        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink(),
            "the link was rotated away"
        );
        assert!(
            !std::path::Path::new(&format!("{}.old", link.to_str().unwrap())).exists(),
            "a rotation happened despite the symlink"
        );
        // Every line still reached the real destination through the link.
        assert!(std::fs::metadata(&target).unwrap().len() >= 170);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// When the directory refuses the rename, rotation stands down
    /// instead of resetting the counter and growing the file in silent
    /// threshold-sized steps -- and instead of redirecting the stream.
    #[test]
    #[cfg(unix)]
    fn a_refused_rename_stands_rotation_down_but_keeps_logging() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("shoes-log-noren-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.log");
        let path_str = path.to_str().unwrap();

        let writer = FileLogWriter::with_rotation(path_str, 64).unwrap();
        // Directory read-only: appends to the open file still work, the
        // rename cannot.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();
        for _ in 0..10 {
            writer.write_log(
                &Record::builder().args(format_args!("")).build(),
                "a-sixteen-byte-l",
            );
        }
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();

        assert!(
            !std::path::Path::new(&format!("{path_str}.old")).exists(),
            "a rotation happened despite the refused rename"
        );
        // Every line landed in the one file; nothing was lost or moved.
        assert!(std::fs::metadata(&path).unwrap().len() >= 170);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
