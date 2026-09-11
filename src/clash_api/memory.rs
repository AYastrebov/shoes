//! Resident set size, from the OS.
//!
//! Not the allocator's own accounting: the library does not choose the
//! allocator, only `main.rs` does, and a figure that means something on the
//! CLI and nothing in a library host is worse than an OS figure that means
//! the same everywhere. See the spec, "Traffic and memory".

/// Bytes of this process resident in memory, or 0 where the OS does not say.
#[cfg(target_os = "linux")]
pub fn rss() -> u64 {
    // Field 2 of /proc/self/statm is the resident set, in pages.
    let Ok(statm) = std::fs::read_to_string("/proc/self/statm") else {
        return 0;
    };
    let pages: u64 = statm
        .split_whitespace()
        .nth(1)
        .and_then(|p| p.parse().ok())
        .unwrap_or(0);
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    pages * page_size.max(0) as u64
}

#[cfg(target_os = "macos")]
pub fn rss() -> u64 {
    let mut info: libc::mach_task_basic_info = unsafe { std::mem::zeroed() };
    let mut count = libc::MACH_TASK_BASIC_INFO_COUNT;
    // SAFETY: `info` is the struct this flavour writes, and `count` is its
    // documented size in words; both are checked by the kernel.
    //
    // `allow(deprecated)`: libc deprecates its whole mach surface in favour
    // of the `mach2` crate. The symbol is a kernel one and is not going
    // anywhere; a dependency for one read on the platform this endpoint
    // exists to serve least -- a router runs Linux -- is the worse trade.
    #[allow(deprecated)]
    let kr = unsafe {
        libc::task_info(
            libc::mach_task_self_,
            libc::MACH_TASK_BASIC_INFO,
            &mut info as *mut libc::mach_task_basic_info as libc::task_info_t,
            &mut count,
        )
    };
    if kr == libc::KERN_SUCCESS {
        info.resident_size
    } else {
        0
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn rss() -> u64 {
    0
}

#[cfg(test)]
mod tests {
    /// A live process is resident somewhere, so on the platforms that
    /// answer, the answer is not zero. Elsewhere zero is the documented
    /// "this OS does not say".
    #[test]
    fn a_running_process_has_a_resident_size() {
        let rss = super::rss();
        if cfg!(any(target_os = "linux", target_os = "macos")) {
            assert!(rss > 0, "expected a resident size, got {rss}");
        } else {
            assert_eq!(rss, 0);
        }
    }
}
