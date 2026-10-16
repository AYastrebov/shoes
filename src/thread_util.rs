#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "predates the lint; see the [lints] note in Cargo.toml"
)]

use std::sync::OnceLock;

static NUM_THREADS: OnceLock<usize> = OnceLock::new();

pub fn set_num_threads(num_threads: usize) {
    let _ = NUM_THREADS.set(num_threads);
}

/// The worker count the binary was started with, or, where nothing set it
/// (the library under FFI or `shoesd`), the default the binary would have
/// chosen: the CPU count, and at least two. It used to panic there instead.
pub fn get_num_threads() -> usize {
    *NUM_THREADS.get_or_init(|| {
        std::cmp::max(
            2,
            std::thread::available_parallelism().map_or(1, |n| n.get()),
        )
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn an_unset_count_is_at_least_one() {
        assert!(super::get_num_threads() >= 2);
    }
}
