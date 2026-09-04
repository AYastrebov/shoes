//! Who may talk to the daemon.
//!
//! The socket's peer credentials are the whole authentication story: there is
//! no token and no TLS, because a Unix socket already carries an unforgeable
//! uid from the kernel and anything layered on top would be a second, weaker
//! answer to a question already settled.
//!
//! The rule is `uid == 0`, or membership of one group named at install time.
//! A rejected caller gets `PERMISSION_DENIED` as a status rather than a
//! dropped connection -- a dropped socket is indistinguishable from a daemon
//! that is not running, and a client that cannot tell the difference offers to
//! install one that is already there.

use std::ffi::{CStr, CString};

/// The group whose members may connect, resolved once at startup.
#[derive(Debug, Clone, Copy)]
pub struct Authorizer {
    group_gid: u32,
}

impl Authorizer {
    /// Resolve a group name to its gid.
    ///
    /// At startup, so that a misspelled group is a refusal to start rather
    /// than a daemon that is running and rejects everyone.
    pub fn for_group(name: &str) -> std::io::Result<Self> {
        let c_name = CString::new(name).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("group name {name:?} contains a NUL byte"),
            )
        })?;

        // SAFETY: `getgrnam` reads the passed pointer, which is a valid
        // NUL-terminated string for the length of this call. The returned
        // pointer is to a static buffer this function copies out of before
        // returning; it is not stored.
        let entry = unsafe { libc::getgrnam(c_name.as_ptr()) };
        if entry.is_null() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("no such group: {name:?}"),
            ));
        }
        // SAFETY: checked non-null above.
        let group_gid = unsafe { (*entry).gr_gid };

        Ok(Self { group_gid })
    }

    /// The resolved gid, for logging what the daemon actually granted.
    pub fn group_gid(&self) -> u32 {
        self.group_gid
    }

    /// An authorizer for a gid directly, skipping the name lookup.
    ///
    /// For the service tests, which need a group the user running them is
    /// actually in and cannot know its name -- that varies by machine and by
    /// CI runner.
    #[cfg(test)]
    pub fn for_gid(group_gid: u32) -> Self {
        Self { group_gid }
    }

    /// Whether a peer may call.
    pub fn allows(&self, uid: u32, primary_gid: u32) -> bool {
        authorize(uid, primary_gid, self.group_gid, |uid| {
            groups_of(uid, primary_gid)
        })
    }
}

/// The decision, with the group lookup injected so it can be tested without
/// depending on the accounts that happen to exist on the machine running the
/// tests.
fn authorize(
    uid: u32,
    primary_gid: u32,
    group_gid: u32,
    groups_of: impl Fn(u32) -> Vec<u32>,
) -> bool {
    // Root is already able to do everything the daemon can do; refusing it
    // would protect nothing and would lock out `launchctl`-driven tooling.
    if uid == 0 {
        return true;
    }
    if primary_gid == group_gid {
        return true;
    }
    // Only now, because this is the branch that costs a passwd lookup and two
    // allocations, and the common caller matches on its primary group.
    groups_of(uid).contains(&group_gid)
}

/// Every group a uid belongs to, primary and supplementary.
///
/// `UCred` carries only the peer's primary gid, and a member of `admin` very
/// often has it as a supplementary group instead -- on macOS a user's primary
/// group is `staff`. Checking only the primary gid would therefore reject
/// almost every administrator, which is the failure this exists to prevent.
///
/// `basegid` is the peer's real primary gid, and passing anything else is a
/// hole rather than a detail: `getgrouplist` echoes the base gid back in the
/// list it fills, so passing a fixed `0` would report every caller as a member
/// of gid 0 -- and gid 0 is `wheel`, a plausible thing to configure `--group`
/// as. The daemon would then admit every user on the machine.
///
/// An empty vector on any failure. That is the safe direction: it can only
/// deny, never grant.
fn groups_of(uid: u32, basegid: u32) -> Vec<u32> {
    let Some(name) = username_of(uid) else {
        return Vec::new();
    };

    // The buffer grows geometrically rather than trusting the count the call
    // writes back on failure. Darwin and Linux disagree about what that count
    // means -- one reports the space required, the other what it managed to
    // fill -- so asking again at the size just reported can repeat the same
    // failure forever, which on Darwin locks out anyone in more than 32
    // groups. Doubling is correct under either reading.
    //
    // The cap is a real ceiling rather than a formality: this runs inside a
    // per-call authorization check, and an unbounded loop there is a way to
    // hang the daemon.
    let mut capacity: libc::c_int = 32;
    loop {
        let mut count = capacity;
        let mut gids: Vec<libc::c_int> = vec![0; capacity as usize];

        // SAFETY: `name` is a valid NUL-terminated string, and `gids` has
        // `capacity` writable elements with `count` saying so. `getgrouplist`
        // writes at most that many.
        let rc = unsafe {
            libc::getgrouplist(
                name.as_ptr(),
                basegid as libc::c_int,
                gids.as_mut_ptr(),
                &mut count,
            )
        };

        if rc != -1 {
            gids.truncate(count.clamp(0, capacity) as usize);
            return gids.into_iter().map(|gid| gid as u32).collect();
        }

        if capacity >= MAX_GROUPS {
            log::warn!(
                "uid {uid} is in more than {MAX_GROUPS} groups; refusing rather than guessing"
            );
            return Vec::new();
        }
        capacity = (capacity * 2).min(MAX_GROUPS);
    }
}

/// Ceiling on the group list one uid can have.
///
/// Well past anything real, and it exists so that a lookup which keeps failing
/// ends rather than spins inside an authorization check.
const MAX_GROUPS: libc::c_int = 8192;

/// The login name for a uid.
///
/// `getpwuid_r`, not `getpwuid`. The plain form returns a pointer into a
/// shared static, and this runs per gRPC call on tonic's worker threads --
/// where the supplementary-group path is the *common* one, since a macOS
/// administrator's primary group is `staff` and `admin` is supplementary. Two
/// concurrent calls would race the read of `pw_name`.
///
/// `None` for a uid with no account, which the caller turns into a refusal.
fn username_of(uid: u32) -> Option<CString> {
    // The suggested size, or what most libcs use when sysconf declines.
    // SAFETY: a scalar argument and no pointers.
    let suggested = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let mut capacity = if suggested > 0 {
        suggested as usize
    } else {
        4096
    };

    loop {
        // SAFETY: `passwd` is only read after `getpwuid_r` reports success,
        // which is what fills it.
        let mut passwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        let mut buffer = vec![0 as libc::c_char; capacity];

        // SAFETY: `passwd` and `result` are valid out-parameters and `buffer`
        // has `capacity` writable bytes. On success `result` points at
        // `passwd`, whose `pw_name` borrows `buffer` -- still alive where it
        // is copied out below.
        let rc = unsafe {
            libc::getpwuid_r(
                uid as libc::uid_t,
                &mut passwd,
                buffer.as_mut_ptr(),
                capacity,
                &mut result,
            )
        };

        if rc == 0 {
            if result.is_null() {
                return None;
            }
            // SAFETY: `result` is non-null, so `pw_name` is a NUL-terminated
            // string inside `buffer`; `to_owned` copies it before `buffer` is
            // dropped.
            return Some(unsafe { CStr::from_ptr(passwd.pw_name) }.to_owned());
        }

        // ERANGE is the only failure worth another try, and only up to a point.
        if rc != libc::ERANGE || capacity >= 1 << 20 {
            return None;
        }
        capacity *= 2;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADMIN: u32 = 80;
    const STAFF: u32 = 20;

    fn no_groups(_uid: u32) -> Vec<u32> {
        Vec::new()
    }

    #[test]
    fn root_is_allowed() {
        assert!(authorize(0, 0, ADMIN, no_groups));
        // Even when root's groups say nothing about the configured one.
        assert!(authorize(0, STAFF, ADMIN, no_groups));
    }

    #[test]
    fn a_primary_group_match_is_allowed() {
        assert!(authorize(501, ADMIN, ADMIN, no_groups));
    }

    /// The case that matters on macOS: an administrator's *primary* group is
    /// `staff`, and `admin` is supplementary. `UCred` reports only the
    /// primary one, so a check that stopped there would reject every
    /// administrator on the machine.
    #[test]
    fn a_supplementary_group_match_is_allowed() {
        assert!(authorize(501, STAFF, ADMIN, |uid| {
            assert_eq!(uid, 501);
            vec![STAFF, ADMIN]
        }));
    }

    #[test]
    fn an_unrelated_user_is_refused() {
        assert!(!authorize(501, STAFF, ADMIN, |_| vec![STAFF, 12, 61]));
    }

    /// A lookup that fails must deny rather than grant. It returns an empty
    /// list, and this pins that an empty list is a refusal.
    #[test]
    fn a_failed_group_lookup_denies() {
        assert!(!authorize(501, STAFF, ADMIN, no_groups));
    }

    /// A group that does not exist is a startup failure, not a daemon that
    /// runs and refuses everyone.
    #[test]
    fn an_unknown_group_does_not_resolve() {
        let err = Authorizer::for_group("no-such-group-exists-here")
            .expect_err("an unknown group must not resolve");
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn a_group_name_with_a_nul_is_refused() {
        let err = Authorizer::for_group("adm\0in").expect_err("NUL is not a group name");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    /// `wheel` is gid 0 on every Unix this runs on, so it is a name the test
    /// host is guaranteed to have.
    #[test]
    fn a_known_group_resolves() {
        let wheel = Authorizer::for_group("wheel").expect("wheel exists on Unix");
        assert_eq!(wheel.group_gid(), 0);
    }
}
