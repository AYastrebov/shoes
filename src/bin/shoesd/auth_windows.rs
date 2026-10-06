//! Who may talk to the daemon, on Windows.
//!
//! The Unix rule is "root, or a member of the admin group" -- the people who
//! could have installed the daemon anyway, so being let in grants nothing new.
//! Translated: the peer is `LocalSystem`, or its token carries
//! `BUILTIN\Administrators`.
//!
//! The translation has one trap, and it is the reason this file is more than a
//! group check. A GUI runs *unelevated*, and under UAC an administrator's
//! unelevated token carries the Administrators SID as **deny-only**
//! (`SE_GROUP_USE_FOR_DENY_ONLY`). A check that asked whether the group is
//! *enabled* would refuse every real client; an ACL granting Administrators
//! would admit nothing but elevated processes. So this asks about
//! membership, in any state -- the property that means "this user could have
//! installed it", which is what the Unix rule is really about.
//!
//! Identity comes from the socket, not from anything the client says: the
//! accepted socket's peer PID (`SIO_AF_UNIX_GETPEERPID`, see `socket_windows`)
//! and that process's token. A rejected caller gets `PERMISSION_DENIED` as a
//! status, as on Unix, for the same reason given there.
//!
//! Design: docs/specs/2026-10-06-windows-privileged-daemon.md, "Authorization".

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{
    GetTokenInformation, PSID, TOKEN_GROUPS, TOKEN_QUERY, TOKEN_USER, TokenGroups, TokenUser,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

/// `NT AUTHORITY\SYSTEM`. The service's own account, and the counterpart of
/// root: refusing it would protect nothing.
const LOCAL_SYSTEM: &str = "S-1-5-18";

/// `BUILTIN\Administrators`. A well-known SID, the same on every Windows in
/// every language -- which is why SIDs are compared and names never are.
const ADMINISTRATORS: &str = "S-1-5-32-544";

/// Who a connected process is, read from its token at accept time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerIdentity {
    pub pid: u32,
    /// The token's user, as a string SID.
    pub user: String,
    /// Every group in the token, in any state -- enabled, deny-only, or
    /// neither. Deliberately not filtered; see the module comment.
    pub groups: Vec<String>,
}

impl PeerIdentity {
    /// Read the identity of process `pid`.
    ///
    /// An error when the process cannot be opened -- most often because it
    /// has already exited, between connecting and being looked up. That is a
    /// refusal, never a guess: the PID may by now belong to someone else.
    pub fn of_process(pid: u32) -> std::io::Result<Self> {
        let process = Handle::open_process(pid)?;
        let token = process.token()?;
        Ok(Self {
            pid,
            user: token_user(&token)?,
            groups: token_groups(&token)?,
        })
    }
}

/// Same name as the Unix type, so `service` has one body on every platform.
pub type Peer = PeerIdentity;

impl std::fmt::Display for PeerIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "pid {} (user {})", self.pid, self.user)
    }
}

/// The message every refused call gets, as on Unix.
pub const REFUSAL: &str = "not permitted; this daemon serves SYSTEM and Administrators";

/// The name `--group` must carry, when given. See [`Authorizer::for_group`].
pub const ADMINISTRATORS_GROUP: &str = "Administrators";

/// Who may call. Stateless: the Windows group that matches the Unix ones is
/// fixed, so there is nothing to resolve.
#[derive(Debug, Clone, Default)]
pub struct Authorizer {
    /// For the service tests only, which need a rule that admits the account
    /// running them -- an administrator on one machine and not on another --
    /// and one that refuses it.
    #[cfg(test)]
    test_rule: TestRule,
}

#[cfg(test)]
#[derive(Debug, Clone, Default)]
enum TestRule {
    /// The real rule.
    #[default]
    Real,
    /// The real rule, plus this user.
    Also(String),
    /// This user and nobody else, not even administrators.
    Only(String),
}

impl Authorizer {
    /// The Unix entry point, kept so `serve` has one body.
    ///
    /// `--group` cannot change who is let in on Windows, so a name other than
    /// Administrators is refused at startup -- the Unix rule that a misspelled
    /// group is a refusal to start rather than a daemon that rejects everyone,
    /// applied to a group that cannot be chosen.
    pub fn for_group(name: &str) -> std::io::Result<Self> {
        if name.eq_ignore_ascii_case(ADMINISTRATORS_GROUP) {
            Ok(Self::default())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "--group {name:?}: on Windows the daemon serves SYSTEM and \
                     {ADMINISTRATORS_GROUP}, and that is not configurable"
                ),
            ))
        }
    }

    /// Admits the account running the tests as well.
    #[cfg(test)]
    pub fn also_allowing(user: String) -> Self {
        Self {
            test_rule: TestRule::Also(user),
        }
    }

    /// Admits one user only, so the refusal path can be driven by an account
    /// the real rule would let in.
    #[cfg(test)]
    pub fn allowing_only(user: String) -> Self {
        Self {
            test_rule: TestRule::Only(user),
        }
    }

    pub fn allows_peer(&self, peer: &Peer) -> bool {
        #[cfg(test)]
        match &self.test_rule {
            TestRule::Real => {}
            TestRule::Also(user) if *user == peer.user => return true,
            TestRule::Also(_) => {}
            TestRule::Only(user) => return *user == peer.user,
        }
        authorize(&peer.user, &peer.groups)
    }

    /// Nothing: the socket's DACL is fixed. See `socket`.
    pub fn socket_access(&self) -> crate::socket::Access {
        crate::socket::Access::default()
    }

    pub fn describe(&self) -> String {
        format!("SYSTEM and {ADMINISTRATORS_GROUP}")
    }
}

/// The peer of a request, as `socket` identified it at accept.
pub fn peer_of<T>(request: &tonic::Request<T>) -> Result<Peer, &'static str> {
    match request.extensions().get::<crate::socket::PeerInfo>() {
        Some(crate::socket::PeerInfo(Ok(peer))) => Ok(peer.clone()),
        Some(crate::socket::PeerInfo(Err(_))) => Err("the peer could not be identified"),
        None => Err("no peer credentials on this connection"),
    }
}

/// The decision, on string SIDs, so it is tested on every platform.
fn authorize(user: &str, groups: &[String]) -> bool {
    user == LOCAL_SYSTEM || groups.iter().any(|group| group == ADMINISTRATORS)
}

/// A kernel handle closed on drop.
struct Handle(HANDLE);

impl Handle {
    fn open_process(pid: u32) -> std::io::Result<Self> {
        // SAFETY: plain FFI call; a null return is checked below.
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if handle.is_null() {
            let e = std::io::Error::last_os_error();
            return Err(std::io::Error::new(
                e.kind(),
                format!("could not open peer process {pid}: {e}"),
            ));
        }
        Ok(Self(handle))
    }

    fn token(&self) -> std::io::Result<Self> {
        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: `self.0` is a live process handle; `token` is written on
        // success and checked.
        if unsafe { OpenProcessToken(self.0, TOKEN_QUERY, &mut token) } == 0 {
            let e = std::io::Error::last_os_error();
            return Err(std::io::Error::new(
                e.kind(),
                format!("could not open the peer's token: {e}"),
            ));
        }
        Ok(Self(token))
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: owned, non-null, closed exactly once.
        unsafe { CloseHandle(self.0) };
    }
}

/// `GetTokenInformation` into a buffer it sizes itself.
///
/// The buffer is `u64`-backed so the structures read out of it are aligned;
/// a `Vec<u8>` is not guaranteed to be.
fn token_information(token: &Handle, class: i32) -> std::io::Result<Vec<u64>> {
    let mut needed: u32 = 0;
    // SAFETY: a size query with a null buffer, as documented.
    unsafe { GetTokenInformation(token.0, class, std::ptr::null_mut(), 0, &mut needed) };
    if needed == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut buffer = vec![0u64; (needed as usize).div_ceil(8)];
    // SAFETY: the buffer holds at least `needed` bytes.
    let ok = unsafe {
        GetTokenInformation(
            token.0,
            class,
            buffer.as_mut_ptr().cast(),
            (buffer.len() * 8) as u32,
            &mut needed,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(buffer)
}

fn token_user(token: &Handle) -> std::io::Result<String> {
    let buffer = token_information(token, TokenUser)?;
    // SAFETY: `TokenUser` fills a TOKEN_USER at the start of the buffer, and
    // the buffer outlives this read.
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    sid_string(user.User.Sid)
}

fn token_groups(token: &Handle) -> std::io::Result<Vec<String>> {
    let buffer = token_information(token, TokenGroups)?;
    // SAFETY: `TokenGroups` fills a TOKEN_GROUPS whose `Groups` is a
    // variable-length array of `GroupCount` entries inside the buffer.
    let groups = unsafe {
        let header = &*buffer.as_ptr().cast::<TOKEN_GROUPS>();
        std::slice::from_raw_parts(header.Groups.as_ptr(), header.GroupCount as usize)
    };
    groups.iter().map(|group| sid_string(group.Sid)).collect()
}

fn sid_string(sid: PSID) -> std::io::Result<String> {
    let mut wide: *mut u16 = std::ptr::null_mut();
    // SAFETY: `sid` points into a token buffer that is alive; the returned
    // string is LocalAlloc'd and freed below.
    if unsafe { ConvertSidToStringSidW(sid, &mut wide) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: a NUL-terminated UTF-16 string from the call above.
    let text = unsafe {
        let len = (0..).take_while(|&i| *wide.add(i) != 0).count();
        String::from_utf16_lossy(std::slice::from_raw_parts(wide, len))
    };
    // SAFETY: allocated by ConvertSidToStringSidW with LocalAlloc.
    unsafe { LocalFree(wide.cast()) };
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn groups(sids: &[&str]) -> Vec<String> {
        sids.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn local_system_is_allowed_with_no_groups() {
        assert!(authorize(LOCAL_SYSTEM, &[]));
    }

    /// The unelevated administrator: the case the whole file is shaped around.
    /// The token lists Administrators, as deny-only -- and the decision does
    /// not see attributes at all, so it is a member.
    #[test]
    fn an_administrator_is_allowed_whatever_the_group_state() {
        let user = "S-1-5-21-1-2-3-1001";
        assert!(authorize(
            user,
            &groups(&["S-1-1-0", ADMINISTRATORS, "S-1-5-32-545"])
        ));
    }

    #[test]
    fn a_standard_user_is_refused() {
        let user = "S-1-5-21-1-2-3-1002";
        // Everyone, Users, Authenticated Users, Interactive -- and no admins.
        assert!(!authorize(
            user,
            &groups(&["S-1-1-0", "S-1-5-32-545", "S-1-5-11", "S-1-5-4"])
        ));
    }

    /// A SID that merely *contains* the admin SID as a prefix is another SID.
    #[test]
    fn a_prefix_of_the_admin_sid_is_not_the_admin_sid() {
        assert!(!authorize("S-1-5-21-9", &groups(&["S-1-5-32-5440"])));
    }

    /// This process's own token reads back: a user SID and at least Everyone.
    /// Unprivileged -- opening one's own process needs nothing.
    #[test]
    fn this_process_identifies_itself() {
        let me = PeerIdentity::of_process(std::process::id()).expect("own token is readable");
        assert!(me.user.starts_with("S-1-5-"), "{}", me.user);
        assert!(me.groups.iter().any(|g| g == "S-1-1-0"), "{:?}", me.groups);
    }

    #[test]
    fn a_process_that_does_not_exist_is_an_error() {
        // PIDs are multiples of 4 on Windows; this one is never allocated.
        PeerIdentity::of_process(3).expect_err("no such process");
    }
}
