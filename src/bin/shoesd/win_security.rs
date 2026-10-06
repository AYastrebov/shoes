//! Windows access control, the counterpart of `chown`/`chmod`.
//!
//! Shared by `socket` (the socket file and a directory it creates) and
//! `install` (the install directory). Access is written as SDDL, the same
//! string `icacls`/PowerShell show, so the rule is readable where it is
//! stated rather than assembled from ACE structures.

use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1, SE_FILE_OBJECT,
    SetNamedSecurityInfoW,
};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR,
};

fn wide(text: &std::ffi::OsStr) -> Vec<u16> {
    text.encode_wide().chain(std::iter::once(0)).collect()
}

/// A LocalAlloc'd security descriptor, freed on drop.
struct Descriptor(PSECURITY_DESCRIPTOR);

impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: allocated by the conversion functions with LocalAlloc.
        unsafe { LocalFree(self.0) };
    }
}

/// Replace `path`'s DACL with the one in `sddl`, protected from inheritance
/// when the SDDL says `D:P`.
pub fn set_file_dacl(path: &Path, sddl: &str) -> std::io::Result<()> {
    let sddl_w = wide(std::ffi::OsStr::new(sddl));
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: `sddl_w` is NUL-terminated; the descriptor is written on success
    // and owned by the guard below.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl_w.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(std::io::Error::other(format!(
            "invalid SDDL {sddl:?}: {}",
            std::io::Error::last_os_error()
        )));
    }
    let descriptor = Descriptor(descriptor);

    let mut present = 0;
    let mut defaulted = 0;
    let mut dacl: *mut ACL = std::ptr::null_mut();
    // SAFETY: a descriptor from the conversion above; `dacl` points into it
    // and is only used while it lives.
    if unsafe { GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut dacl, &mut defaulted) }
        == 0
    {
        return Err(std::io::Error::last_os_error());
    }

    let mut info = DACL_SECURITY_INFORMATION;
    if sddl.starts_with("D:P") {
        info |= PROTECTED_DACL_SECURITY_INFORMATION;
    }
    let path_w = wide(path.as_os_str());
    // SAFETY: NUL-terminated path; the DACL is alive for the call.
    let rc = unsafe {
        SetNamedSecurityInfoW(
            path_w.as_ptr(),
            SE_FILE_OBJECT,
            info,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dacl,
            std::ptr::null(),
        )
    };
    if rc != ERROR_SUCCESS {
        let e = std::io::Error::from_raw_os_error(rc as i32);
        return Err(std::io::Error::new(
            e.kind(),
            format!("could not set the DACL on {}: {e}", path.display()),
        ));
    }
    Ok(())
}

/// `path`'s DACL as SDDL. For tests and diagnostics.
#[cfg(test)]
pub fn file_dacl_sddl(path: &Path) -> std::io::Result<String> {
    use windows_sys::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW,
    };

    let path_w = wide(path.as_os_str());
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: NUL-terminated path; the descriptor is written on success and
    // owned by the guard below.
    let rc = unsafe {
        GetNamedSecurityInfoW(
            path_w.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(std::io::Error::from_raw_os_error(rc as i32));
    }
    let descriptor = Descriptor(descriptor);

    let mut text: *mut u16 = std::ptr::null_mut();
    // SAFETY: a valid descriptor; `text` is LocalAlloc'd on success.
    if unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor.0,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            &mut text,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    let text = Descriptor(text.cast());
    // SAFETY: NUL-terminated UTF-16 from the call above.
    let sddl = unsafe {
        let p = text.0.cast::<u16>();
        let len = (0..).take_while(|&i| *p.add(i) != 0).count();
        String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
    };
    Ok(sddl)
}

/// Whether this process runs elevated: `TokenElevation` on its own token.
///
/// The Windows answer to `geteuid() == 0` for `install`'s refusal. Not "is the
/// user an administrator" -- an administrator's unelevated process is exactly
/// what must be refused here, and exactly what `auth` admits as a client.
pub fn is_elevated() -> std::io::Result<bool> {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: the pseudo-handle for this process; `token` is written on
    // success and closed below.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut returned = 0u32;
    // SAFETY: a TOKEN_ELEVATION-sized buffer for the `TokenElevation` class.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    };
    // SAFETY: opened above, closed once.
    unsafe { CloseHandle(token) };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(elevation.TokenIsElevated != 0)
}
