//! Noticing that the routing table or an interface moved, on Windows.
//!
//! `NotifyRouteChange2` and `NotifyIpInterfaceChange` -- the IP Helper
//! counterparts of `PF_ROUTE` and netlink's route and link groups. Their
//! callbacks run on a system thread pool and do one thing: post to a channel.
//! The loop around that, settle and second look included, is the one the
//! other two platforms use (`host/monitor.rs`); this file supplies only the
//! source of events.

use std::ffi::c_void;
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};

use windows_sys::Win32::Foundation::{ERROR_SUCCESS, HANDLE};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    MIB_IPFORWARD_ROW2, MIB_IPINTERFACE_ROW, MIB_NOTIFICATION_TYPE, NotifyIpInterfaceChange,
    NotifyRouteChange2,
};
use windows_sys::Win32::Networking::WinSock::AF_UNSPEC;

use crate::host::monitor::{self, Event};

/// Watch the routing table and interfaces, calling `on_change` when they move.
///
/// Process-lifetime, like the Unix monitors: the notification registrations
/// are never cancelled and their context is leaked deliberately, because the
/// daemon has nothing to join them for and a callback that outlived a freed
/// context would be a use-after-free.
pub fn spawn(on_change: impl Fn() + Send + 'static) -> std::io::Result<()> {
    // One slot: a burst only needs to wake the loop once, and the loop drains
    // the rest itself.
    let (tx, rx) = sync_channel::<()>(1);
    let context: &'static SyncSender<()> = Box::leak(Box::new(tx));
    let context = std::ptr::from_ref(context).cast_mut().cast::<c_void>();

    let mut route_handle: HANDLE = std::ptr::null_mut();
    // SAFETY: the callback and its context live for the rest of the process.
    let rc =
        unsafe { NotifyRouteChange2(AF_UNSPEC, Some(on_route), context, false, &mut route_handle) };
    if rc != ERROR_SUCCESS {
        return Err(std::io::Error::from_raw_os_error(rc as i32));
    }
    let mut interface_handle: HANDLE = std::ptr::null_mut();
    // SAFETY: as above.
    let rc = unsafe {
        NotifyIpInterfaceChange(
            AF_UNSPEC,
            Some(on_interface),
            context,
            false,
            &mut interface_handle,
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(std::io::Error::from_raw_os_error(rc as i32));
    }

    std::thread::Builder::new()
        .name("shoesd-route-monitor".to_owned())
        .spawn(move || monitor::run(|| next(&rx), || drain(&rx), on_change))?;
    Ok(())
}

fn next(rx: &Receiver<()>) -> Event {
    match rx.recv() {
        Ok(()) => Event::Changed,
        Err(_) => Event::Ended("its notifications stopped".to_owned()),
    }
}

fn drain(rx: &Receiver<()>) {
    while rx.try_recv().is_ok() {}
}

fn post(context: *const c_void) {
    // SAFETY: the context is the leaked sender from `spawn`, alive forever.
    let tx = unsafe { &*context.cast::<SyncSender<()>>() };
    // A full slot already means "look again"; that is not an error.
    if let Err(TrySendError::Disconnected(())) = tx.try_send(()) {
        log::debug!("route notification after the monitor ended");
    }
}

unsafe extern "system" fn on_route(
    context: *const c_void,
    _row: *const MIB_IPFORWARD_ROW2,
    _kind: MIB_NOTIFICATION_TYPE,
) {
    post(context);
}

unsafe extern "system" fn on_interface(
    context: *const c_void,
    _row: *const MIB_IPINTERFACE_ROW,
    _kind: MIB_NOTIFICATION_TYPE,
) {
    post(context);
}
