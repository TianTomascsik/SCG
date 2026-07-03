//! C ABI for the client library.
//!
//! The functions here are a thin, panic-safe veneer over [`crate::ScgClient`].
//! A generated header (`include/scg_client.h`, produced by `build.rs`) and a
//! header-only C++ wrapper (`include/scg_client.hpp`) expose them to C/C++.
//!
//! Conventions:
//! * Handles are opaque `ScgClientHandle*` owned by the caller; free them with
//!   [`scg_client_close`].
//! * Functions returning `int` use `0` for success, `-1` for error, and `1`
//!   for the specific "no message within the timeout" case of
//!   [`scg_client_recv`].
//! * On error, a human-readable message is available via
//!   [`scg_client_last_error`] (per handle) or the `err_buf` out-parameter of
//!   [`scg_client_connect`] (which has no handle yet).

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::path::Path;
use std::ptr;
use std::time::Duration;

use crate::{Direction, ScgClient, TrafficClass, Transport};

// --- Stable integer constants mirrored into the generated header. ----------

/// Transport selector: Unix-domain socket.
pub const SCG_TRANSPORT_UDS: c_int = 0;
/// Transport selector: shared memory.
pub const SCG_TRANSPORT_SHM: c_int = 1;
/// Traffic class: best-effort / non-safety.
pub const SCG_CLASS_NORMAL: c_int = 0;
/// Traffic class: safety-critical.
pub const SCG_CLASS_SAFETY: c_int = 1;
/// Direction: application encrypts toward the upstream.
pub const SCG_DIRECTION_ENCRYPT: c_int = 0;
/// Direction: application receives decrypted traffic (v1: unsupported).
pub const SCG_DIRECTION_DECRYPT: c_int = 1;

/// Return code: success.
pub const SCG_OK: c_int = 0;
/// Return code: generic failure (see [`scg_client_last_error`]).
pub const SCG_ERR: c_int = -1;
/// Return code from [`scg_client_recv`]: no message within the timeout.
pub const SCG_TIMEOUT: c_int = 1;
/// Return code from [`scg_client_reserve`]/[`scg_client_commit`]: the send ring
/// is full — retry after the gateway drains (not an error).
pub const SCG_FULL: c_int = 2;

/// Opaque client handle. Created by [`scg_client_connect`], destroyed by
/// [`scg_client_close`].
pub struct ScgClientHandle {
    inner: ScgClient,
    last_error: Option<CString>,
}

impl ScgClientHandle {
    fn set_err(&mut self, msg: &str) {
        // CString cannot contain interior NULs; replace any defensively.
        self.last_error = CString::new(msg.replace('\0', " ")).ok();
    }
}

/// # Safety
/// `p` must be NUL-terminated and valid for the duration of the call, or null.
unsafe fn cstr_to_str<'a>(p: *const c_char) -> Option<&'a str> {
    if p.is_null() {
        return None;
    }
    CStr::from_ptr(p).to_str().ok()
}

/// # Safety
/// `buf` must point to at least `len` writable bytes, or be null.
unsafe fn write_err(buf: *mut c_char, len: usize, msg: &str) {
    if buf.is_null() || len == 0 {
        return;
    }
    let bytes = msg.as_bytes();
    let n = bytes.len().min(len - 1);
    ptr::copy_nonoverlapping(bytes.as_ptr() as *const c_char, buf, n);
    *buf.add(n) = 0;
}

fn map_transport(v: c_int) -> Option<Transport> {
    match v {
        SCG_TRANSPORT_UDS => Some(Transport::Uds),
        SCG_TRANSPORT_SHM => Some(Transport::Shm),
        _ => None,
    }
}

fn map_class(v: c_int) -> Option<TrafficClass> {
    match v {
        SCG_CLASS_NORMAL => Some(TrafficClass::Normal),
        SCG_CLASS_SAFETY => Some(TrafficClass::Safety),
        _ => None,
    }
}

fn map_direction(v: c_int) -> Option<Direction> {
    match v {
        SCG_DIRECTION_ENCRYPT => Some(Direction::Encrypt),
        SCG_DIRECTION_DECRYPT => Some(Direction::Decrypt),
        _ => None,
    }
}

/// Create an endpoint and connect its data plane.
///
/// Returns a non-null handle on success, or null on failure (in which case a
/// message is written to `err_buf`, truncated to `err_len - 1` bytes plus a
/// terminating NUL).
///
/// `mgmt_socket` may be null to use the default management socket path.
///
/// # Safety
/// All pointers must be null or valid; `app_id` must be a valid C string.
#[no_mangle]
pub unsafe extern "C" fn scg_client_connect(
    mgmt_socket: *const c_char,
    app_id: *const c_char,
    transport: c_int,
    traffic_class: c_int,
    direction: c_int,
    err_buf: *mut c_char,
    err_len: usize,
) -> *mut ScgClientHandle {
    let app_id = match cstr_to_str(app_id) {
        Some(s) => s,
        None => {
            write_err(err_buf, err_len, "app_id is null or not valid UTF-8");
            return ptr::null_mut();
        }
    };

    let mgmt_path: Option<&Path> = if mgmt_socket.is_null() {
        None
    } else {
        match cstr_to_str(mgmt_socket) {
            Some(s) => Some(Path::new(s)),
            None => {
                write_err(err_buf, err_len, "mgmt_socket is not valid UTF-8");
                return ptr::null_mut();
            }
        }
    };

    let transport = match map_transport(transport) {
        Some(t) => t,
        None => {
            write_err(err_buf, err_len, "invalid transport selector");
            return ptr::null_mut();
        }
    };
    let class = match map_class(traffic_class) {
        Some(c) => c,
        None => {
            write_err(err_buf, err_len, "invalid traffic class");
            return ptr::null_mut();
        }
    };
    let direction = match map_direction(direction) {
        Some(d) => d,
        None => {
            write_err(err_buf, err_len, "invalid direction");
            return ptr::null_mut();
        }
    };

    match ScgClient::connect(mgmt_path, app_id, transport, class, direction) {
        Ok(inner) => Box::into_raw(Box::new(ScgClientHandle {
            inner,
            last_error: None,
        })),
        Err(e) => {
            write_err(err_buf, err_len, &e.to_string());
            ptr::null_mut()
        }
    }
}

/// Send one framed message.
///
/// Returns [`SCG_OK`] or [`SCG_ERR`]. A `len` of 0 sends an empty frame.
///
/// # Safety
/// `handle` must be a live handle; `data` must point to `len` readable bytes
/// (or may be null when `len == 0`).
#[no_mangle]
pub unsafe extern "C" fn scg_client_send(
    handle: *mut ScgClientHandle,
    traffic_id: u32,
    data: *const u8,
    len: usize,
) -> c_int {
    let h = match handle.as_mut() {
        Some(h) => h,
        None => return SCG_ERR,
    };
    let slice: &[u8] = if len == 0 {
        &[]
    } else if data.is_null() {
        h.set_err("data is null but len > 0");
        return SCG_ERR;
    } else {
        std::slice::from_raw_parts(data, len)
    };

    match h.inner.send(traffic_id, slice) {
        Ok(()) => SCG_OK,
        Err(e) => {
            h.set_err(&e.to_string());
            SCG_ERR
        }
    }
}

/// Reserve the next send slot for **zero-copy, in-place** production (SHM slot
/// ring only). On [`SCG_OK`], `*out_ptr` points at `*out_cap` writable bytes in
/// shared memory: build the message there, then call [`scg_client_commit`] with
/// the byte count. Returns [`SCG_FULL`] if the ring is full (retry after
/// draining with [`scg_client_recv`]/backoff) or [`SCG_ERR`] on error (e.g. a
/// UDS or byte-stream endpoint, which has no in-place slot — use
/// [`scg_client_send`]). The returned pointer is valid only until the matching
/// [`scg_client_commit`]; do not reserve twice without committing.
///
/// # Safety
/// `handle` must be a live handle; `out_ptr`/`out_cap` must be valid, writable.
#[no_mangle]
pub unsafe extern "C" fn scg_client_reserve(
    handle: *mut ScgClientHandle,
    out_ptr: *mut *mut u8,
    out_cap: *mut usize,
) -> c_int {
    let h = match handle.as_mut() {
        Some(h) => h,
        None => return SCG_ERR,
    };
    if out_ptr.is_null() || out_cap.is_null() {
        h.set_err("out_ptr/out_cap must be non-null");
        return SCG_ERR;
    }
    match h.inner.reserve_raw() {
        Ok(Some((p, cap))) => {
            *out_ptr = p;
            *out_cap = cap;
            SCG_OK
        }
        Ok(None) => SCG_FULL,
        Err(e) => {
            h.set_err(&e.to_string());
            SCG_ERR
        }
    }
}

/// Publish `len` bytes written into the slot from the last [`scg_client_reserve`]
/// under `traffic_id`, and wake the gateway. `len` must not exceed the capacity
/// that `scg_client_reserve` returned. Returns [`SCG_OK`] on success,
/// [`SCG_FULL`] if the ring filled since the reserve, or [`SCG_ERR`] on error.
///
/// # Safety
/// `handle` must be a live handle; call exactly once per successful
/// [`scg_client_reserve`], having written no more than `cap` bytes.
#[no_mangle]
pub unsafe extern "C" fn scg_client_commit(
    handle: *mut ScgClientHandle,
    traffic_id: u32,
    len: usize,
) -> c_int {
    let h = match handle.as_mut() {
        Some(h) => h,
        None => return SCG_ERR,
    };
    match h.inner.commit_raw(traffic_id, len) {
        Ok(true) => SCG_OK,
        Ok(false) => SCG_FULL,
        Err(e) => {
            h.set_err(&e.to_string());
            SCG_ERR
        }
    }
}

/// Receive one framed message.
///
/// On success returns [`SCG_OK`], sets `*traffic_id_out`, and allocates a
/// buffer into `*out_data` / `*out_len` that the caller must release with
/// [`scg_client_free_buf`]. Returns [`SCG_TIMEOUT`] if no message arrived
/// within `timeout_ms` (a negative `timeout_ms` blocks indefinitely), or
/// [`SCG_ERR`] on error.
///
/// # Safety
/// `handle` must be a live handle; the out-pointers must be null or valid.
#[no_mangle]
pub unsafe extern "C" fn scg_client_recv(
    handle: *mut ScgClientHandle,
    traffic_id_out: *mut u32,
    out_data: *mut *mut u8,
    out_len: *mut usize,
    timeout_ms: c_int,
) -> c_int {
    let h = match handle.as_mut() {
        Some(h) => h,
        None => return SCG_ERR,
    };

    let result = if timeout_ms < 0 {
        h.inner.recv().map(Some)
    } else {
        h.inner
            .recv_timeout(Some(Duration::from_millis(timeout_ms as u64)))
    };

    match result {
        Ok(Some((tid, buf))) => {
            // Validate the output pointers BEFORE allocating: if `out_data` is
            // null we must not `Box::into_raw` the buffer, or its allocation
            // would leak (the caller never receives the pointer to free it).
            if out_data.is_null() || out_len.is_null() {
                h.set_err("out_data and out_len must not be null");
                return SCG_ERR; // `buf` is dropped here — no leak.
            }
            if !traffic_id_out.is_null() {
                *traffic_id_out = tid;
            }
            let boxed = buf.into_boxed_slice();
            let n = boxed.len();
            let p = Box::into_raw(boxed) as *mut u8;
            *out_data = p;
            *out_len = n;
            SCG_OK
        }
        Ok(None) => SCG_TIMEOUT,
        Err(e) => {
            h.set_err(&e.to_string());
            SCG_ERR
        }
    }
}

/// Release a buffer previously returned by [`scg_client_recv`].
///
/// # Safety
/// `data`/`len` must be exactly a pair produced by [`scg_client_recv`], passed
/// at most once.
#[no_mangle]
pub unsafe extern "C" fn scg_client_free_buf(data: *mut u8, len: usize) {
    if data.is_null() || len == 0 {
        return;
    }
    let slice = ptr::slice_from_raw_parts_mut(data, len);
    drop(Box::from_raw(slice));
}

/// Return the last error message recorded on `handle`, or null if none.
///
/// The returned pointer is owned by the handle and valid until the next failed
/// call on it or until the handle is closed.
///
/// # Safety
/// `handle` must be a live handle or null.
#[no_mangle]
pub unsafe extern "C" fn scg_client_last_error(handle: *const ScgClientHandle) -> *const c_char {
    match handle.as_ref() {
        Some(h) => match &h.last_error {
            Some(s) => s.as_ptr(),
            None => ptr::null(),
        },
        None => ptr::null(),
    }
}

/// Deregister the endpoint and free the handle.
///
/// Returns [`SCG_OK`] if the gateway acknowledged the close, else [`SCG_ERR`]
/// (the handle is freed either way).
///
/// # Safety
/// `handle` must be a live handle (or null) and must not be used afterwards.
#[no_mangle]
pub unsafe extern "C" fn scg_client_close(handle: *mut ScgClientHandle) -> c_int {
    if handle.is_null() {
        return SCG_ERR;
    }
    let handle = Box::from_raw(handle);
    let ScgClientHandle { inner, .. } = *handle;
    match inner.close() {
        Ok(()) => SCG_OK,
        Err(_) => SCG_ERR,
    }
}
