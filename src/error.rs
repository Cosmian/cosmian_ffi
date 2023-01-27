use std::{
    cell::RefCell,
    ffi::CString,
    os::raw::{c_char, c_int},
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum FfiError {
    #[error("Invalid NULL pointer: {0}")]
    NullPointer(String),

    #[error("FFI error: {0}")]
    Generic(String),
}

thread_local! {
    /// a thread-local variable which holds the most recent error
    static LAST_ERROR: RefCell<Option<Box<FfiError>>> = RefCell::new(None);
}

/// Sets the most recent error, clearing whatever may have been there before.
#[inline]
pub fn set_last_error(err: FfiError) {
    LAST_ERROR.with(|prev| {
        *prev.borrow_mut() = Some(Box::new(err));
    });
}

#[inline]
#[must_use]
pub fn get_last_error() -> String {
    LAST_ERROR
        .with(|prev| prev.borrow_mut().take())
        .map_or(String::new(), |e| e.to_string())
}

/// Externally sets the last error recorded on the Rust side.
///
/// # Safety
///
/// This function is meant to be called from the Foreign Function
/// Interface.
#[no_mangle]
pub unsafe extern "C" fn h_set_error(error_message_ptr: *const c_char) -> i32 {
    let error_message = ffi_read_string!("error message", error_message_ptr);
    set_last_error(FfiError::Generic(error_message));
    0
}

/// Gets the most recent error as utf-8 bytes, clearing it in the process.
///
/// # Safety
///
/// - `error_ptr`: pointer to the buffer to which to write the error
/// - `error_len`: size of the allocated memory
#[no_mangle]
pub unsafe extern "C" fn h_get_error(error_ptr: *mut c_char, error_len: *mut c_int) -> c_int {
    let cs = ffi_unwrap!(
        CString::new(get_last_error()),
        "failed to convert error to CString"
    );

    ffi_write_bytes!("error", cs.as_bytes(), error_ptr, error_len);

    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr::null_mut;

    #[test]
    fn test_error() {
        let error_msg = "Emergency!!!";

        // Set the error message.
        let res = unsafe { h_set_error(error_msg.as_ptr().cast()) };
        assert_eq!(res, 0);

        // Reads the error message.
        let res = unsafe {
            let mut bytes = [0u8; 8192];
            let ptr = bytes.as_mut_ptr().cast();
            let mut len = bytes.len() as c_int;
            h_get_error(ptr, &mut len);
            String::from_utf8(bytes[..len as usize].to_vec()).unwrap()
        };
        assert!(res.contains(error_msg));

        // Reads the error message.
        unsafe {
            let ptr = null_mut::<u8>();
            let mut len = 10;
            h_get_error(ptr.cast(), &mut len);
        };

        // Reads the error message.
        let res = unsafe {
            let mut bytes = [0u8; 8192];
            let ptr = bytes.as_mut_ptr().cast();
            let mut len = bytes.len() as c_int;
            h_get_error(ptr, &mut len);
            String::from_utf8(bytes[..len as usize].to_vec()).unwrap()
        };
        assert!(res.contains("NULL pointer"));
    }
}
