pub use std::ffi::CStr;

/// Asserts a pointer is not `null`.
///
/// Sets the given message as last error and returns early with 1.
///
/// - `name`    : name of the object to use in error message
/// - `ptr`     : pointer to check
#[macro_export]
macro_rules! ffi_not_null {
    ( $name:literal, $ptr:expr) => {
        if $ptr.is_null() {
            $crate::error::set_last_error($crate::error::FfiError::NullPointer($name.to_string()));
            return 1_i32;
        }
    };
}

/// Unwraps an `std::result::Result`.
///
/// If the result is an error, sets the last error to this error and returns
/// early with 1.
///
/// - `res` : result to unwrap
/// - `msg` : (optional) additional message to use as error
#[macro_export]
macro_rules! ffi_unwrap {
    ($res:expr, $msg:literal) => {
        match $res {
            Ok(v) => v,
            Err(e) => {
                $crate::error::set_last_error($crate::error::FfiError::Generic(format!(
                    "{}: {}",
                    $msg, e
                )));
                return 1_i32;
            }
        }
    };
    ($res:expr) => {
        match $res {
            Ok(v) => v,
            Err(e) => {
                $crate::error::set_last_error($crate::error::FfiError::Generic(e.to_string()));
                return 1_i32;
            }
        }
    };
}

/// Returns with an error.
///
/// Sets the last error to the given message and returns early with the given
/// error code if given or 1 if it's not.
///
/// - `msg` : error message to set
/// - `err` : (optional) error code to return
#[macro_export]
macro_rules! ffi_bail {
    ($msg:expr) => {
        $crate::error::set_last_error($crate::error::FfiError::Generic($msg));
        return 1;
    };
    ($msg: expr, $err: expr) => {
        $crate::error::set_last_error($crate::error::FfiError::Generic($msg.to_string()));
        return $err;
    };
}

/// Writes the given bytes to an FFI pointer.
///
/// Asserts enough space is allocated to the output pointer and writes the
/// given bytes. Writes the actual length to `len`.
///
/// - `name`    : object name to use in error message
/// - `bytes`   : bytes to write
/// - `ptr`     : pointer to the output buffer
/// - `len`     : length of the output buffer
#[macro_export]
macro_rules! ffi_write_bytes {
    ($name: literal, $bytes: expr, $ptr: ident, $len: ident) => {

        $crate::ffi_not_null!( $name, $ptr);

        let allocated = *$len;
        *$len = $bytes.len() as c_int;

        if allocated < *$len {
            $crate::ffi_bail!(
                format!("The pre-allocated {} buffer is too small; need {} bytes, allocated {allocated}", $name, *$len),
                $bytes.len() as c_int
            );
        }

        std::slice::from_raw_parts_mut($ptr.cast(), $bytes.len()).copy_from_slice($bytes);
    };
}

/// Reads bytes from an FFI pointer.
///
/// Asserts the given pointer is not null and its length is not null and
/// reads `len` bytes from it.
///
/// - `name`    : object name to use in error message
/// - `ptr`     : pointer to the input buffer
/// - `len`     : length of the input buffer
#[macro_export]
macro_rules! ffi_read_bytes {
    ($name: literal, $ptr: ident, $len: ident) => {{
        $crate::ffi_not_null!($name, $ptr);

        if $len == 0 {
            $crate::ffi_bail!(format!(
                "{} buffer should have a size greater than zero",
                $name
            ));
        }

        std::slice::from_raw_parts($ptr.cast(), $len as usize)
    }};
}

/// Reads Rust string from the given pointer to a null-terminated C string.
///
/// Asserts the given pointer is not null and reads a null-terminated C
/// string from it. Converts it into Rust string.
///
/// - `name`    : object name to use in error message
/// - `ptr`     : pointer to the input null-terminated C string
#[macro_export]
macro_rules! ffi_read_string {
    ($name: literal, $ptr: ident) => {{
        $crate::ffi_not_null!($name, $ptr);

        match $crate::macros::CStr::from_ptr($ptr).to_str() {
            Ok(msg) => msg.to_owned(),
            Err(e) => {
                $crate::ffi_bail!(format!("{} invalid C string: {}", $name, e));
            }
        }
    }};
}
