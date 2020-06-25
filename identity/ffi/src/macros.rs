#[macro_export]
macro_rules! error {
    ($result:expr) => {
        error!($result, $crate::CLIENT_UNKNOWN);
    };
    ($result:expr, $error:expr) => {
        match $result {
            Ok(value) => value,
            Err(e) => {
                ffi_helpers::update_last_error(e);
                return $error;
            }
        }
    };
}

#[macro_export]
macro_rules! result {
    ($result:expr) => {
        result!($result, $crate::CLIENT_UNKNOWN);
    };
    ($result:expr, $error:expr) => {
        match $result {
            Ok(value) => value,
            Err(_) => {
                return $error;
            }
        }
    };
}

#[macro_export]
macro_rules! cstr {
    ($ptr:expr, allow_null) => {
        if $ptr.is_null() {
            None
        } else {
            Some(cstr!($ptr))
        }
    };
    ($ptr:expr) => {
        cstr!($ptr, $crate::CLIENT_BAD_CSTR);
    };
    ($ptr:expr, $error:expr) => {
        unsafe {
            ffi_helpers::null_pointer_check!($ptr);
            error!(CStr::from_ptr($ptr).to_str(), $error)
        }
    };
}

#[macro_export]
macro_rules! client {
    () => {
        client!(err = $crate::CLIENT_UNINIT);
    };
    (err = $err:expr) => {
        // this safe since we get a immutable ref for the client
        unsafe {
            match $crate::CLIENT {
                Some(ref client) => client,
                None => {
                    return $err;
                }
            }
        }
    };
}

#[macro_export]
macro_rules! enum_result {
    ($($err:ident = $val:expr),+ $(,)?) => {
        $(
            #[allow(dead_code)]
            pub const $err: i32 = $val;
        )+
    };
}
