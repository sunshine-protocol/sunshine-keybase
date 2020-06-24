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
macro_rules! isolate_err {
    ($result:expr, $isolate:expr) => {
        isolate_err!($result, $isolate, $crate::CLIENT_UNKNOWN);
    };
    ($result:expr, $isolate:expr, $error:expr) => {
        match $result {
            Ok(value) => value,
            Err(e) => {
                $isolate.post(e.to_string());
                return $error;
            }
        }
    };
}

#[macro_export]
macro_rules! cstr {
    ($ptr:expr) => {
        cstr!($ptr, $crate::CLIENT_BAD_CSTR);
    };
    ($ptr:expr, $error:expr) => {
        unsafe {
            ffi_helpers::null_pointer_check!($ptr);
            #[allow(clippy::not_unsafe_ptr_arg_deref)]
            error!(CStr::from_ptr($ptr).to_str(), $error)
        }
    };
}

#[macro_export]
macro_rules! client {
    ($isolate:expr) => {
        client!($isolate, $crate::CLIENT_UNINIT, $crate::CLIENT_UNINIT);
    };
    ($isolate:expr, $post:expr) => {
        client!($isolate, $post, $crate::CLIENT_UNINIT);
    };
    ($isolate:expr, $post:expr, $err:expr) => {
        // this safe since we get a immutable ref for the client
        unsafe {
            match $crate::CLIENT {
                Some(ref client) => client,
                None => {
                    $isolate.post($post);
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
