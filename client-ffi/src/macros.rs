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
    ($ptr:expr, $error:expr) => {{
        ffi_helpers::null_pointer_check!($ptr);
        error!(CStr::from_ptr($ptr).to_str(), $error)
    }};
}

#[macro_export]
macro_rules! client {
    ($isolate:expr) => {
        client!($isolate, $crate::CLIENT_UNINIT, $crate::CLIENT_UNINIT);
    };
    ($isolate:expr, $post:expr) => {
        client!($isolate, $post, $crate::CLIENT_UNINIT);
    };
    ($isolate:expr, $post:expr, $err:expr) => {{
        let mut client = CLIENT.lock().await;
        match client.as_mut() {
            Some(client) => client,
            None => {
                $isolate.post($post);
                return $err;
            }
        }
    }};
}