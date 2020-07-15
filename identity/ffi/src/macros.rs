#[doc(hidden)]
#[macro_export]
macro_rules! error {
    ($result:expr) => {
        $crate::error!($result, CLIENT_UNKNOWN);
    };
    ($result:expr, $error:expr) => {
        match $result {
            Ok(value) => value,
            Err(e) => {
                return $error;
            }
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! last_error {
    () => {
        $crate::last_error!(err = CLIENT_UNINIT);
    };
    (err = $err:expr) => {
        // this safe since we get a immutable ref for the client
        unsafe {
            match LAST_ERROR {
                Some(ref last_err) => last_err,
                None => {
                    return $err;
                }
            }
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! result {
    ($result:expr) => {
        $crate::result!($result, CLIENT_UNKNOWN);
    };
    ($result:expr, $error:expr) => {
        match $result {
            Ok(value) => value,
            Err(e) => {
                $crate::log::error!("{:?}", e);
                return $error;
            }
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! cstr {
    ($ptr:expr, allow_null) => {
        if $ptr.is_null() {
            None
        } else {
            Some($crate::cstr!($ptr))
        }
    };
    ($ptr:expr) => {
        $crate::cstr!($ptr, CLIENT_BAD_CSTR);
    };
    ($ptr:expr, $error:expr) => {
        unsafe {
            if $ptr.is_null() {
                return $error;
            }
            $crate::error!(CStr::from_ptr($ptr).to_str(), $error)
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! static_client {
    () => {
        $crate::static_client!(err = CLIENT_UNINIT);
    };
    (err = $err:expr) => {
        // this safe since we get a immutable ref for the client
        unsafe {
            match CLIENT {
                Some(ref client) => client,
                None => {
                    return $err;
                }
            }
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! enum_result {
    ($($err:ident = $val:expr),+ $(,)?) => {
        $(
            #[allow(dead_code)]
            pub const $err: i32 = $val;
        )+
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! gen_ffi {
    (
        $(#[$outer:meta])*
        $struct: ident :: $method: ident => fn $name: ident(
            $($param: ident : $ty: ty = $val: expr),*
        ) -> $ret: ty;
    ) => {
        $(#[$outer])*
        #[allow(clippy::not_unsafe_ptr_arg_deref)]
        #[no_mangle]
        pub extern "C" fn $name(port: i64, $($param: $ty),*) -> i32 {
            let isolate = Isolate::new(port);
            $(
                let $param = $val;
            )*
            let client = static_client!();
            let ffi_struct = ffi::$struct::new(client);
            let t = isolate.task(async move {
                match ffi::$struct::$method(&ffi_struct, $($param),*).await {
                    Ok(v) => Some(v),
                    Err(e) => {
                        $crate::log::error!("{:?}: {:?}", stringify!($struct::$method), e);
                        let last_err = $crate::last_error!(err = None);
                        if let Ok(mut v) = last_err.write() {
                            v.write(e.to_string());
                        }
                        None
                    }
                }
            });
            task::spawn(t);
            CLIENT_OK
        }
    };

    ($(
        $(#[$outer:meta])*
        $struct: ident :: $method: ident => fn $name: ident(
            $($param: ident : $ty: ty = $val: expr),*
        ) -> $ret: ty;
    )+) => {
        $(
            gen_ffi!(
                $(#[$outer])*
                $struct::$method => fn $name($($param: $ty = $val),*) -> $ret;
            );
        )+
    }
}
