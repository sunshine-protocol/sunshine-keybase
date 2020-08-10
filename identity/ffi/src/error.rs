use sunshine_ffi_utils::async_std;
use std::ffi::CString;

pub struct LastError {
    e: Option<String>,
}

impl LastError {
    pub const fn new() -> Self {
        Self { e: None }
    }

    pub fn write(&mut self, e: String) {
        let _ = self.e.take();
        self.e.replace(e);
    }

    pub fn read(&self) -> Option<CString> {
        self.e.clone().and_then(|v| CString::new(v).ok())
    }
}
