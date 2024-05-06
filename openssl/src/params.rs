use std::ffi::CString;

enum SupportedParamType {
    Uint(c_unit),
    Utf8String(CString),
    Key(CString),
}

pub struct OsslParams {
    lifetime_keep: Vec<SupportedParamType>,
    param_array: Vec<ffi::OSSL_PARAM>,
}

impl OsslParams {
    pub fn new() -> Self {
        let end_marker = unsafe { ffi::OSSL_PARAM_construct_end() };

        Self {
            lifetime_keep: Vec::new(),
            param_array: vec![end_marker],
        }
    }

    pub fn add_str(&mut self, key: &str, value: &str) -> &mut Self {
        let key = SupportedParamType::Key(CString::new(key.as_bytes()).unwrap());

        let value = CString::new(value.as_bytes()).unwrap();
        let raw_value = value.into_raw();
        let param = unsafe { ffi::OSSL_PARAM_construct_utf8_string(key.as_ptr(), raw_value, 0) };

        self.lifetime_keep.push(key);
        unsafe {
            let kept_value = SupportedParamType::Utf8String(CString::from_raw(raw_value));
            self.lifetime_keep.push(kept_value);
        }

        self.param_array.insert(0, param);

        self
    }

    pub fn add_uint(&mut self, key: &str, value: u32) -> &mut Self {
        let key = SupportedParamType::Key(CString::new(key.as_bytes()).unwrap());
        let value = SupportedParamType::Uint(value);

        let param = unsafe { ffi::OSSL_PARAM_construct_uint(key.as_ptr(), &mut value) };

        self.lifetime_keep.push(key);
        self.lifetime_keep.push(value);

        self.param_array.insert(0, param);

        self
    }
}

impl AsRef<[ffi::OSSL_PARAM]> for OsslParams {
    fn as_ref(&self) -> &[ffi::OSSL_PARAM] {
        &self.param_array
    }
}
