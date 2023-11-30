use crate::cvt_p;
use crate::error::ErrorStack;
use crate::lib_ctx::LibCtxRef;
use crate::pkey::{PKey, Private};
use foreign_types::ForeignType;
use openssl_macros::corresponds;
use std::ffi::CString;
use std::ptr;

foreign_type_and_impl_send_sync! {
    type CType = ffi::OSSL_STORE_CTX;
    fn drop = ffi::OSSL_STORE_close;

    pub struct StoreCtx;
    pub struct StoreCtxRef;
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::OSSL_STORE_INFO;
    fn drop = ffi::OSSL_STORE_INFO_free;

    pub struct StoreInfo;
    pub struct StoreInfoRef;
}

impl StoreCtx {
    #[corresponds(OSSL_STORE_open_ex)]
    pub fn new_ex(uri: &str, libctx: Option<&LibCtxRef>, propq: &str) -> Result<Self, ErrorStack> {
        unsafe {
            let uri = CString::new(uri).unwrap();
            let propq = CString::new(propq).unwrap();

            let p = cvt_p(ffi::OSSL_STORE_open_ex(
                uri.as_ptr(),
                libctx.map_or(ptr::null_mut(), ::foreign_types::ForeignTypeRef::as_ptr),
                propq.as_ptr(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null_mut(),
            ))?;

            Ok(Self::from_ptr(p))
        }
    }

    #[corresponds(OSSL_STORE_open)]
    pub fn new(uri: Option<&str>) -> Result<Self, ErrorStack> {
        let uri = uri.map(|uri| CString::new(uri).unwrap());

        unsafe {
            let p = cvt_p(ffi::OSSL_STORE_open(
                uri.map_or(ptr::null(), |uri| uri.as_ptr()),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
            ))?;

            Ok(Self::from_ptr(p))
        }
    }

    #[corresponds(OSSL_STORE_load)]
    pub fn load(self) -> Result<StoreInfo, ErrorStack> {
        unsafe {
            let p = cvt_p(ffi::OSSL_STORE_load(self.as_ptr()))?;
            Ok(StoreInfo::from_ptr(p))
        }
    }
}

impl StoreInfo {
    #[corresponds(OSSL_STORE_INFO_get1_PKEY)]
    pub fn get1_pkey(&self) -> Result<PKey<Private>, ErrorStack> {
        unsafe {
            let p = cvt_p(ffi::OSSL_STORE_INFO_get1_PKEY(self.as_ptr()))?;
            Ok(PKey::from_ptr(p))
        }
    }
}
