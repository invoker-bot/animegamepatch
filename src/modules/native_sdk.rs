//! The native account SDK embeds libcurl; its price requests bypass Unity/WinHTTP.

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::sync::Mutex;
use std::time::Duration;

use anyhow::Result;
use ilhook::x64::Registers;
use lazy_static::lazy_static;
use windows::core::s;
use windows::Win32::System::LibraryLoader::GetModuleHandleA;

use super::{http::sdk_price_url, MhyContext, MhyModule, ModuleType};
use crate::util;

// AccountPlatNative.dll 7.1: curl_easy_setopt at RVA 0x41ae90. Both native HTTP
// request builders set CURLOPT_URL (10002) through this entry. Unique signature,
// including its variadic argument stores; no fixed loaded address is assumed.
const CURL_EASY_SETOPT: &str = "89 54 24 10 4C 89 44 24 18 4C 89 4C 24 20 48 83 EC 28 48 85 C9 75 08 8D 41 2B 48 83 C4 28 C3 4C 8D 44 24 40 E8 87 9D 00 00 48 83 C4 28 C3";
const CURLOPT_URL: u64 = 10002;

lazy_static! {
    // Keep replacement pointers valid until curl copies them. A bounded cache
    // also avoids leaking a new CString on every shop refresh.
    static ref PRICE_URLS: Mutex<HashMap<String, CString>> = Mutex::new(HashMap::new());
}

pub struct NativeSdkPrices;

/// This DLL loads with login, after the main patch initialization has finished.
pub fn start_when_loaded() {
    std::thread::spawn(|| {
        for _ in 0..3000 {
            if unsafe { GetModuleHandleA(s!("AccountPlatNative.dll")) }.is_ok() {
                unsafe {
                    crate::MODULE_MANAGER.write().unwrap().enable(
                        MhyContext::<NativeSdkPrices>::new("AccountPlatNative.dll"),
                    );
                }
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        crate::plog!("Native SDK price hook: SDK module did not load");
    });
}

impl MhyModule for MhyContext<NativeSdkPrices> {
    unsafe fn init(&mut self) -> Result<()> {
        if let Some(addr) = util::pattern_scan_code(self.assembly_name, CURL_EASY_SETOPT) {
            self.interceptor.attach(addr as usize, on_curl_setopt)?;
            crate::plog!("native_sdk_curl_setopt: {:x}", addr as usize);
        } else {
            crate::plog!("Native SDK price hook: unsupported SDK signature");
        }
        Ok(())
    }

    unsafe fn de_init(&mut self) -> Result<()> { Ok(()) }

    fn get_module_type(&self) -> ModuleType { ModuleType::NativeSdkPrices }
}

unsafe extern "win64" fn on_curl_setopt(reg: *mut Registers, _: usize) {
    if (*reg).rdx != CURLOPT_URL || (*reg).r8 == 0 { return; }
    let Ok(url) = CStr::from_ptr((*reg).r8 as *const i8).to_str() else { return; };
    let Some(replacement) = sdk_price_url(url) else { return; };
    let Ok(mut urls) = PRICE_URLS.lock() else { return; };
    if !urls.contains_key(&replacement) {
        if urls.len() >= 64 { return; }
        let Ok(value) = CString::new(replacement.clone()) else { return; };
        urls.insert(replacement.clone(), value);
    }
    (*reg).r8 = urls[&replacement].as_ptr() as u64;
    // Never record query strings, account IDs, device information or tokens.
    crate::plog!("Native SDK price request: {}", replacement.split(['?', '#']).next().unwrap());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_curl_url_argument_is_replaced_without_touching_the_handle_or_option() {
        let url = CString::new("https://sdk-static.mihoyo.com/hk4e_cn/mdk/shopwindow/shopwindow/listPriceTier?game_biz=hk4e_cn").unwrap();
        let mut reg: Registers = unsafe { std::mem::zeroed() };
        reg.rcx = 123;
        reg.rdx = CURLOPT_URL;
        reg.r8 = url.as_ptr() as u64;
        unsafe { on_curl_setopt(&mut reg, 0); }
        assert_eq!(reg.rcx, 123);
        assert_eq!(reg.rdx, CURLOPT_URL);
        assert_eq!(unsafe { CStr::from_ptr(reg.r8 as *const i8) }.to_str().unwrap(),
            "http://127.0.0.1:8088/hk4e_cn/mdk/shopwindow/shopwindow/listPriceTier?game_biz=hk4e_cn");
    }

    #[test]
    fn other_curl_options_and_non_price_requests_keep_their_original_arguments() {
        for (option, value) in [(10004, "https://sdk-static.mihoyo.com/hk4e_cn/mdk/shopwindow/shopwindow/listPriceTier"),
            (CURLOPT_URL, "https://passport-api.mihoyo.com/account/ma-cn-session/app/verify")] {
            let text = CString::new(value).unwrap();
            let mut reg: Registers = unsafe { std::mem::zeroed() };
            reg.rdx = option;
            reg.r8 = text.as_ptr() as u64;
            unsafe { on_curl_setopt(&mut reg, 0); }
            assert_eq!(reg.r8, text.as_ptr() as u64);
        }
        let mut reg: Registers = unsafe { std::mem::zeroed() };
        reg.rdx = 3;
        reg.r8 = 1; // Numeric option values must never be read as string pointers.
        unsafe { on_curl_setopt(&mut reg, 0); }
        assert_eq!(reg.r8, 1);
    }
}
