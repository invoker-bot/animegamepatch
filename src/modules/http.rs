use std::ffi::CString;

use super::{MhyContext, MhyModule, ModuleType};
use crate::marshal;
use anyhow::Result;
use ilhook::x64::Registers;
use crate::util;

const WEB_REQUEST_UTILS_MAKE_INITIAL_URL: &str = "55 41 56 56 57 53 48 81 EC ?? ?? ?? ?? 48 8D AC 24 ?? ?? ?? ?? 48 C7 45 ?? ?? ?? ?? ?? 48 89 D6 48 89 CF 48 8B 0D ?? ?? ?? ??";
const BROWSER_LOAD_URL: &str = "41 B0 01 E9 08 00 00 00 0F 1F 84 00 00 00 00 00 56 57";
const BROWSER_LOAD_URL_OFFSET: usize = 0x10;

// MiHoYo.SDK.NetworkManager, verified against the supplied client profile.
// The price SDK starts its own Unity requests rather than using WebRequestUtils.
const SDK_GET_REQUEST: &str = "41 57 41 56 41 54 56 57 55 53 48 83 EC 50 0F 29 74 24 40 4C 89 CE 4D 89 C6 49 89 D7 49 89 CC 8B AC 24 B8 00 00 00 F3 0F 10 B4 24 B0 00 00 00 80 3D 8E 9D 6D EC 00";
const SDK_POST_REQUEST: &str = "41 57 41 56 41 54 56 57 55 53 48 83 EC 50 0F 29 74 24 40 4C 89 CE 4D 89 C6 49 89 D7 49 89 CC 8B AC 24 B8 00 00 00 F3 0F 10 B4 24 B0 00 00 00 80 3D 7A A4 6D EC 00";
const SDK_INVOKE: &str = "55 41 57 41 56 41 54 56 57 53 48 83 EC 60 48 8D 6C 24 60 48 C7 45 F0 FE FF FF FF 4C 89 CF 4D 89 C7 48 89 D6 49 89 CE";
const SDK_PRODUCT_RESPONSE: &str = "55 41 57 41 56 56 57 53 48 81 EC A8 00 00 00 48 8D AC 24 80 00 00 00 48 C7 45 18 FE FF FF FF 48 89 D7 48 89 4D 10 80";

pub struct Http;

impl MhyModule for MhyContext<Http> {
    unsafe fn init(&mut self) -> Result<()> {

        let web_request_utils_make_initial_url = util::pattern_scan_il2cpp(self.assembly_name, WEB_REQUEST_UTILS_MAKE_INITIAL_URL);
        if let Some(addr) = web_request_utils_make_initial_url {
            crate::plog!("web_request_utils_make_initial_url: {:x}", addr as usize);
            self.interceptor.attach(
                addr as usize,
                on_make_initial_url,
            )?;
        }
        else
        {
            crate::plog!("Failed to find web_request_utils_make_initial_url");
        }

        let browser_load_url = util::pattern_scan_il2cpp(self.assembly_name, BROWSER_LOAD_URL);
        if let Some(addr) = browser_load_url {
            let addr_offset = addr as usize + BROWSER_LOAD_URL_OFFSET;
            crate::plog!("browser_load_url: {:x}", addr_offset);
            self.interceptor.attach(
                addr_offset,
                on_browser_load_url,
            )?;
        }
        else
        {
            crate::plog!("Failed to find browser_load_url");
        }

        for (name, pattern) in [
            ("sdk_get_request", SDK_GET_REQUEST),
            ("sdk_post_request", SDK_POST_REQUEST),
        ] {
            if let Some(addr) = util::pattern_scan_il2cpp(self.assembly_name, pattern) {
                crate::plog!("{name}: {:x}", addr as usize);
                self.interceptor.attach(addr as usize, on_sdk_price_url)?;
            } else {
                crate::plog!("Failed to find {name}; SDK prices may remain unavailable");
            }
        }

        // Trace only product discovery boundaries, without logging SDK payloads.
        for (name, pattern, callback) in [
            ("sdk_invoke", SDK_INVOKE, on_sdk_invoke as unsafe extern "win64" fn(*mut Registers, usize)),
            ("sdk_product_response", SDK_PRODUCT_RESPONSE, on_sdk_product_response),
        ] {
            if let Some(addr) = util::pattern_scan_il2cpp(self.assembly_name, pattern) {
                self.interceptor.attach(addr as usize, callback)?;
                crate::plog!("{name}: {:x}", addr as usize);
            } else {
                crate::plog!("Failed to find {name}");
            }
        }
        
        Ok(())
    }

    unsafe fn de_init(&mut self) -> Result<()> {
        Ok(())
    }

    fn get_module_type(&self) -> super::ModuleType {
        ModuleType::Http
    }
}

/// http(s) only, file:// urls must not be rewritten
fn is_redirectable(url: &str) -> bool {
    url.starts_with("http://") || url.starts_with("https://")
}

pub(super) fn sdk_price_url(url: &str) -> Option<String> {
    let rest = url.strip_prefix("https://").or_else(|| url.strip_prefix("http://"))?;
    let (_, path) = rest.split_once('/')?;
    let endpoint = path.split(['?', '#']).next()?;
    let supported = ["hk4e_cn", "hk4e_global"].iter().any(|region| {
        ["listPriceTier", "listPriceTierV2"].iter().any(|api| {
            endpoint == format!("{region}/mdk/shopwindow/shopwindow/{api}")
        })
    });
    supported.then(|| format!("http://127.0.0.1:8088/{path}"))
}

/// SDK instance methods receive their URL in rdx; leave payloads and callbacks intact.
unsafe extern "win64" fn on_sdk_price_url(reg: *mut Registers, _: usize) {
    let Some(url) = managed_string((*reg).rdx) else { return; };
    if let Some(new_url) = sdk_price_url(&url) {
        // Do not log account tokens or query strings.
        let path = new_url.split(['?', '#']).next().unwrap();
        crate::plog!("SDK price request: {path}");
        if let Ok(text) = CString::new(new_url) {
            (*reg).rdx = marshal::ptr_to_string_ansi(&text) as u64;
        }
    }
}

unsafe fn managed_string(ptr: u64) -> Option<String> {
    let ptr = ptr as *const u8;
    if ptr.is_null() { return None; }
    let length = *(ptr.add(16) as *const i32);
    if !(0..=65536).contains(&length) { return None; }
    Some(String::from_utf16_lossy(std::slice::from_raw_parts(ptr.add(20) as *const u16, length as usize)))
}

unsafe extern "win64" fn on_sdk_invoke(reg: *mut Registers, _: usize) {
    if managed_string((*reg).rdx).as_deref() == Some("login_get_product_list") {
        crate::plog!("SDK product list requested");
    }
}

unsafe extern "win64" fn on_sdk_product_response(reg: *mut Registers, _: usize) {
    if let Some(response) = managed_string((*reg).rdx) {
        crate::plog!("SDK product response received: chars={}, product identifiers={}",
            response.len(), response.matches("productIdentifier").count());
    }
}

#[cfg(test)]
mod tests {
    use super::sdk_price_url;

    #[test]
    fn sdk_prices_reach_local_server_without_losing_queries() {
        for region in ["hk4e_cn", "hk4e_global"] {
            for api in ["listPriceTier", "listPriceTierV2"] {
                let path = format!("/{region}/mdk/shopwindow/shopwindow/{api}?currency=CNY&game_biz={region}");
                for scheme in ["http", "https"] {
                    let url = format!("{scheme}://sdk-static.mihoyo.com{path}");
                    assert_eq!(sdk_price_url(&url), Some(format!("http://127.0.0.1:8088{path}")));
                }
            }
        }
    }

    #[test]
    fn unrelated_sdk_and_local_file_requests_are_not_rewritten() {
        for url in [
            "file:///hk4e_cn/mdk/shopwindow/shopwindow/listPriceTier",
            "https://sdk-static.mihoyo.com/hk4e_cn/mdk/shield/api/loadConfig",
            "https://sdk-static.mihoyo.com/hk4e_cn/mdk/shopwindow/shopwindow/listPriceTierOther",
        ] {
            assert_eq!(sdk_price_url(url), None);
        }
    }
}

unsafe extern "win64" fn on_make_initial_url(reg: *mut Registers, _: usize) {
    let str_length = *((*reg).rcx.wrapping_add(16) as *const u32);
    let str_ptr = (*reg).rcx.wrapping_add(20) as *const u8;

    let slice = std::slice::from_raw_parts(str_ptr, (str_length * 2) as usize);
    let url = String::from_utf16le(slice).unwrap();

    if !is_redirectable(&url) {
        return;
    }

    let mut new_url = String::from("http://127.0.0.1:8088");

    url.split('/').skip(3).for_each(|s| {
        new_url.push_str("/");
        new_url.push_str(s);
    });

    if !url.contains("/query_cur_region") {
        crate::plog!("Redirect: {url} -> {new_url}");
        (*reg).rcx =
            marshal::ptr_to_string_ansi(CString::new(new_url.as_str()).unwrap().as_c_str()) as u64;
    }
}

unsafe extern "win64" fn on_browser_load_url(reg: *mut Registers, _: usize) {
    let str_length = *((*reg).rdx.wrapping_add(16) as *const u32);
    let str_ptr = (*reg).rdx.wrapping_add(20) as *const u8;

    let slice = std::slice::from_raw_parts(str_ptr, (str_length * 2) as usize);
    let url = String::from_utf16le(slice).unwrap();

    if !is_redirectable(&url) {
        return;
    }

    let mut new_url = String::from("http://127.0.0.1:8088");
    url.split('/').skip(3).for_each(|s| {
        new_url.push_str("/");
        new_url.push_str(s);
    });

    crate::plog!("Browser::LoadURL: {url} -> {new_url}");

    (*reg).rdx =
        marshal::ptr_to_string_ansi(CString::new(new_url.as_str()).unwrap().as_c_str()) as u64;
}
