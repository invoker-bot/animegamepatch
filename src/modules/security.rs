use std::ffi::CString;

use crate::marshal;

use super::{MhyContext, MhyModule, ModuleType};
use anyhow::Result;
use ilhook::x64::Registers;
use crate::util;

const MHYRSA_PERFORM_CRYPTO_ACTION: &str = "E8 ? ? ? ? 48 83 C4 20 66 41 C7 06 30 82";
const KEY_SIGN_CHECK: &str = "E8 ? ? ? ? 48 83 C4 30 84 C0 74 ? 41 8B 04 24";
const KEY_SIGN_CHECK_OFFSET: usize = 0x5;
const SDK_UTIL_RSA_ENCRYPT: &str = "41 57 41 56 41 55 41 54 56 57 55 53 48 83 EC ?? 49 89 D6 48 89 CE 48 8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 49 89 C5";

const KEY_SIZE: usize = 268;
static SERVER_PUBLIC_KEY: &[u8] = include_bytes!("../../server_public_key.bin");
static SDK_PUBLIC_KEY: &str = include_str!("../../sdk_public_key.xml");

pub struct Security;

impl MhyModule for MhyContext<Security> {
    unsafe fn init(&mut self) -> Result<()> {

        let mhyrsa_perform_crypto_action = util::pattern_scan_code(self.assembly_name, MHYRSA_PERFORM_CRYPTO_ACTION);
        if let Some(addr) = mhyrsa_perform_crypto_action {
            crate::plog!("mhyrsa_perform_crypto_action: {:x}", addr as usize);
            self.interceptor.attach(
                addr as usize,
                on_mhy_rsa,
            )?;
        }
        else
        {
            crate::plog!("Failed to find mhyrsa_perform_crypto_action");
        }

        let key_sign_check = util::pattern_scan_code(self.assembly_name, KEY_SIGN_CHECK);
        if let Some(addr) = key_sign_check {
            let addr_offset = addr as usize + KEY_SIGN_CHECK_OFFSET;
            crate::plog!("key_sign_check: {:x}", addr_offset as usize);
            self.interceptor.attach(
                addr_offset as usize,
                after_key_sign_check,
            )?;
        }
        else
        {
            crate::plog!("Failed to find key_sign_check");
        }


        let sdk_util_rsa_encrypt = util::pattern_scan_il2cpp(self.assembly_name, SDK_UTIL_RSA_ENCRYPT);
        if let Some(addr) = sdk_util_rsa_encrypt {
            crate::plog!("sdk_util_rsa_encrypt: {:x}", addr as usize);
            self.interceptor.attach(
                addr as usize,
                on_sdk_util_rsa_encrypt,
            )?;
        }
        else
        {
            crate::plog!("Failed to find sdk_util_rsa_encrypt");
        }

        Ok(())
    }

    unsafe fn de_init(&mut self) -> Result<()> {
        Ok(())
    }

    fn get_module_type(&self) -> super::ModuleType {
        ModuleType::Security
    }
}

unsafe extern "win64" fn after_key_sign_check(reg: *mut Registers, _: usize) {
    crate::plog!("key sign check!");
    (*reg).rax = 1
}

unsafe extern "win64" fn on_mhy_rsa(reg: *mut Registers, _: usize) {
    crate::plog!("key: {:X}", *((*reg).r12 as *const u64));
    crate::plog!("len: {:X}", (*reg).r8 -3);

    if ((*reg).r8 as usize) - 3 == KEY_SIZE {
        crate::plog!("[*] key replaced");

        std::ptr::copy_nonoverlapping(
            SERVER_PUBLIC_KEY.as_ptr(),
            (*reg).r13 as *mut u8,
            SERVER_PUBLIC_KEY.len(),
        );
    }
}

unsafe extern "win64" fn on_sdk_util_rsa_encrypt(reg: *mut Registers, _: usize) {
    // rcx = key, rdx = plaintext
    let Some(original) = read_sdk_string((*reg).rcx) else { return; };
    let Some(plaintext) = read_sdk_string((*reg).rdx) else { return; };
    if !should_replace_sdk_key(&original, &plaintext) {
        crate::plog!("[*] SDK RSA: original key preserved (modulus bytes: {:?})", rsa_modulus_bytes(&original));
        return;
    }
    crate::plog!("[*] SDK RSA: login key replaced");
    (*reg).rcx =
        marshal::ptr_to_string_ansi(CString::new(SDK_PUBLIC_KEY).unwrap().as_c_str()) as u64;
}

unsafe fn read_sdk_string(pointer: u64) -> Option<String> {
    if pointer == 0 { return None; }
    let length = *((pointer + 16) as *const i32);
    if !(0..=16384).contains(&length) { return None; }
    String::from_utf16(std::slice::from_raw_parts((pointer + 20) as *const u16, length as usize)).ok()
}

fn rsa_modulus_bytes(xml: &str) -> Option<usize> {
    let value = xml.split_once("<Modulus>")?.1.split_once("</Modulus>")?.0;
    let mut length = 0;
    let mut padding = 0;
    for b in value.bytes().filter(|b| !b.is_ascii_whitespace()) {
        if b == b'=' { padding += 1; }
        else if padding != 0 || !(b.is_ascii_alphanumeric() || b == b'+' || b == b'/') { return None; }
        length += 1;
    }
    if length == 0 || length % 4 != 0 || padding > 2 { return None; }
    Some(length / 4 * 3 - padding)
}

fn should_replace_sdk_key(original: &str, plaintext: &str) -> bool {
    // NoticeManager encrypts its cookie with a separate 2048-bit key. Replacing
    // it with the 1024-bit login key throws before the WebView loads its URL.
    let replacement_size = rsa_modulus_bytes(SDK_PUBLIC_KEY);
    replacement_size == Some(128) && rsa_modulus_bytes(original) == replacement_size
        && plaintext.len() <= 128 - 11 // RSA PKCS#1 v1.5 maximum UTF-8 payload.
}

#[cfg(test)]
mod tests {
    use super::*;

    fn public_key(modulus_bytes: usize) -> String {
        let padding = (3 - modulus_bytes % 3) % 3;
        let length = modulus_bytes.div_ceil(3) * 4;
        format!("<RSAKeyValue><Modulus>{}{}</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>",
            "A".repeat(length - padding), "=".repeat(padding))
    }

    #[test]
    fn announcement_cookie_keeps_its_original_2048_bit_key() {
        assert!(!should_replace_sdk_key(&public_key(256), &"x".repeat(180)));
        assert!(!should_replace_sdk_key(&public_key(256), "short cookie"));
    }

    #[test]
    fn short_login_payload_still_uses_server_key() {
        assert!(should_replace_sdk_key(&public_key(128), "password"));
        assert!(should_replace_sdk_key(&public_key(128), &"x".repeat(117)));
    }

    #[test]
    fn overlong_or_unknown_inputs_are_not_downgraded() {
        assert!(!should_replace_sdk_key(&public_key(128), &"x".repeat(118)));
        assert!(!should_replace_sdk_key(&public_key(128), &"汉".repeat(40)));
        assert!(!should_replace_sdk_key(&public_key(512), "data"));
        for unknown in ["", "not an XML key", "<RSAKeyValue><Modulus>?</Modulus></RSAKeyValue>",
                "<RSAKeyValue><Modulus>AA=A</Modulus></RSAKeyValue>"] {
            assert!(!should_replace_sdk_key(unknown, "data"));
        }
    }

    #[test]
    fn formatted_xml_keeps_login_key_recognition() {
        let formatted = public_key(128).replace("<Modulus>", "<Modulus>\n  ").replace("</Modulus>", "\n</Modulus>");
        assert!(should_replace_sdk_key(&formatted, "password"));
    }
}
