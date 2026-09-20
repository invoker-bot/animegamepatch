//! forwards the Astrolabe_* exports to Astrolabe_orig.dll

use std::ffi::CString;
use std::sync::atomic::{AtomicI64, Ordering};

use windows::core::{PCSTR, PCWSTR};
use windows::Win32::Foundation::{HINSTANCE, HMODULE};
use windows::Win32::System::LibraryLoader::{
    GetModuleFileNameW, GetProcAddress, LoadLibraryW,
};

include!(concat!(env!("OUT_DIR"), "/astrolabe_proxy.rs"));

/// DllMain's hinstDll is this DLL's own module handle.
///
/// GetModuleFileNameW(None) resolves against the *main EXE* (.../7.0.0/
/// YuanShen.exe), not against this proxy DLL -- so the constructed path pointed
/// at .../7.0.0/Astrolabe_orig.dll, which does not exist, and LoadLibraryW died
/// with 0x8007007E. That silently made every forwarded Astrolabe_* export hit
/// the missing() stub. The real DLL lives in YuanShen_Data/Plugins/.
static OUR_MODULE: AtomicI64 = AtomicI64::new(0);

pub unsafe fn set_module(h: HINSTANCE) {
    OUR_MODULE.store(h.0 as i64, Ordering::SeqCst);
}

/// stub for exports the real dll lacks
unsafe extern "C" fn missing() -> usize {
    0
}

/// Astrolabe exports that run the anti-cheat's *own* periodic self-checks.
///
/// This proxy sits in the Astrolabe.dll module slot, so those checks inspect
/// our image rather than the signed original, fail, and their failure path
/// unwinds a stack straight into ntdll!RtlVirtualUnwind2+0xDC7 about 100s into
/// every session -- the "The client is damaged, please reinstall the client"
/// death. A private server has no use for the check, so route these to the
/// missing() stub instead of the real implementation.
///
/// `LUNAGC_DISABLE=detect` (or the same line in %TEMP%\lunagc-disable.txt)
/// forwards them normally, kept for A/B testing the diagnosis.
const NEUTRALIZE: &[&str] = &[
    "Astrolabe_AddDetectionThread",
    "Astrolabe_RemoveDetectionThread",
    "Astrolabe_InstallMemMonitor",
    "Astrolabe_InstallHang",
    "Astrolabe_OnHang",
];

/// fills the table from Astrolabe_orig.dll, next to this dll
pub unsafe fn init() {
    // seed first, so no slot is ever 0
    let stub = missing as unsafe extern "C" fn() -> usize as usize;
    for slot in (&raw mut REAL).as_mut().unwrap() {
        *slot = stub;
    }

    // beside this dll, not the cwd (None here would give the exe's directory)
    let mut buffer = [0u16; 260];
    let len = GetModuleFileNameW(
        HMODULE::from(HINSTANCE(OUR_MODULE.load(Ordering::SeqCst) as isize)),
        &mut buffer,
    ) as usize;
    let mut path: Vec<u16> = buffer[..len].to_vec();
    while path.last().is_some_and(|&c| c != b'\\' as u16) {
        path.pop();
    }
    path.extend("Astrolabe_orig.dll\0".encode_utf16());

    let real = match LoadLibraryW(PCWSTR(path.as_ptr())) {
        Ok(handle) => handle,
        Err(e) => {
            crate::plog!(
                "[proxy] could not load Astrolabe_orig.dll: {e}. The game's own Astrolabe \
                 functions will do nothing - copy GenshinImpact_Data\\Plugins\\Astrolabe.dll \
                 beside the patch under that name."
            );
            return;
        }
    };

    let mut resolved = 0;
    for (i, name) in NAMES.iter().enumerate() {
        let c_name = CString::new(*name).unwrap();
        if let Some(addr) = GetProcAddress(real, PCSTR(c_name.as_ptr() as *const u8)) {
            REAL[i] = addr as usize;
            resolved += 1;
        } else {
            crate::plog!("[proxy] Astrolabe_orig.dll does not export {name}");
        }
    }

    crate::plog!(
        "[proxy] forwarding {}/{} Astrolabe exports to Astrolabe_orig.dll",
        resolved,
        NAMES.len()
    );

    // see NEUTRALIZE: done after resolution so the A/B switch can compare a
    // fully-forwarded table against a neutralized one
    if !crate::is_off(&crate::disabled(), "detect") {
        for (i, name) in NAMES.iter().enumerate() {
            if NEUTRALIZE.contains(name) {
                REAL[i] = stub;
                crate::plog!("[proxy] neutralized {name} (anti-cheat self-check)");
            }
        }
    }
    let _: HMODULE = real;
}
