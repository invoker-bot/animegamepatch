#![feature(str_from_utf16_endian)]

use std::{sync::RwLock};

use lazy_static::lazy_static;
use modules::{CcpBlocker, Misc};
use windows::Win32::System::Console;
use windows::Win32::System::SystemServices::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH};
use windows::Win32::{Foundation::HINSTANCE, System::LibraryLoader::GetModuleFileNameA};
use std::ffi::CStr;
use std::path::Path;

mod log;
mod proxy;
mod interceptor;
mod marshal;
mod modules;
mod util;
mod exclog;
mod swap;

use crate::modules::{Http, MhyContext, ModuleManager, Security, WinHttp};

/// Bisection switch for the crash hunt. Reads a comma list from the
/// `LUNAGC_DISABLE` env var, or from `%TEMP%\lunagc-disable.txt` -- the file
/// is the reliable path, since Start-Process across the UAC boundary drops
/// our session env vars. Recognised names: ccp, security, http, misc,
/// winhttp, memguard, console, detect. Absent/empty = full patch.
/// `detect` is special: it does not disable a hook, it re-enables the
/// anti-cheat's own self-check exports that proxy.rs neutralizes by default.
/// `exclog` gates the exception recorder. It is OFF by default now -- see
/// recorder_wanted() -- because installing it is itself detectable.
/// `swap` gates swap.rs: leaving the signed stock DLL in the on-disk slot
/// while our patched image stays mapped, so the signature verifier reads a
/// file it is happy with. Disabling it brings back the ~90s kill.
fn disabled() -> Vec<String> {
    let raw = std::env::var("LUNAGC_DISABLE")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            std::fs::read_to_string(std::env::temp_dir().join("lunagc-disable.txt")).ok()
        })
        .unwrap_or_default();
    raw.split(',')
        .filter(|s| !s.is_empty())
        .map(|s| s.trim().to_ascii_lowercase())
        .collect()
}

fn is_off(off: &[String], name: &str) -> bool {
    off.iter().any(|s| s == name)
}

fn is_game_executable(name: &str) -> bool {
    name.eq_ignore_ascii_case("GenshinImpact.exe") || name.eq_ignore_ascii_case("YuanShen.exe")
}

#[cfg(test)]
mod executable_tests {
    use super::is_game_executable;

    #[test]
    fn windows_launch_path_case_does_not_disable_the_patch() {
        for name in ["YuanShen.exe", "yuanshen.exe", "YUANSHEN.EXE", "GenshinImpact.exe", "genshinimpact.exe"] {
            assert!(is_game_executable(name));
        }
        assert!(!is_game_executable("launcher.exe"));
        assert!(!is_game_executable("YuanShen.exe.backup"));
    }
}

/// Whether exclog's exception recorder should be installed at all.
///
/// AddVectoredExceptionHandler(1) puts us FIRST in the chain, ahead of
/// mhypbase's own handler, and that ordering is visible to the anti-cheat.
/// Two otherwise-identical idle sessions, swap engaged in both:
///   recorder OFF -> ran for 80 minutes (killed only by the operator)
///   recorder ON  -> died at ~94s, AV at ntdll!RtlVirtualUnwind2+0xFB77,
///                   caller mhypbase.dll+0x195AFB2 -- the same kill the
///                   signature gate used, but with the signed stock DLL
///                   sitting in the on-disk slot the whole time
/// So the recorder is opt-in and exists only for crash hunting.
/// `LUNAGC_DISABLE=exclog` still force-kills it even when asked for.
fn recorder_wanted(off: &[String]) -> bool {
    if is_off(off, "exclog") {
        return false;
    }
    // Start-Process across the UAC boundary drops our session env vars, so a
    // marker file beside the disable list is the reliable way to ask for it
    std::env::var("LUNAGC_EXCLOG")
        .ok()
        .filter(|s| !s.is_empty())
        .is_some()
        || std::path::Path::new(&std::env::temp_dir())
            .join("lunagc-exclog.txt")
            .exists()
}

unsafe fn thread_func() {
    let mut module_manager = MODULE_MANAGER.write().unwrap();

    let off = disabled();
    crate::plog!("LUNAGC_DISABLE: {:?}", off);

    // Block query_security_file ASAP
    if !is_off(&off, "ccp") {
        module_manager.enable(MhyContext::<CcpBlocker>::new(""));
    }

    if !is_off(&off, "memguard") {
        util::disable_memprotect_guard();
    }
    if !is_off(&off, "console") {
        Console::AllocConsole().unwrap();
    }

    crate::plog!("Genshin Impact encryption patch\nMade by xeondev\n(Modded for all version >= 6.5)");
    crate::plog!("Log file: {}", log::path().display());

    let mut buffer = [0u8; 260];
    GetModuleFileNameA(None, &mut buffer);
    let exe_path = CStr::from_ptr(buffer.as_ptr() as *const i8).to_str().unwrap();
    let exe_name = Path::new(exe_path).file_name().unwrap().to_str().unwrap();
    crate::plog!("Current executable name: {}", exe_name);

    if !is_game_executable(exe_name) {
        crate::plog!("Executable is not Genshin. Skipping initialization.");
        return;
    }

    crate::plog!("Initializing modules...");

    if !is_off(&off, "security") {
        module_manager.enable(MhyContext::<Security>::new(&exe_name));
    }
    if !(is_off(&off, "http") && is_off(&off, "security")) {
        marshal::find();
    }
    if !is_off(&off, "http") {
        module_manager.enable(MhyContext::<Http>::new(&exe_name));
        modules::start_native_sdk_prices();
    }
    if !is_off(&off, "misc") {
        module_manager.enable(MhyContext::<Misc>::new(&exe_name));
    }

    // the account sdk uses winhttp, not the C# path above
    if !is_off(&off, "winhttp") {
        module_manager.enable(MhyContext::<WinHttp>::new(&exe_name));
    }

    crate::plog!("Successfully initialized!");

    // The handler is back on, so the table it reads has to stay fresh.
    // Gates on the same switch as exclog::install() -- a resolver thread with
    // no recorder is just an extra thread for the anti-cheat to react to.
    //
    // GameAssembly/mhyprot/zf_cef load after our DllMain, and the crash window
    // is the first ~30s (bundle load). A 2s tick left the slot where the
    // faulting module lives empty, so the interesting address printed as a raw
    // number; keep the table tight while it matters, then back off.
    if recorder_wanted(&off) {
        std::thread::spawn(|| {
        // 50ms for 30s: a refresh is ~50us, so this is still idle
        for _ in 0..600 {
            std::thread::sleep(std::time::Duration::from_millis(50));
            exclog::refresh();
        }
        // 2s for another 10 min, in case it dies later in the session
        for _ in 0..300 {
            std::thread::sleep(std::time::Duration::from_secs(2));
            exclog::refresh();
        }
        });
    }
}

lazy_static! {
    static ref MODULE_MANAGER: RwLock<ModuleManager> = RwLock::new(ModuleManager::default());
}

#[no_mangle]
#[allow(non_snake_case)]
unsafe extern "system" fn DllMain(hinst: HINSTANCE, call_reason: u32, _: *mut ()) -> bool {
    if call_reason == DLL_PROCESS_ATTACH {
        log::start_session();

        // see the exception that starts the crash, not just the unwinder fault
        // WER is disabled on this box so this is our only crash recorder
        //
        // -- BISECTION: installing this handler changes the failure mode. With
        //    it absent the game AVs in ntdll!RtlVirtualUnwind2 at 100s; with it
        //    present the process leaves silently at 42-64s before that window
        //    opens. Both are symptoms, so the recorder is switchable.
        //    (It installs FIRST in the chain -- AddVectoredExceptionHandler(1)
        //    -- ahead of mhypbase's own handler, and runs on every first-chance
        //    exception. exclog.rs documents two previous revisions where the
        //    recorder itself was the killer; the current one touches only a
        //    file mapping on the exception path.)
        //
        // -- UPDATE: with the swap fix in, that ordering itself is the trigger.
        //    An idle session with the recorder installed dies at ~94s at the
        //    same ntdll!RtlVirtualUnwind2 site while the identical session
        //    without it survives 80 minutes, both with the signed stock DLL in
        //    the on-disk slot. So it is opt-in now (LUNAGC_EXCLOG=1 or
        //    %TEMP%\lunagc-exclog.txt), not switchable-by-default. See
        //    recorder_wanted().
        if recorder_wanted(&disabled()) {
            exclog::install();
        }

        // remember our own module handle before proxy::init resolves
        // Astrolabe_orig.dll relative to this dll's directory
        proxy::set_module(hinst);

        // swap.rs must run here, not on the thread: our DllMain executing at
        // all means the loader has already mapped this (patched) image, and an
        // image section outlives its file name. So the on-disk slot can now be
        // replaced with the signed stock DLL without unmapping our code.
        // Before proxy::init, so the forwarding targets resolve against the
        // same directory either way.
        if !is_off(&disabled(), "swap") {
            swap::engage(hinst);
            // AccountPlatNative.dll loads with the login flow, long after this
            // DllMain returns, so its slot is swapped from a poller thread
            // instead -- see swap::engage_apn for why an external timer cannot
            // hit the window. Spawning here, under the loader lock, only delays
            // the thread until this DllMain returns; the SDK is not due for
            // another ~16s.
            swap::engage_apn();
        }

        // here, not on the thread: the game may call the exports once DllMain returns
        proxy::init();

        #[cfg(debug_assertions)]
        {
            thread_func();
        }
        #[cfg(not(debug_assertions))]
        {
            std::thread::spawn(|| thread_func());
        }
    } else if call_reason == DLL_PROCESS_DETACH {
        // A graceful exit puts the patched image back so the next launch is
        // patched again. A crash or TerminateProcess never reaches this, which
        // is why tools/patch_game.ps1 also clears the leftover live copy.
        if !is_off(&disabled(), "swap") {
            swap::restore();
        }
    }

    true
}
