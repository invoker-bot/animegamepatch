#![feature(str_from_utf16_endian)]

use std::{sync::RwLock};

use lazy_static::lazy_static;
use modules::{CcpBlocker, Misc};
use windows::Win32::System::Console;
use windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH;
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

use crate::modules::{Http, MhyContext, ModuleManager, Security, WinHttp};

unsafe fn thread_func() {
    let mut module_manager = MODULE_MANAGER.write().unwrap();

    // Block query_security_file ASAP
    module_manager.enable(MhyContext::<CcpBlocker>::new(""));

    util::disable_memprotect_guard();
    Console::AllocConsole().unwrap();

    crate::plog!("Genshin Impact encryption patch\nMade by xeondev\n(Modded for all version >= 6.5)");
    crate::plog!("Log file: {}", log::path().display());

    let mut buffer = [0u8; 260];
    GetModuleFileNameA(None, &mut buffer);
    let exe_path = CStr::from_ptr(buffer.as_ptr() as *const i8).to_str().unwrap();
    let exe_name = Path::new(exe_path).file_name().unwrap().to_str().unwrap();
    crate::plog!("Current executable name: {}", exe_name);

    if exe_name != "GenshinImpact.exe" && exe_name != "YuanShen.exe" {
        crate::plog!("Executable is not Genshin. Skipping initialization.");
        return;
    }

    crate::plog!("Initializing modules...");

    module_manager.enable(MhyContext::<Security>::new(&exe_name));
    marshal::find();
    module_manager.enable(MhyContext::<Http>::new(&exe_name));
    module_manager.enable(MhyContext::<Misc>::new(&exe_name));

    // the account sdk uses winhttp, not the C# path above
    module_manager.enable(MhyContext::<WinHttp>::new(&exe_name));

    crate::plog!("Successfully initialized!");

    // GameAssembly/mhyprot/zf_cef load after our DllMain, and the crash window
    // is the first ~30s (bundle load). A 2s tick left the slot where the
    // faulting module lives empty, so the interesting address printed as a raw
    // number; keep the table tight while it matters, then back off.
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
        exclog::install();

        // remember our own module handle before proxy::init resolves
        // Astrolabe_orig.dll relative to this dll's directory
        proxy::set_module(hinst);

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
    }

    true
}
