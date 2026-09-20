//! On-disk signature decoy for the Astrolabe module slot.
//!
//! mhypbase.dll statically links LIEF + OpenSSL 1.0.2j and verifies the
//! Authenticode signature of whichever file occupies the Astrolabe.dll slot
//! against miHoYo's pinned signing certificate (the cert is embedded in
//! mhypbase at +0x19f5d77, byte-identical to the stock signer). Our proxy is
//! unsigned, so that check kills the session ~90s in with a poisoned stack
//! unwind that faults inside ntdll!RtlVirtualUnwind2 -- the "The client is
//! damaged, please reinstall the client" dialog.
//!
/// Two verification gates fire in sequence, and both read the file from DISK:
///   gate 1  ~2.5s after load - security directory present, signer == pinned
///   gate 2   ~83s after load - full Authenticode digest
/// Gate 1 is the proof that a disk read is happening: the certificate table
/// sits at a file offset beyond every section, so it is absent from the mapped
/// image entirely. R13 appended a real-but-wrong-digest signature to our file
/// and still cleared gate 1 -> the verifier opened the file, it did not read
/// the mapping.
///
/// The digest is unforgeable without miHoYo's private key, but the verifier
/// only ever looks at the file. The loader has already mapped our proxy by the
/// time DllMain runs, and an image section outlives its file name -- renaming
/// a mapped DLL keeps every page valid and every export callable. So we
/// rename ourselves aside and drop the signed original into our slot. The
/// process keeps executing patched code while the verifier reads a perfectly
/// valid stock DLL, and both gates pass against it.
///
/// `Astrolabe_orig.dll` is the stock image proxy.rs already forwards the 47
/// exports to, so it is guaranteed to sit beside us and to be genuinely
/// signed (all known stock copies hash to fa6f7aef4bbd9a5f017f62afaa79c864).
///
/// DLL_PROCESS_DETACH puts the patched file back so the next launch loads the
/// patch again. A hard death (crash, TerminateProcess) skips detach and leaves
/// the stock file in place; the next launch then runs the unpatched client and
/// reaches the official servers ("account or password error"). A re-run of
/// `task patch` repairs that, and tools/patch_game.ps1 also clears the
/// leftover live copy.
///
/// `LUNAGC_DISABLE=swap` skips all of this, kept for A/B testing.

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};

use windows::core::PCWSTR;
use windows::Win32::Foundation::{BOOL, HINSTANCE, HMODULE};
use windows::Win32::Storage::FileSystem::{
    CopyFileW, DeleteFileW, GetFileAttributesW, MoveFileExW, MoveFileW, MOVEFILE_REPLACE_EXISTING,
};
use windows::Win32::System::LibraryLoader::GetModuleFileNameW;

/// marks our own (patched) image on disk while a session is running
const LIVE_SUFFIX: &str = ".lunagc-live";
/// the stock, signed original the proxy already forwards to
const ORIG_NAME: &str = "Astrolabe_orig.dll";

/// set once engage() succeeded, so detach knows there is something to put back
static SWAPPED: AtomicBool = AtomicBool::new(false);
/// our own module handle, captured in engage(): GetModuleFileNameW(NULL)
/// resolves the *main executable*, not us, so detach cannot rediscover the path
/// on its own. Attach always precedes detach, so this is set before any use.
static OWN_HINST: AtomicI64 = AtomicI64::new(0);

/// our own full path as the loader recorded it at load time. Renaming the file
/// afterwards does not change this -- the loader's module entry keeps the name
/// it parsed, which is exactly why the proxy keeps resolving Astrolabe_orig.dll
/// beside us after the swap.
unsafe fn own_path(hinst: HINSTANCE) -> Option<PathBuf> {
    let mut buffer = [0u16; 260];
    let len = GetModuleFileNameW(HMODULE::from(hinst), &mut buffer) as usize;
    if len == 0 || len >= buffer.len() {
        return None;
    }
    Some(PathBuf::from(OsString::from_wide(&buffer[..len])))
}

/// nul-terminated UTF-16 for the wide file APIs
fn wide(path: &PathBuf) -> Vec<u16> {
    let s = path.to_string_lossy().into_owned();
    let mut v: Vec<u16> = s.encode_utf16().collect();
    v.push(0);
    v
}

fn exists(path: &PathBuf) -> bool {
    // GetFileAttributesW returns the flags, not a Result: a missing file comes
    // back as INVALID_FILE_ATTRIBUTES (all bits set)
    unsafe { GetFileAttributesW(PCWSTR::from_raw(wide(path).as_ptr())) != 0xFFFF_FFFF }
}

/// call from DLL_PROCESS_ATTACH, before proxy::init(). Never fails the load:
/// every error path logs and leaves the process running unswapped, which is
/// exactly the behaviour we already had.
pub unsafe fn engage(hinst: HINSTANCE) {
    OWN_HINST.store(hinst.0 as i64, Ordering::SeqCst);
    let path = match own_path(hinst) {
        Some(p) => p,
        None => {
            crate::plog!("[swap] could not resolve our own path - leaving the file as-is");
            return;
        }
    };
    let dir = match path.parent() {
        Some(d) => d,
        None => {
            crate::plog!("[swap] our path has no directory - leaving the file as-is");
            return;
        }
    };

    let name = match path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n,
        None => {
            crate::plog!("[swap] our path has no file name - leaving the file as-is");
            return;
        }
    };

    let live = dir.join(format!("{name}{LIVE_SUFFIX}"));
    let orig = dir.join(ORIG_NAME);

    if !exists(&orig) {
        crate::plog!(
            "[swap] {ORIG_NAME} is missing beside us - nothing signed to put in the slot"
        );
        return;
    }

    // Our DllMain running at all proves the loader read a patched file for this
    // slot, so any live copy left by an earlier session is stale - a fresh
    // `task patch` deploy already replaced it. Drop it rather than the running
    // image.
    if exists(&live) {
        match DeleteFileW(PCWSTR::from_raw(wide(&live).as_ptr())) {
            Ok(()) => crate::plog!("[swap] dropped stale {name}{LIVE_SUFFIX}"),
            Err(e) => {
                crate::plog!(
                    "[swap] stale {name}{LIVE_SUFFIX} is not deletable ({e}) - aborting"
                );
                return;
            }
        }
    }

    // 1. step aside. The mapping follows the file object, not the name, so our
    //    code stays mapped and our exports stay callable after this.
    if let Err(e) = MoveFileW(
        PCWSTR::from_raw(wide(&path).as_ptr()),
        PCWSTR::from_raw(wide(&live).as_ptr()),
    ) {
        crate::plog!("[swap] cannot rename {name} aside ({e}) - staying unsigned");
        return;
    }

    // 2. take the slot with the signed original.
    match CopyFileW(
        PCWSTR::from_raw(wide(&orig).as_ptr()),
        PCWSTR::from_raw(wide(&path).as_ptr()),
        BOOL(0),
    ) {
        Ok(()) => {
            SWAPPED.store(true, Ordering::SeqCst);
            crate::plog!(
                "[swap] {name} -> {name}{LIVE_SUFFIX}, on-disk slot now holds the signed {ORIG_NAME}"
            );
        }
        Err(e) => {
            // the slot is empty and unsigned - undo step 1 rather than ship a
            // game whose Astrolabe.dll vanished from disk
            crate::plog!("[swap] the {ORIG_NAME} copy failed ({e}) - putting {name} back");
            let _ = MoveFileW(
                PCWSTR::from_raw(wide(&live).as_ptr()),
                PCWSTR::from_raw(wide(&path).as_ptr()),
            );
        }
    }
}

/// call from DLL_PROCESS_DETACH. Restores the patched image so the next launch
/// loads the patch. A crash never gets here - see the module docs.
pub unsafe fn restore() {
    if !SWAPPED.load(Ordering::SeqCst) {
        return;
    }
    // NULL here would resolve the main executable, not our DLL -- see OWN_HINST
    let path = match own_path(HINSTANCE(OWN_HINST.load(Ordering::SeqCst) as isize)) {
        Some(p) => p,
        None => return,
    };
    let dir = match path.parent() {
        Some(d) => d,
        None => return,
    };
    let name = match path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n,
        None => return,
    };
    let live = dir.join(format!("{name}{LIVE_SUFFIX}"));
    if !exists(&live) {
        crate::plog!("[swap] no live copy to restore from");
        return;
    }

    // replace the stock file in one hop if the OS will let us; a verifier that
    // still holds the file open can make the target unreplaceable
    if MoveFileExW(
        PCWSTR::from_raw(wide(&live).as_ptr()),
        PCWSTR::from_raw(wide(&path).as_ptr()),
        MOVEFILE_REPLACE_EXISTING,
    )
    .is_ok()
    {
        crate::plog!("[swap] restored {name} from {name}{LIVE_SUFFIX}");
        return;
    }

    let _ = DeleteFileW(PCWSTR::from_raw(wide(&path).as_ptr()));
    match MoveFileW(
        PCWSTR::from_raw(wide(&live).as_ptr()),
        PCWSTR::from_raw(wide(&path).as_ptr()),
    ) {
        Ok(()) => crate::plog!("[swap] restored {name} from {name}{LIVE_SUFFIX} (delete+rename)"),
        Err(e) => crate::plog!("[swap] could not restore {name} ({e}) - re-run `task patch`"),
    }
}
