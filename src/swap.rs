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
/// The same treatment for the passport SDK, in `engage_apn` below -- a module
/// that loads *late*, which is why it needs its own entry point.
///
/// `LUNAGC_DISABLE=swap` skips all of this, kept for A/B testing.

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::OnceLock;
use std::time::Duration;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{BOOL, HINSTANCE, HMODULE};
use windows::Win32::Storage::FileSystem::{
    CopyFileW, DeleteFileW, GetFileAttributesW, MoveFileExW, MoveFileW, MOVEFILE_REPLACE_EXISTING,
};
use windows::Win32::System::LibraryLoader::{GetModuleFileNameW, GetModuleHandleW};
use windows::Win32::System::Threading::GetCurrentProcessId;

use crate::util::wide_str;

/// marks our own (patched) image on disk while a session is running
const LIVE_SUFFIX: &str = ".lunagc-live";
/// the stock, signed original the proxy already forwards to
const ORIG_NAME: &str = "Astrolabe_orig.dll";
/// the passport SDK -- the *other* file `task patch` edits in place. Its
/// passport URLs and embedded RSA key are rewritten byte-for-byte, so the
/// on-disk Authenticode digest is as broken as ours, and the same verifier
/// opens the same file.
const APN_NAME: &str = "AccountPlatNative.dll";
/// pristine backup that tools/patch_game.ps1 keeps for `task patch:reset` --
/// the APN equivalent of ORIG_NAME
const APN_STOCK: &str = "AccountPlatNative.dll.lunagc-bak";
/// poll cadence / budget for engage_apn(): the SDK loads with the login flow,
/// so a minute covers every login-delay case seen so far
const APN_POLL_MS: u64 = 50;
const APN_POLL_ATTEMPTS: u32 = 1200;

/// set once engage() succeeded, so detach knows there is something to put back
static SWAPPED: AtomicBool = AtomicBool::new(false);
/// our own module handle, captured in engage(): GetModuleFileNameW(NULL)
/// resolves the *main executable*, not us, so detach cannot rediscover the path
/// on its own. Attach always precedes detach, so this is set before any use.
static OWN_HINST: AtomicI64 = AtomicI64::new(0);
/// where our own patched image was parked, so restore() moves that exact file
/// back. This is pinned rather than derived from the slot name because
/// live_path() may pick a per-process name -- see the stale-copy fallback.
static ASTROLABE_LIVE: OnceLock<PathBuf> = OnceLock::new();

/// the APN slot we swapped, for restore(). Unlike Astrolabe this cannot be
/// rediscovered from any module handle at detach time: APN's own path is stable
/// across the rename (it never moves), but a handle stored here would be NULL
/// if the SDK was unloaded again before detach, and NULL resolves to the main
/// executable. So the path is pinned at swap time. One swap per process.
static APN_PATH: OnceLock<PathBuf> = OnceLock::new();
/// the live name the APN image was parked under -- may be the per-process
/// fallback rather than the plain LIVE_SUFFIX name
static APN_LIVE: OnceLock<PathBuf> = OnceLock::new();

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

/// the directory the loader recorded for `handle` -- the module table is the
/// only authoritative source, and for a DLL loaded by name it is the Plugins
/// directory even when the working directory is elsewhere
unsafe fn module_dir(handle: HMODULE) -> Option<PathBuf> {
    let mut buffer = [0u16; 260];
    let len = GetModuleFileNameW(handle, &mut buffer) as usize;
    if len == 0 || len >= buffer.len() {
        return None;
    }
    PathBuf::from(OsString::from_wide(&buffer[..len]))
        .parent()
        .map(Path::to_path_buf)
}

/// nul-terminated UTF-16 for the wide file APIs
fn wide(path: &Path) -> Vec<u16> {
    let s = path.to_string_lossy().into_owned();
    let mut v: Vec<u16> = s.encode_utf16().collect();
    v.push(0);
    v
}

fn exists(path: &Path) -> bool {
    // GetFileAttributesW returns the flags, not a Result: a missing file comes
    // back as INVALID_FILE_ATTRIBUTES (all bits set)
    unsafe { GetFileAttributesW(PCWSTR::from_raw(wide(path).as_ptr())) != 0xFFFF_FFFF }
}

/// byte-identical files? A slot that is *already* stock has nothing to swap,
/// and swapping anyway would leave a live copy behind for `task patch` to
/// clean. Any read failure reports false, so an unreadable file is still
/// swapped rather than silently skipped.
fn same_bytes(a: &Path, b: &Path) -> bool {
    matches!((std::fs::read(a), std::fs::read(b)), (Ok(x), Ok(y)) if x == y)
}

/// Where the patched image gets parked while the stock file holds the slot.
///
/// A live copy left by an earlier session that died swapped is stale now --
/// this process's loader already read the file it read, and a fresh
/// `task patch` deploy has since replaced the slot. It is normally deletable,
/// and deleting it is the tidy outcome.
///
/// When it is not, an older session is *still running* with an image section
/// over that file, and the delete fails with a sharing violation. Bailing out
/// there would leave the slot unsigned, which is exactly the ~99s crash this
/// whole module exists to prevent -- so instead this session parks its image
/// under a per-process name and records it for restore(). The two sessions'
/// live copies never collide, and the older one is cleaned by `task patch`
/// once it has gone.
unsafe fn live_path(slot: &Path) -> PathBuf {
    let parent = slot.parent().unwrap_or_else(|| Path::new(""));
    let name = slot.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let preferred = parent.join(format!("{name}{LIVE_SUFFIX}"));
    if !exists(&preferred) {
        return preferred;
    }
    match DeleteFileW(PCWSTR::from_raw(wide(&preferred).as_ptr())) {
        Ok(()) => preferred,
        Err(e) => {
            crate::plog!(
                "[swap] stale {name}{LIVE_SUFFIX} is locked ({e}) - an older session may still hold it; parking this one under a per-process name"
            );
            parent.join(format!("{name}{LIVE_SUFFIX}.{}", GetCurrentProcessId()))
        }
    }
}

/// the file shuffle itself: `slot` steps aside to `live` and `stock` takes the
/// slot. The mapping follows the file object, not the name, so a DLL already
/// mapped from `slot` keeps every page valid and every export callable after
/// this -- which is the whole premise. The caller picks `live` via live_path().
///
/// Every failure undoes the rename, because a slot that vanished from disk is
/// worse than an unsigned one: the loader's next lookup of that name would fail
/// outright. Returns true when the slot now holds the stock image.
unsafe fn swap_slot(slot: &Path, live: &Path, stock: &Path) -> bool {
    let name = match slot.file_name().and_then(|n| n.to_str()) {
        Some(n) => n,
        None => {
            crate::plog!("[swap] cannot parse the slot path - leaving the file as-is");
            return false;
        }
    };

    if let Err(e) = MoveFileW(
        PCWSTR::from_raw(wide(slot).as_ptr()),
        PCWSTR::from_raw(wide(live).as_ptr()),
    ) {
        crate::plog!("[swap] cannot rename {name} aside ({e}) - staying unsigned");
        return false;
    }

    match CopyFileW(
        PCWSTR::from_raw(wide(stock).as_ptr()),
        PCWSTR::from_raw(wide(slot).as_ptr()),
        BOOL(0),
    ) {
        Ok(()) => {
            let stock_name = stock
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("the stock image");
            crate::plog!(
                "[swap] {name} -> {name}{LIVE_SUFFIX}, on-disk slot now holds {stock_name}"
            );
            true
        }
        Err(e) => {
            crate::plog!("[swap] the stock copy failed ({e}) - putting {name} back");
            let _ = MoveFileW(
                PCWSTR::from_raw(wide(live).as_ptr()),
                PCWSTR::from_raw(wide(slot).as_ptr()),
            );
            false
        }
    }
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

    // parsed only to reject an unparseable path before touching the disk; the
    // log lines that used it moved into swap_slot()
    let _name = match path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n,
        None => {
            crate::plog!("[swap] our path has no file name - leaving the file as-is");
            return;
        }
    };

    let live = live_path(&path);
    let orig = dir.join(ORIG_NAME);

    if !exists(&orig) {
        crate::plog!(
            "[swap] {ORIG_NAME} is missing beside us - nothing signed to put in the slot"
        );
        return;
    }

    // our DllMain running at all proves the loader read a patched file for this
    // slot, so the slot cannot already hold the stock image
    if swap_slot(&path, &live, &orig) {
        let _ = ASTROLABE_LIVE.set(live);
        SWAPPED.store(true, Ordering::SeqCst);
    }
}

/// The passport SDK version of engage(), for a module that is not loaded yet
/// when our DllMain runs.
///
/// AccountPlatNative.dll is loaded by the login flow, roughly +16s in, and the
/// signature gate reads the file at that point -- verified twice from outside
/// the process, in both directions:
///
///   * swapping at +2s put stock in the slot *before* the load, so the loader
///     mapped the pristine SDK. Login ran against the real
///     dispatchcnglobal.yuanshen.com and the kill never armed. The session
///     "survived" while pointed at servers that are not ours -- useless.
///   * swapping at +30s ran *after* the login read, so the verifier had
///     already digested the patched file. The session still died at 98.86s,
///     identical to no swap at all.
///
/// So the window is between "the loader is done with the file" and "the login
/// flow reads it back", and only code inside the process can see that edge.
/// This polls GetModuleHandleW and swaps the instant the module appears in the
/// loader's table, which is after the image is mapped and before anything has
/// had a reason to re-open the file.
///
/// The swap itself is identical to engage(): the patched image stays mapped
/// and keeps serving the rewritten URLs and key, while the on-disk slot holds
/// the pristine signed `task patch:reset` backup.
pub unsafe fn engage_apn() {
    std::thread::spawn(poll_apn);
}

fn poll_apn() {
    let probe = wide_str(APN_NAME);
    for attempt in 0u32..APN_POLL_ATTEMPTS {
        // GetModuleHandleW only consults the loader's table -- it never loads
        // anything, and it does not need the file, so this is safe to hammer
        match unsafe { GetModuleHandleW(PCWSTR::from_raw(probe.as_ptr())) } {
            Ok(handle) if handle.0 != 0 => {
                let dir = unsafe { module_dir(handle) };
                let dir = match dir {
                    Some(d) => d,
                    None => {
                        crate::plog!("[swap] {APN_NAME} appeared but its path is unreadable");
                        return;
                    }
                };
                crate::plog!(
                    "[swap] {APN_NAME} mapped after {:.1}s - swapping its slot",
                    attempt as f64 * APN_POLL_MS as f64 / 1000.0
                );
                unsafe { swap_apn(&dir) };
                return;
            }
            _ => std::thread::sleep(Duration::from_millis(APN_POLL_MS)),
        }
    }
    crate::plog!("[swap] {APN_NAME} never loaded - nothing to swap");
}

unsafe fn swap_apn(dir: &Path) {
    let slot = dir.join(APN_NAME);
    let stock = dir.join(APN_STOCK);
    let live = live_path(&slot);

    if !exists(&stock) {
        crate::plog!("[swap] no pristine {APN_STOCK} - leaving {APN_NAME} alone");
        return;
    }

    // a session that died swapped and was not re-patched leaves stock in the
    // slot and the SDK mapped from it. Swapping then is a no-op that would also
    // leave a live copy behind for patch_game.ps1 to clean
    if same_bytes(&slot, &stock) {
        crate::plog!("[swap] {APN_NAME} is already the stock file - nothing to swap");
        return;
    }

    if swap_slot(&slot, &live, &stock) {
        let _ = APN_PATH.set(slot);
        let _ = APN_LIVE.set(live);
    }
}

/// call from DLL_PROCESS_DETACH. Restores the patched image so the next launch
/// loads the patch. A crash never gets here - see the module docs.
pub unsafe fn restore() {
    if SWAPPED.load(Ordering::SeqCst) {
        // NULL here would resolve the main executable, not our DLL -- see OWN_HINST
        let slot = own_path(HINSTANCE(OWN_HINST.load(Ordering::SeqCst) as isize));
        restore_slot(
            slot.as_deref(),
            ASTROLABE_LIVE.get().map(PathBuf::as_path),
        );
    }
    // APN restored second and unconditionally: an Astrolabe restore that failed
    // must not strand the SDK slot too, and vice versa
    restore_slot(
        APN_PATH.get().map(PathBuf::as_path),
        APN_LIVE.get().map(PathBuf::as_path),
    );
}

/// the reverse of swap_slot(): move the live copy back over the stock file.
/// `live` is the exact name the image was parked under, which may be the
/// per-process fallback rather than the plain LIVE_SUFFIX name.
unsafe fn restore_slot(slot: Option<&Path>, live: Option<&Path>) {
    let path = match slot {
        Some(p) => p,
        None => return, // nothing was swapped, or the path was never pinned
    };
    let name = match path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n,
        None => return,
    };
    let live = match live {
        Some(l) => l,
        None => return,
    };
    if !exists(live) {
        crate::plog!("[swap] no live copy of {name} to restore from");
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
