//! Vectored exception handler that logs every *first-chance* exception.
//!
//! Why this exists: the client dies with 0xC0000005 inside ntdll while
//! *unwinding* an earlier exception, so WER's report names only the unwinder
//! and hides the exception that started it. WER is disabled on this box and
//! WerSvc cannot be started without admin, so LocalDumps produces nothing --
//! a VEH is the only recorder we have.
//!
//! CRASH SAFETY -- read this before touching on_exception. The handler makes
//! NO kernel calls and allocates nothing. It writes into a file mapping that
//! install() opened from a normal context; a memcpy into a mapped view is all
//! it ever does, and the memory manager flushes those pages even when the
//! process is killed, so the last line before death survives.
//!
//! The previous revision called OpenOptions::open() and write!() *on the
//! exception path*. IL2CPP throws constantly while the heap and loader locks
//! are held, and a CreateFileW/WriteFile in that window nested a fault inside
//! the dispatcher. The process then died in ntdll on a garbage stack, and the
//! launcher reported that as "The client is damaged" -- our own crash
//! recorder was the killer. An even older revision parsed PE headers inside
//! the handler and faulted on a LOAD_LIBRARY_AS_DATAFILE handle (its low bit
//! shifts every PE field by a byte, so e_lfanew was garbage); WER reported
//! that one as Astrolabe.dll+0xA00A.
//!
//! The handler never suppresses anything: it returns EXCEPTION_CONTINUE_SEARCH
//! after logging.
//!
//! Module resolution happens in refresh() from a normal context by walking the
//! PEB loader list -- that covers every loaded module, not a hand-picked few,
//! and it needs no API calls. on_exception only reads the resulting table.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use windows::Win32::Foundation::STATUS_ACCESS_VIOLATION;
use windows::Win32::System::Diagnostics::Debug::{
    AddVectoredExceptionHandler, EXCEPTION_POINTERS, EXCEPTION_RECORD,
};

/// log at most this many lines, so a hot exception loop cannot run past the
/// mapping -- and cannot spend a dying process's last moments in formatting
const MAX_LOGGED: u32 = 400;

static LOGGED: AtomicU32 = AtomicU32::new(0);

/// one slot per unique (code, faulting-ip); IL2CPP throws constantly but from
/// a fixed set of sites, so this caps the noise without hiding anything new
const SEEN_N: usize = 512;
// a const path is repeatable without Copy; AtomicU64::new(0) inline is not
const ZERO64: AtomicU64 = AtomicU64::new(0);
static SEEN: [AtomicU64; SEEN_N] = [ZERO64; SEEN_N];

/// true if this exact (code, ip) was already logged. O(1), lock-free; a hash
/// collision just logs a duplicate, which is harmless
fn already_seen(code: u32, addr: usize) -> bool {
    let h = code as u64 ^ addr as u64 ^ ((addr as u64) >> 24);
    let slot = &SEEN[(h as usize) & (SEEN_N - 1)];
    slot.swap(h, Ordering::Relaxed) == h
}

// ---------------------------------------------------------------- the log itself

/// 256 KiB holds ~1300 lines; MAX_LOGGED is 400, so it can never fill.
/// A power of two keeps the bounds check simple.
const MAP_CAP: usize = 0x4_0000;

/// base of the mapped view, 0 until install() succeeds -- the handler is a
/// no-op before that
static VIEW: AtomicU64 = AtomicU64::new(0);
/// next write position within the view; each line reserves its length first,
/// so concurrent threads never interleave
static POS: AtomicUsize = AtomicUsize::new(0);
/// set once the mapping is full, so a caller past the end stops trying
static FULL: AtomicBool = AtomicBool::new(false);
/// the mapping handle, kept alive for the life of the process
static MAPPING: AtomicU64 = AtomicU64::new(0);

/// copies a line into the mapping; the only memory the handler ever mutates
fn emit(buf: &[u8]) {
    let view = VIEW.load(Ordering::Relaxed) as usize;
    if view == 0 || FULL.load(Ordering::Relaxed) {
        return;
    }
    let Some(pos) = POS.fetch_add(buf.len(), Ordering::Relaxed).checked_add(buf.len()) else {
        return;
    };
    if pos > MAP_CAP {
        FULL.store(true, Ordering::Relaxed);
        return;
    }
    let start = pos - buf.len();
    // plain copy, no kernel call -- the MM flushes on unmap, even at death
    unsafe {
        core::ptr::copy_nonoverlapping(buf.as_ptr(), (view + start) as *mut u8, buf.len());
    }
}

// ------------------------------------------------------- the suspect module table

const MAX_MODULES: usize = 512;
/// 48 fits every dll name we have seen, with room for the extension
const MAX_NAME: usize = 48;
/// a refresh walks at most this many entries, so a corrupted list terminates
const MAX_WALK: usize = 4096;

struct Mod {
    /// published LAST (see refresh): name and size are already in place when a
    /// nonzero base becomes visible, so the handler never reads a half-entry
    base: AtomicU64,
    size: AtomicU64,
    name: [u8; MAX_NAME],
    name_len: AtomicU32,
}

const ZERO_MOD: Mod = Mod {
    base: AtomicU64::new(0),
    size: AtomicU64::new(0),
    name: [0u8; MAX_NAME],
    name_len: AtomicU32::new(0),
};

static MODULES: [Mod; MAX_MODULES] = [ZERO_MOD; MAX_MODULES];
/// number of populated slots; grows only, and only from refresh()
static MODULE_COUNT: AtomicU32 = AtomicU32::new(0);

fn code_name(code: u32) -> &'static str {
    match code {
        0xC0000005 => "AV",
        0xC00000FD => "STACK_OVERFLOW",
        0xC000001D => "ILLEGAL_INSTRUCTION",
        0xC0000094 => "INT_DIVIDE_BY_ZERO",
        0xC0000374 => "HEAP_CORRUPTION",
        0xE06D7363 => "CPP_EXCEPTION", // MSVC C++ throw -- the IL2CPP/Unity ones
        0xE0434352 => "CLR_EXCEPTION",  // .NET -- the C# side (mono)
        _ => "?",
    }
}

/// every loaded module, straight off the PEB loader list. Reading the list
/// without the loader lock is racy in principle; every pointer is range-
/// checked before it is followed, so a list mid-edit yields a skipped entry,
/// not a fault.
pub fn refresh() {
    let mut added = 0;
    let mut sig = String::new();
    unsafe {
        let peb: *const u8;
        core::arch::asm!(
            "mov {peb}, gs:0x60",
            peb = out(reg) peb,
            options(nomem, nostack, preserves_flags),
        );
        if peb.is_null() {
            return;
        }
        // PEB.Ldr -> PEB_LDR_DATA.InLoadOrderModuleList
        let ldr = *(peb.add(0x18) as *const *const u8);
        if !is_user(ldr as usize) {
            return;
        }
        let head = ldr.add(0x10);
        if !is_user(head as usize) {
            return;
        }
        let first = (*(head as *const ListEntry)).flink;
        if !is_user(first as usize) {
            return;
        }
        let mut cur = first;
        let mut walked = 0;
        while cur != first.sub(0) && is_user(cur as usize) {
            walked += 1;
            if walked > MAX_WALK {
                break;
            }
            // cur points at InLoadOrderLinks, i.e. at the entry itself
            let entry = cur as *const u8;
            let next = (*(cur as *const ListEntry)).flink;
            let base = *(entry.add(0x30) as *const usize);
            let size = *(entry.add(0x40) as *const u32) as usize;
            // BaseDllName is a UNICODE_STRING at +0x58: u16 Length, +8 buffer
            let name_len = *(entry.add(0x58) as *const u16) as usize;
            let name_buf = *(entry.add(0x58 + 8) as *const *const u16);
            if base != 0 && size != 0 && is_user(base) && is_user(name_buf as usize) {
                if upsert(base, size, name_buf, name_len / 2, &mut added, &mut sig) {
                    // a fresh module mid-crash-window is the interesting one;
                    // name it in the main log so addresses resolve offline too
                    crate::log::write(&sig);
                    sig.clear();
                }
            }
            cur = next;
        }
    }
    if added > 0 {
        let n = MODULE_COUNT.load(Ordering::Relaxed);
        crate::log::write(&format!("[exc] suspect modules: {n} loaded"));
    }
}

#[repr(C)]
struct ListEntry {
    flink: *const ListEntry,
    _blink: *const ListEntry,
}

/// user-mode addresses only; anything else is a list we should not follow
fn is_user(addr: usize) -> bool {
    (0x1_0000..=0x0000_7FFF_FFFF_FFFF).contains(&addr)
}

/// inserts the module if its base is new; on success fills `sig` with a
/// "[exc] module name=base+size" line for the main log
unsafe fn upsert(
    base: usize,
    size: usize,
    name: *const u16,
    name_chars: usize,
    added: &mut u32,
    sig: &mut String,
) -> bool {
    let count = MODULE_COUNT.load(Ordering::Relaxed) as usize;
    for i in 0..count {
        if MODULES[i].base.load(Ordering::Relaxed) as usize == base {
            return false; // already known
        }
    }
    let i = MODULE_COUNT.fetch_add(1, Ordering::Relaxed) as usize;
    if i >= MAX_MODULES {
        return false; // table full; 512 real modules would be a record
    }
    let slot = &MODULES[i];
    // raw pointer, not &mut: MODULES is a shared static; the atomics carry
    // their own interior mutability and the name bytes are ours alone here
    let name_ptr = core::ptr::addr_of!(MODULES[i].name) as *const u8 as *mut u8;
    let out = core::slice::from_raw_parts_mut(name_ptr, MAX_NAME);
    let n = copy_name(name, name_chars, out);
    slot.name_len.store(n as u32, Ordering::Relaxed);
    slot.size.store(size as u64, Ordering::Relaxed);
    slot.base.store(base as u64, Ordering::Release);
    *added += 1;
    *sig = format!(
        "[exc] module {} base=0x{:X} size=0x{:X}",
        core::str::from_utf8_unchecked(&slot.name[..n.min(MAX_NAME)]),
        base,
        size
    );
    true
}

/// utf-16 dll name to lowercase ascii; a non-ascii name stops the copy, which
/// only loses exotic names we do not resolve anyway
unsafe fn copy_name(src: *const u16, chars: usize, out: &mut [u8]) -> usize {
    let mut i = 0;
    while i < chars && i + 1 < out.len() {
        let c = *src.add(i) as u32;
        if c >= 0x80 {
            break;
        }
        // 'A'-'Z' -> 'a'-'z', everything else passes through
        let c = if (0x41..=0x5A).contains(&c) { c + 0x20 } else { c };
        out[i] = c as u8;
        i += 1;
    }
    i
}

/// "addr" -> "modname+0xOFF" or "0xADDR", into a fixed stack buffer.
/// Reads only the precomputed table -- no API calls, no pointer chasing.
unsafe fn describe(addr: usize, out: &mut [u8]) -> usize {
    let count = MODULE_COUNT.load(Ordering::Relaxed) as usize;
    for i in 0..count {
        let base = MODULES[i].base.load(Ordering::Acquire) as usize;
        if base == 0 || base > addr {
            continue;
        }
        let size = MODULES[i].size.load(Ordering::Relaxed) as usize;
        if addr < base + size {
            let len = MODULES[i].name_len.load(Ordering::Relaxed) as usize;
            let len = len.min(MAX_NAME);
            let name = core::str::from_utf8_unchecked(&MODULES[i].name[..len]);
            return format_into(out, format_args!("{}+0x{:X}", name, addr - base));
        }
    }
    format_into(out, format_args!("0x{:016X}", addr))
}

fn format_into(out: &mut [u8], args: core::fmt::Arguments<'_>) -> usize {
    use core::fmt::Write;
    let mut buf = StackBuf { buf: out, pos: 0 };
    let _ = buf.write_fmt(args);
    buf.pos
}

struct StackBuf<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> core::fmt::Write for StackBuf<'a> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let bytes = s.as_bytes();
        if self.pos + bytes.len() <= self.buf.len() {
            self.buf[self.pos..self.pos + bytes.len()].copy_from_slice(bytes);
            self.pos += bytes.len();
        }
        Ok(())
    }
}

// ------------------------------------------------------------------- the handler

/// re-entrancy guard: a fault inside the handler re-enters it, and without
/// this the recursion eats the stack. Skipping the nested one costs a log
/// line, not the process.
static IN_HANDLER: AtomicBool = AtomicBool::new(false);

unsafe extern "system" fn on_exception(info: *mut EXCEPTION_POINTERS) -> i32 {
    if IN_HANDLER.swap(true, Ordering::Relaxed) {
        return 0; // a fault inside this very handler -- drop it
    }
    let r = on_exception_inner(info);
    IN_HANDLER.store(false, Ordering::Relaxed);
    r
}

unsafe fn on_exception_inner(info: *mut EXCEPTION_POINTERS) -> i32 {
    let record: *mut EXCEPTION_RECORD = (*info).ExceptionRecord;
    if record.is_null() {
        return 0; // EXCEPTION_CONTINUE_SEARCH
    }

    // every code, not just the AV: the fatal AV lands inside the unwinder,
    // and the earlier exception it is unwinding is the one we need to see
    let code = (*record).ExceptionCode.0 as u32;
    let addr = (*record).ExceptionAddress as usize;

    if already_seen(code, addr) {
        return 0;
    }

    let n = LOGGED.fetch_add(1, Ordering::Relaxed);
    if n >= MAX_LOGGED {
        return 0;
    }

    let is_av = code == STATUS_ACCESS_VIOLATION.0 as u32;

    let mut where_buf = [0u8; 64];
    let where_len = describe(addr, &mut where_buf);

    // return-address chain from the faulting frame's RSP. The fatal AV is deep
    // inside ntdll; its callers say who asked for it. RSP at exception time is
    // the dispatcher stack, so the read is safe as long as RSP is user-mode
    let mut ret = [0usize; 4];
    let ctx = (*info).ContextRecord;
    if !ctx.is_null() {
        let rsp = (*ctx).Rsp as usize;
        if is_user(rsp) {
            for i in 0..ret.len() {
                ret[i] = *((rsp + i * 8) as *const usize);
            }
        }
    }

    // one fixed stack buffer per line, formatted then copied into the mapping;
    // no String, no heap -- the heap may be the thing that is broken
    let mut line = [0u8; 384];
    let len = {
        let mut buf = StackBuf {
            buf: &mut line,
            pos: 0,
        };
        use core::fmt::Write;
        let mut tmp = [0u8; 64];
        // module of the faulting code, then up the stack
        let w = core::str::from_utf8(&where_buf[..where_len]).unwrap_or("?");
        if is_av {
            let is_write = (*record)
                .ExceptionInformation
                .get(0)
                .copied()
                .unwrap_or(0);
            let fault_va = (*record)
                .ExceptionInformation
                .get(1)
                .copied()
                .unwrap_or(0);
            let mut fault_buf = [0u8; 64];
            let fault_len = describe(fault_va, &mut fault_buf);
            let f = core::str::from_utf8(&fault_buf[..fault_len]).unwrap_or("?");
            let _ = write!(
                buf,
                "[exc] #{n} AV at {w} {} fault_va={f} ret=[",
                if is_write == 1 { "WRITE" } else { "READ " },
            );
        } else {
            let _ = write!(buf, "[exc] #{n} {}(0x{code:08X}) at {w} ret=[", code_name(code),);
        }
        for (i, r) in ret.iter().enumerate() {
            let l = describe(*r, &mut tmp);
            let _ = write!(
                buf,
                "{}{}",
                if i == 0 { "" } else { "," },
                core::str::from_utf8(&tmp[..l]).unwrap_or("?")
            );
        }
        let _ = write!(buf, "]\n");
        buf.pos
    };

    emit(&line[..len]);

    if n + 1 == MAX_LOGGED {
        let mut tail = *b"[exc] log cap reached, further exceptions not logged\n";
        emit(&mut tail);
    }

    0 // EXCEPTION_CONTINUE_SEARCH -- never swallow
}

/// registers the handler and opens the crash log; safe to call more than once
pub unsafe fn install() {
    // 0.54 returns a raw handle (null on failure), not a Result
    if AddVectoredExceptionHandler(1, Some(on_exception)).is_null() {
        crate::log::write("[exc] failed to install VEH");
        return;
    }
    crate::log::write("[exc] vectored exception handler installed");
    open_mapping();
    refresh();
}

/// opens the crash log as a file mapping once, from a normal context. The
/// handler then never needs the filesystem: it copies into the view, and the
/// MM persists it. A separate file from the patch log so the two writers
/// cannot interleave.
unsafe fn open_mapping() {
    use std::fs::OpenOptions;
    use std::os::windows::io::AsRawHandle;

    let path = crate::log::exc_path();
    let file = match OpenOptions::new().create(true).write(true).truncate(true).open(&path) {
        Ok(f) => f,
        Err(e) => {
            crate::log::write(&format!("[exc] could not open {path:?}: {e}"));
            return;
        }
    };
    // the whole mapping has to be backed by real file bytes, or a write past
    // the end of the file would fault inside the handler -- the exact thing
    // this redesign exists to avoid
    if file.set_len(MAP_CAP as u64).is_err() || file.metadata().map(|m| m.len()).ok() != Some(MAP_CAP as u64) {
        crate::log::write("[exc] could not size the exception log");
        return;
    }

    use winapi::um::memoryapi::{CreateFileMappingW, MapViewOfFile, FILE_MAP_ALL_ACCESS};
    use winapi::um::winnt::PAGE_READWRITE;

    let mapping = CreateFileMappingW(
        file.as_raw_handle() as *mut _,
        core::ptr::null_mut(),
        PAGE_READWRITE,
        0,
        MAP_CAP as u32,
        core::ptr::null(),
    );
    if mapping.is_null() {
        crate::log::write("[exc] could not map the exception log");
        return;
    }
    MAPPING.store(mapping as u64, Ordering::Relaxed);

    let view = MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if view.is_null() {
        crate::log::write("[exc] could not map the view");
        return;
    }
    VIEW.store(view as u64, Ordering::Relaxed);

    // hold both until the process dies; closing them is not worth a Drop
    core::mem::forget(file);

    let mut header = *b"[exc] first-chance exception log (0 = no kernel calls on the exception path)\n";
    emit(&mut header);
    crate::log::write(&format!("[exc] exception log at {}", path.display()));
}
