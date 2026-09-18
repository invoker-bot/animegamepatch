//! Vectored exception handler that logs every *first-chance* exception.
//!
//! Why this exists: the game dies with 0xC0000005 inside ntdll's
//! RtlVirtualUnwind2 -- i.e. it crashes *while unwinding an earlier
//! exception*. WER reports only the unwinder fault, which hides the real one.
//! WerSvc is also stopped on this machine and cannot be started without
//! admin, so LocalDumps produces nothing. Registering a VEH ourselves is the
//! cheapest way to see the exception that started it all.
//!
//! THE HANDLER MUST NOT CALL INTO THE OS. The first version resolved the
//! faulting module with GetModuleHandleW and parsed its PE headers *inside
//! the handler*. That read faulted on a suspect whose handle was not a plain
//! base (a LOAD_LIBRARY_AS_DATAFILE handle has the low bit set, which shifts
//! every PE field by one byte, so e_lfanew came out garbage), the nested
//! exception inside the exception dispatcher killed the process, and WER
//! reported the whole thing as Astrolabe.dll+0xA00A -- our own crash recorder
//! had murdered the game. Resolution now happens in refresh() from a normal
//! context; on the exception path we only read this static table and write to
//! a file.
//!
//! The handler never suppresses anything: it returns EXCEPTION_CONTINUE_SEARCH
//! after logging.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use windows::core::PCWSTR;
use windows::Win32::Foundation::STATUS_ACCESS_VIOLATION;
use windows::Win32::System::Diagnostics::Debug::{
    AddVectoredExceptionHandler, EXCEPTION_POINTERS, EXCEPTION_RECORD,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;

/// stop after this many lines so a hot exception loop can't flood the log
const MAX_LOGGED: u32 = 200;

static LOGGED: AtomicU32 = AtomicU32::new(0);

/// one slot per unique (code, faulting-ip); IL2CPP throws constantly but from a
/// fixed set of sites, so this caps the noise without hiding anything new
const SEEN_N: usize = 256;
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

/// modules worth naming in the log; anything else falls back to a raw address
const SUSPECTS: &[&str] = &[
    "YuanShen.exe",
    "GameAssembly.dll",
    "ntdll.dll",
    "kernelbase.dll",
    "unityplayer.dll",
    "winhttp.dll",
    "Astrolabe.dll",
    "ext.dll",
    "mhyprot.dll",
    "zf_cef.dll",
    "AccountPlatNative.dll",
];

/// (base, size_of_image) per suspect, filled by refresh() from a normal
/// context. Both stay 0 for modules that are not loaded. The handler only
/// reads these, so the exception path never touches the loader or a foreign
/// PE header.
struct Range {
    base: AtomicU64,
    size: AtomicU64,
}

const ZERO: Range = Range {
    base: AtomicU64::new(0),
    size: AtomicU64::new(0),
};

static RANGES: [Range; SUSPECTS.len()] = [ZERO; SUSPECTS.len()];

unsafe fn module_range(name: &str) -> Option<(usize, usize)> {
    let mut wide: Vec<u16> = name.encode_utf16().collect();
    wide.push(0);
    let handle = GetModuleHandleW(PCWSTR::from_raw(wide.as_ptr())).ok()?;
    let mut base = handle.0 as usize;
    if base == 0 {
        return None;
    }
    // a module loaded LOAD_LIBRARY_AS_DATAFILE comes back with the low bit
    // set; the mapping base is the handle with that bit cleared
    base &= !1usize;
    // DOS e_lfanew (at +0x3C, NOT +0 -- +0 is the "MZ" magic) -> PE signature(4)
    // + file header(20) -> optional header
    let e_lfanew = *((base + 0x3C) as *const u32) as usize;
    // the DOS stub is tiny, and the headers are always in the first page;
    // anything bigger means the handle is not a PE base, do not follow it
    if e_lfanew > 0x400 {
        return None;
    }
    if *((base + e_lfanew) as *const u32) != 0x0000_4550 {
        // "PE\0\0" -- not a PE image at all
        return None;
    }
    // PE32 and PE32+ both keep SizeOfImage at optional-header offset 0x38
    let size_of_image = *((base + e_lfanew + 24 + 0x38) as *const u32) as usize;
    if size_of_image == 0 {
        return None;
    }
    Some((base, size_of_image))
}

/// re-resolve every suspect from a normal context; the handler reads the
/// result. GameAssembly/mhyprot/zf_cef load after our DllMain, so this has to
/// run repeatedly for a while -- call it from a timer thread, not from the
/// exception path.
pub fn refresh() {
    let mut got = 0;
    let mut sig = String::new();
    for (i, name) in SUSPECTS.iter().enumerate() {
        if let Some((base, size)) = unsafe { module_range(name) } {
            RANGES[i].base.store(base as u64, Ordering::Relaxed);
            RANGES[i].size.store(size as u64, Ordering::Relaxed);
            got += 1;
            sig.push_str(&format!("{name}=0x{base:X}+0x{size:X} "));
        }
    }
    // only re-print when the loaded set changed, so a 2s timer can't flood
    static LAST: AtomicU64 = AtomicU64::new(u64::MAX);
    let hash = got as u64;
    if hash != LAST.swap(hash, Ordering::Relaxed) {
        crate::log::write(&format!(
            "[exc] suspect modules ({}/{}): {}",
            got,
            SUSPECTS.len(),
            sig.trim_end()
        ));
    }
}

/// "addr" -> "modname+0xOFF" or "<0xADDR>", into a fixed stack buffer.
/// Reads only our own statics -- no API calls, no pointer chasing.
unsafe fn describe(addr: usize, out: &mut [u8]) -> usize {
    for (i, name) in SUSPECTS.iter().enumerate() {
        let base = RANGES[i].base.load(Ordering::Relaxed) as usize;
        if base == 0 {
            continue;
        }
        let size = RANGES[i].size.load(Ordering::Relaxed) as usize;
        if base <= addr && addr < base + size {
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

/// module of the faulting code, resolved from the precomputed table only
unsafe extern "system" fn on_exception(info: *mut EXCEPTION_POINTERS) -> i32 {
    let record: *mut EXCEPTION_RECORD = (*info).ExceptionRecord;
    if record.is_null() {
        return 0; // EXCEPTION_CONTINUE_SEARCH
    }

    // every code, not just the AV: the fatal AV lands inside RtlVirtualUnwind2,
    // i.e. while *unwinding* an earlier exception, and that earlier one is what
    // we actually need to see
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
    // inside ntdll!RtlVirtualUnwind2; its callers tell us who asked for the
    // unwind. RSP at exception time is the dispatcher stack, so the read is
    // safe as long as RSP looks like a user-mode address at all
    let mut ret = [0usize; 3];
    let ctx = (*info).ContextRecord;
    if !ctx.is_null() {
        let rsp = (*ctx).Rsp as usize;
        if (0x1_0000..=0x0000_7FFF_FFFF_FFFF).contains(&rsp) {
            for i in 0..ret.len() {
                ret[i] = *((rsp + i * 8) as *const usize);
            }
        }
    }

    let mut ret_buf = [0u8; 200];
    let ret_len = {
        let mut buf = StackBuf {
            buf: &mut ret_buf,
            pos: 0,
        };
        use core::fmt::Write;
        let mut tmp = [0u8; 64];
        for (i, r) in ret.iter().enumerate() {
            let len = describe(*r, &mut tmp);
            let _ = write!(
                buf,
                "{}{}",
                if i == 0 { "" } else { "," },
                std::str::from_utf8(&tmp[..len]).unwrap_or("?")
            );
        }
        buf.pos
    };

    // integer/str formatting on a stack buffer; no String allocation on the
    // exception path (the heap may already be the thing that's broken)
    use std::io::Write;
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(crate::log::path())
    {
        if is_av {
            let is_write = (*record).ExceptionInformation.get(0).copied().unwrap_or(0);
            let fault_va = (*record).ExceptionInformation.get(1).copied().unwrap_or(0);
            let mut fault_buf = [0u8; 64];
            let fault_len = describe(fault_va, &mut fault_buf);
            let _ = write!(
                file,
                "[exc] #{n} AV at {} {} fault_va={} ret=[{}]\n",
                std::str::from_utf8(&where_buf[..where_len]).unwrap_or("?"),
                if is_write == 1 { "WRITE" } else { "READ " },
                std::str::from_utf8(&fault_buf[..fault_len]).unwrap_or("?"),
                std::str::from_utf8(&ret_buf[..ret_len]).unwrap_or("?"),
            );
        } else {
            let _ = write!(
                file,
                "[exc] #{n} {}(0x{code:08X}) at {} ret=[{}]\n",
                code_name(code),
                std::str::from_utf8(&where_buf[..where_len]).unwrap_or("?"),
                std::str::from_utf8(&ret_buf[..ret_len]).unwrap_or("?"),
            );
        }
        if n + 1 == MAX_LOGGED {
            let _ = write!(file, "[exc] log cap reached, further exceptions not logged\n");
        }
    }

    0 // EXCEPTION_CONTINUE_SEARCH -- never swallow
}

/// registers the handler; safe to call more than once
pub unsafe fn install() {
    // 0.54 returns a raw handle (null on failure), not a Result
    if AddVectoredExceptionHandler(1, Some(on_exception)).is_null() {
        crate::log::write("[exc] failed to install VEH");
    } else {
        crate::log::write("[exc] vectored exception handler installed");
    }
    refresh();
}
