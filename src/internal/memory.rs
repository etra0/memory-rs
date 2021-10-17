use crate::error::{Error, ErrorType};
use crate::wrap_winapi;
use anyhow::{Context, Result};
use std::ffi::OsString;
use std::os::windows::prelude::*;
use std::path::PathBuf;
use std::ptr::copy_nonoverlapping;
use winapi::shared::minwindef::LPVOID;
use winapi::um::libloaderapi;
use winapi::um::memoryapi::{VirtualProtect, VirtualQuery};
use winapi::um::processthreadsapi::{FlushInstructionCache, GetCurrentProcess};
use winapi::um::winnt::{MEM_FREE, PAGE_EXECUTE_READWRITE};

pub struct MemProtect {
    addr: usize,
    size: usize,
    prot: u32,
}

/// Scoped VirtualProtect.
/// # Safety
/// The only unsafe bit is the VirtualProtect, which according to msdn
/// it shouldn't have undefined behavior, so we wrap that function with an
/// `try_winapi!` macro.
impl MemProtect {
    pub fn new(addr: usize, size: usize, prot: Option<u32>) -> Result<Self> {
        let new_prot = prot.unwrap_or(PAGE_EXECUTE_READWRITE);

        let mut old_prot = 0u32;

        unsafe {
            wrap_winapi!(VirtualProtect(
                addr as LPVOID,
                size,
                new_prot,
                &mut old_prot
            ), x == 0)?;
        }

        Ok(Self {
            addr,
            size,
            prot: old_prot,
        })
    }
}

impl Drop for MemProtect {
    fn drop(&mut self) {
        let mut _prot = 0;
        unsafe {
            VirtualProtect(self.addr as _, self.size, self.prot, &mut _prot);
        }
    }
}

pub struct MemoryPattern {
    pub size: usize,
    pub pattern: fn(&[u8]) -> bool
}

impl MemoryPattern {
    pub fn new(size: usize, pattern: fn(&[u8]) -> bool) -> Self
    {
        MemoryPattern { size, pattern }
    }

    pub fn scan(&self, val: &[u8]) -> bool {
        (self.pattern)(val)
    }
}

/// Write an array of bytes to the desired ptr address.
/// # Safety
/// This function can cause the target program to crash due to
/// incorrect writing, or it could simply make crash the software in case
/// the virtual protect doesn't succeed.
pub unsafe fn write_aob(ptr: usize, source: &[u8]) -> Result<()> {
    let size = source.len();

    let _mp = MemProtect::new(ptr, size, None)?;

    copy_nonoverlapping(source.as_ptr(), ptr as *mut u8, size);

    let ph = GetCurrentProcess();
    FlushInstructionCache(ph, ptr as LPVOID, size);

    Ok(())
}

/// Injects a jmp in the target address. The minimum length of it is 12 bytes.
/// In case the space is bigger than 14 bytes, it'll inject a non-dirty
/// trampoline, and will nop the rest of the instructions.
/// # Safety
/// this function is inherently unsafe since it does a lot of nasty stuff.
pub unsafe fn hook_function(
    original_function: usize,
    new_function: usize,
    new_function_end: Option<&mut usize>,
    len: usize,
) -> Result<()> {
    assert!(len >= 12, "Not enough space to inject the shellcode");

    let ph = GetCurrentProcess();

    // Unprotect zone we'll write
    let _mp = MemProtect::new(original_function, len, None)?;

    let nops = vec![0x90; len];
    write_aob(original_function, &nops)
        .with_context(|| "Couldn't nop original bytes")?;

    // Inject the jmp to the original function
    // address as an AoB
    let aob: [u8; std::mem::size_of::<usize>()] = new_function.to_le_bytes();

    let injection = if len < 14 {
        let mut v = vec![0x48, 0xb8];
        v.extend_from_slice(&aob);
        v.extend_from_slice(&[0xff, 0xe0]);
        v
    } else {
        let mut v = if cfg!(target_arch = "x86_64") {
            vec![0xff, 0x25, 0x00, 0x00, 0x00, 0x00]
        } else {
            let mut v = vec![0xFF, 0x25];
            v.extend_from_slice(&(original_function + 6).to_le_bytes());
            v
        };
        v.extend_from_slice(&aob);
        v
    };

    write_aob(original_function, &injection).with_context(|| {
        "Couldn't write the injection to the original function"
    })?;

    FlushInstructionCache(ph, original_function as LPVOID, injection.len());

    // Inject the jmp back if required
    if let Some(p) = new_function_end {
        *p = original_function + len;
    }

    Ok(())
}

/// This function will use the WinAPI to check if the region to scan is valid.
/// A region is not valid when it's free or when VirtualQuery returns an
/// error at the moment of querying that region.
pub fn check_valid_region(start_address: usize, len: usize) -> Result<()> {
    use winapi::um::winnt::MEMORY_BASIC_INFORMATION;

    if start_address == 0x0 {
        return Err(Error::new(
            ErrorType::Internal,
            "start_address can't be 0".into(),
        )
        .into());
    }

    if len == 0x0 {
        return Err(
            Error::new(ErrorType::Internal, "len can't be 0".into()).into()
        );
    }

    let mut region_size = 0_usize;
    let size_mem_inf = std::mem::size_of::<MEMORY_BASIC_INFORMATION>();

    while region_size < len {
        let mut information = MEMORY_BASIC_INFORMATION::default();
        unsafe {
            wrap_winapi!(VirtualQuery(
                (start_address + region_size) as LPVOID,
                &mut information,
                size_mem_inf
            ), x == 0)?;
        }

        if information.State == MEM_FREE {
            return Err(Error::new(
                ErrorType::Internal,
                "The region to scan is invalid".to_string(),
            )
            .into());
        }

        region_size += information.RegionSize as usize;
    }

    Ok(())
}

/// Get DLL's parent path
/// # Safety
/// This function can fail on the
/// GetModuleFileNameA, everything else is unsafe
pub unsafe fn resolve_module_path(lib: LPVOID) -> Result<PathBuf> {
    let mut buf: Vec<u16> = vec![0x0; 255];

    wrap_winapi!(libloaderapi::GetModuleFileNameW(
        lib as _,
        buf.as_mut_ptr(),
        255
    ), x == 0)?;
    let name = OsString::from_wide(&buf);
    let mut path: PathBuf = name.into();
    path.pop();
    Ok(path)
}
