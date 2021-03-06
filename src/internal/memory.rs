use crate::error::{Error, ErrorType};
use crate::try_winapi;
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
        let new_prot = match prot {
            Some(p) => p,
            None => PAGE_EXECUTE_READWRITE,
        };

        let mut old_prot = 0u32;

        unsafe {
            try_winapi!(VirtualProtect(
                addr as LPVOID,
                size,
                new_prot,
                &mut old_prot
            ));
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
            try_winapi!(VirtualQuery(
                (start_address + region_size) as LPVOID,
                &mut information,
                size_mem_inf
            ));
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

/// Search for a pattern using the `pattern_function` argument. The
/// `pattern_function` receives a lambda with an `&[u8]` as argument and
/// returns true or false if the pattern is matched. You can generate
/// that function using `generate_aob_pattern!` macro.
pub fn scan_aob(
    start_address: usize,
    len: usize,
    memory_pattern: MemoryPattern,
) -> Result<Option<usize>>
{
    check_valid_region(start_address, len)?;

    let data =
        unsafe { std::slice::from_raw_parts(start_address as *mut u8, len) };

    let index = data.windows(memory_pattern.size).position(memory_pattern.pattern);

    match index {
        Some(addr) => Ok(Some(start_address + addr)),
        None => Ok(None),
    }
}

/// Search for all matches over a pattern. This function will always
/// return a [std::vec::Vec], if it doesn't find anything, it will return
/// an empty vector.
pub fn scan_aob_all_matches(
    start_address: usize,
    len: usize,
    memory_pattern: MemoryPattern
) -> Result<Vec<usize>>
{
    check_valid_region(start_address, len)?;

    let data =
        unsafe { std::slice::from_raw_parts(start_address as *mut u8, len) };
    let mut iter = data.windows(memory_pattern.size);
    let mut matches: Vec<usize> = Vec::new();

    loop {
        let val = iter.position(memory_pattern.pattern);
        if val.is_none() {
            break;
        }

        let val = val.unwrap();
        let last_val = matches.last().copied();
        match last_val {
            Some(last_val) => matches.push(val + last_val + 0x1),
            None => matches.push(val + start_address),
        };
    }

    Ok(matches)
}

/// Scan for a value of type  `T` assuming it will be aligned
/// in respect to its size. The difference with
/// [memory_rs::internal::memory::scan_aob] is that the one mentioned
/// searches using a window (i.e. bytes can be not aligned). This function
/// is way faster because of this (and also because comparisons are different).
pub fn scan_aligned_value<T>(
    start_address: usize,
    len: usize,
    value: T,
) -> Result<Vec<usize>, Box<dyn std::error::Error>>
where
    T: Copy + std::cmp::PartialEq,
{
    check_valid_region(start_address, len)?;

    let size_type = std::mem::size_of::<T>();
    let mut matches = vec![];

    if len / size_type == 0 {
        return Err(Error::new(
            ErrorType::Internal,
            "The space to scan is 0".to_string(),
        )
        .into());
    }

    let data = unsafe {
        std::slice::from_raw_parts(start_address as *mut T, len / size_type)
    };
    let mut iter = data.iter();

    let match_function = |&x: &T| x == value;

    loop {
        let val = iter.position(match_function);
        if val.is_none() {
            break;
        }

        let val = val.unwrap();
        let last_val = matches.last().copied();
        match last_val {
            Some(last_val) => matches.push((val + 0x1) * size_type + last_val),
            None => matches.push((val * size_type) + start_address),
        };
    }

    Ok(matches)
}

/// Get DLL's parent path
/// # Safety
/// This function can fail on the
/// GetModuleFileNameA, everything else is unsafe
pub unsafe fn resolve_module_path(lib: LPVOID) -> Result<PathBuf> {
    let mut buf: Vec<u16> = vec![0x0; 255];

    try_winapi!(libloaderapi::GetModuleFileNameW(
        lib as _,
        buf.as_mut_ptr(),
        255
    ));
    let name = OsString::from_wide(&buf);
    let mut path: PathBuf = name.into();
    path.pop();
    Ok(path)
}
