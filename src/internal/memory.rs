use crate::error::{Error, ErrorType};
use crate::try_winapi;
use anyhow::{Context, Result};
use std::ffi::CStr;
use std::path::PathBuf;
use std::ptr::copy_nonoverlapping;
use winapi::shared::minwindef::LPVOID;
use winapi::um::libloaderapi;
use winapi::um::memoryapi::{VirtualProtect, VirtualQuery};
use winapi::um::processthreadsapi::{FlushInstructionCache, GetCurrentProcess};
use winapi::um::winnt::{MEM_FREE, PAGE_EXECUTE_READWRITE};

/// Write an array of bytes to the desired ptr address.
/// # Safety
/// This function can cause the target program to crash due to
/// incorrect writing, or it could simply make crash the software in case
/// the virtual protect doesn't succeed.
pub unsafe fn write_aob(ptr: usize, source: &[u8]) -> Result<()> {
    let mut protection_bytes: u32 = 0x0;
    let size = source.len();

    try_winapi!(VirtualProtect(
        ptr as LPVOID,
        size,
        PAGE_EXECUTE_READWRITE,
        &mut protection_bytes
    ));

    copy_nonoverlapping(source.as_ptr(), ptr as *mut u8, size);

    let mut ignored_bytes: u32 = 0x0;
    try_winapi!(VirtualProtect(
        ptr as LPVOID,
        size,
        protection_bytes,
        &mut ignored_bytes
    ));

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

    let mut o_function_prot: u32 = 0x0;
    let mut ignored_prot: u32 = 0x0;

    // Unprotect zone we'll write
    try_winapi!(VirtualProtect(
        original_function as LPVOID,
        len,
        PAGE_EXECUTE_READWRITE,
        &mut o_function_prot
    ));

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

    try_winapi!(VirtualProtect(
        original_function as LPVOID,
        len,
        o_function_prot,
        &mut ignored_prot
    ));

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
pub fn scan_aob<F>(
    start_address: usize,
    len: usize,
    pattern_function: F,
    pattern_size: usize,
) -> Result<Option<usize>>
where
    F: Fn(&[u8]) -> bool,
{
    check_valid_region(start_address, len)?;

    let data =
        unsafe { std::slice::from_raw_parts(start_address as *mut u8, len) };

    let index = data.windows(pattern_size).position(pattern_function);

    match index {
        Some(addr) => Ok(Some(start_address + addr)),
        None => Ok(None),
    }
}

/// Search for all matches over a pattern. This function will always
/// return a [std::vec::Vec], if it doesn't find anything, it will return
/// an empty vector.
pub fn scan_aob_all_matches<F>(
    start_address: usize,
    len: usize,
    pattern_function: F,
    pattern_size: usize,
) -> Result<Vec<usize>>
where
    F: Fn(&[u8]) -> bool + Copy,
{
    check_valid_region(start_address, len)?;

    let data =
        unsafe { std::slice::from_raw_parts(start_address as *mut u8, len) };
    let mut iter = data.windows(pattern_size);
    let mut matches: Vec<usize> = Vec::new();

    loop {
        let val = iter.position(pattern_function);
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
pub unsafe fn resolve_module_path(lib: LPVOID) -> Result<PathBuf> {
    let mut buf: Vec<i8> = Vec::with_capacity(255);

    try_winapi!(libloaderapi::GetModuleFileNameA(
        lib as _,
        buf.as_mut_ptr(),
        255
    ));
    let name = CStr::from_ptr(buf.as_ptr());
    let name = String::from(name.to_str()?);

    let mut path: PathBuf = name.into();
    path.pop();
    Ok(path)
}
