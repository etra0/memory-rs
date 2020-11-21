use crate::error::{Error, ErrorType};
use crate::try_winapi;
use anyhow::{Context, Result};
use std::ptr::copy_nonoverlapping;
use winapi::shared::minwindef::LPVOID;
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
    use std::mem::transmute;

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
    write_aob(original_function, &nops).with_context(|| "Couldn't nop original bytes")?;

    // Inject the jmp to the original function
    // address as an AoB
    let aob: [u8; 8] = transmute(new_function.to_le());

    let injection = if len < 14 {
        let mut v = vec![0x48, 0xb8];
        v.extend_from_slice(&aob);
        v.extend_from_slice(&[0xff, 0xe0]);
        v
    } else {
        let mut v = vec![0xff, 0x25, 0x00, 0x00, 0x00, 0x00];
        v.extend_from_slice(&aob);
        v
    };

    write_aob(original_function, &injection)
        .with_context(|| "Couldn't write the injection to the original function")?;

    FlushInstructionCache(ph, original_function as LPVOID, injection.len());

    try_winapi!(VirtualProtect(
        original_function as LPVOID,
        len,
        o_function_prot,
        &mut ignored_prot
    ));

    // Inject the jmp back if required
    let new_function_end = match new_function_end {
        Some(v) => v,
        None => return Ok(()),
    };

    *new_function_end = original_function + len;

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
    use winapi::um::winnt::MEMORY_BASIC_INFORMATION;

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

    let data = unsafe { std::slice::from_raw_parts(start_address as *mut u8, len) };

    let index = data.windows(pattern_size).position(pattern_function);

    match index {
        Some(addr) => Ok(Some(start_address + addr)),
        None => Ok(None),
    }
}
