use std::ptr::copy_nonoverlapping;
use winapi::shared::minwindef::LPVOID;
use winapi::um::memoryapi::{VirtualProtect, VirtualQuery};
use winapi::um::winnt::{PAGE_EXECUTE_READWRITE, MEM_FREE};
use anyhow::{Context, Result};
use crate::error::{Error, ErrorType};

#[macro_export]
macro_rules! main_dll {
    ($func:expr) => {
        #[no_mangle]
        #[allow(non_snake_case)]
        pub extern "system" fn DllMain(
            lib: winapi::shared::minwindef::HINSTANCE,
            reason: u32,
            _: usize,
        ) -> u32 {
            unsafe {
                match reason {
                    winapi::um::winnt::DLL_PROCESS_ATTACH => {
                        winapi::um::processthreadsapi::CreateThread(
                            std::ptr::null_mut(),
                            0,
                            Some($func),
                            lib as winapi::shared::minwindef::LPVOID,
                            0,
                            std::ptr::null_mut(),
                        );
                    }
                    _ => (),
                };
            }

            return true as u32;
        }
    };
}

// Macro created by t0mstone
// You can check the original source at
// https://github.com/T0mstone/tlibs/blob/master/some_macros/src/lib.rs#L23-L29
#[macro_export]
macro_rules! count_args {
    (@one $($t:tt)*) => { 1 };
    ($(($($x:tt)*)),*$(,)?) => {
        0 $(+ $crate::count_args!(@one $($x)*))*
    };
}

macro_rules! try_winapi {
    ($call:tt($($args:expr),*)) => {{
        let res = $call ($($args),*);
        if res == 0 {
            let msg = format!("{} failed with error code {}", std::stringify!($call), std::io::Error::last_os_error());
            return Err(Error::new(ErrorType::WinAPI, msg).into());
        }
    }}
}

/// Returns a tuple where the first value will contain the size of the pattern
/// and the second value is a lambda that returns true if the pattern is
/// matched otherwise will return false
#[macro_export]
macro_rules! generate_aob_pattern {
    [$($val:tt),* ] => {
        (
            $crate::count_args!($(($val)),*),
        |slice: &[u8]| -> bool {
            match slice {
                [$($val),*] => {
                    return true;
                },
                _ => {
                    return false;
                }
            };
        }
        )
    }
}

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
            &mut protection_bytes)
    );


    copy_nonoverlapping(source.as_ptr(), ptr as *mut u8, size);

    let mut ignored_bytes: u32 = 0x0;
    try_winapi!(
        VirtualProtect(ptr as LPVOID, size, protection_bytes, &mut ignored_bytes)
    );

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
    new_function_end: Option<usize>,
    len: usize,
) -> Result<()> {
    use std::mem::transmute;

    assert!(len >= 12, "Not enough space to inject the shellcode");

    let mut o_function_prot: u32 = 0x0;
    let mut n_function_prot: u32 = 0x0;

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

    try_winapi!(VirtualProtect(
        original_function as LPVOID,
        len,
        o_function_prot,
        &mut o_function_prot
    ));

    // Inject the jmp back if required
    let new_function_end = match new_function_end {
        Some(v) => v,
        None => return Ok(())
    };

    try_winapi!(VirtualProtect(
        new_function_end as LPVOID,
        14,
        PAGE_EXECUTE_READWRITE,
        &mut n_function_prot
    ));

    let aob: [u8; 8] = transmute((original_function + len).to_le());
    let mut injection = vec![0xff, 0x25, 0x00, 0x00, 0x00, 0x00];
    injection.extend_from_slice(&aob);
    write_aob(new_function_end, &injection)
        .with_context(|| "Couldn't write the return back")?;

    try_winapi!(VirtualProtect(
        new_function_end as LPVOID,
        14,
        n_function_prot,
        &mut n_function_prot
    ));

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

    let mut information = MEMORY_BASIC_INFORMATION::default();
    let size = std::mem::size_of::<MEMORY_BASIC_INFORMATION>();

    unsafe {
        try_winapi!(
            VirtualQuery(start_address as LPVOID, &mut information, size)
        );
    }

    if information.State == MEM_FREE {
        return Err(Error::new(ErrorType::Internal, "The region to scan is invalid".to_string()).into());
    }

    if (information.BaseAddress as usize) + (information.RegionSize as usize) < start_address + len {
        return Err(Error::new(ErrorType::Internal, "The region to scan is larger than the region size".to_string()).into());
    }
    
    let data = unsafe { std::slice::from_raw_parts(start_address as *mut u8, len) };

    let index = data
        .windows(pattern_size)
        .position(pattern_function);

    match index {
        Some(addr) => return Ok(Some(start_address + addr)),
        None => return Ok(None)
    };
}
