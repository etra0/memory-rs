use std::io::Error;
use std::ptr::copy_nonoverlapping;
use winapi::shared::minwindef::LPVOID;
use winapi::um::memoryapi::VirtualProtect;
use winapi::um::winnt::PAGE_EXECUTE_READWRITE;

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
    ($call:expr, $message:expr) => {{
        let res = $call;
        if res == 0 {
            return Err(format!($message, Error::last_os_error()).into());
        }
    }};
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
pub unsafe fn write_aob(ptr: usize, source: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut protection_bytes: u32 = 0x0;
    let size = source.len();

    try_winapi!(
        VirtualProtect(
            ptr as LPVOID,
            size,
            PAGE_EXECUTE_READWRITE,
            &mut protection_bytes,
        ),
        "First VirtualProtect failed with error code: {:?}"
    );


    copy_nonoverlapping(source.as_ptr(), ptr as *mut u8, size);

    let mut ignored_bytes: u32 = 0x0;
    try_winapi!(
        VirtualProtect(ptr as LPVOID, size, protection_bytes, &mut ignored_bytes),
        "Second VirtualProtect failed with error code: {:?}"
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
) -> Result<(), Box<dyn std::error::Error>> {
    use std::mem::transmute;

    assert!(len >= 12, "Not enough space to inject the shellcode");

    let mut o_function_prot: u32 = 0x0;
    let mut n_function_prot: u32 = 0x0;

    try_winapi!(VirtualProtect(
        original_function as LPVOID,
        len,
        PAGE_EXECUTE_READWRITE,
        &mut o_function_prot,
    ), "Couldn't change original_function protection: {:?}");

    let nops = vec![0x90; len];
    write_aob(original_function, &nops).map_err(|e| 
        format!("Couldn't nop original bytes: {:?}", e).to_string())?;

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

    write_aob(original_function, &injection).map_err(|e|
        format!("Couldn't write the injection to the original function: {:?}",
            e).to_string())?;

    try_winapi!(VirtualProtect(
        original_function as LPVOID,
        len,
        o_function_prot,
        &mut o_function_prot,
    ), "Couldn't restore original_function protection: {:?}");

    // Inject the jmp back if required
    if new_function_end.is_none() {
        return Ok(());
    }

    let new_function_end = new_function_end.unwrap();

    try_winapi!(VirtualProtect(
        new_function_end as LPVOID,
        14,
        PAGE_EXECUTE_READWRITE,
        &mut n_function_prot,
    ), "Couldn't change protection of the jmp back: {}");

    let aob: [u8; 8] = transmute((original_function + len).to_le());
    let mut injection = vec![0xff, 0x25, 0x00, 0x00, 0x00, 0x00];
    injection.extend_from_slice(&aob);
    write_aob(new_function_end, &injection).map_err(|e|
        format!("Couldn't write the return back: {:?}", e))?;

    try_winapi!(VirtualProtect(
        new_function_end as LPVOID,
        14,
        n_function_prot,
        &mut n_function_prot,
    ), "Couldn't restore protection of the function end: {}");

    Ok(())
}

/// Search for a pattern using the `pattern_function` argument. The
/// `pattern_function` receives a lambda with an `&[u8]` as argument and
/// returns true or false if the pattern is matched. You can generate
/// that function using `generate_aob_pattern!` macro.
pub unsafe fn scan_aob<F>(
    start_address: usize,
    len: usize,
    pattern_function: F,
    pattern_size: usize,
) -> Result<usize, &'static str>
where
    F: Fn(&[u8]) -> bool,
{
    let data = std::slice::from_raw_parts(start_address as *mut u8, len);

    let index = data
        .windows(pattern_size)
        .position(pattern_function)
        .ok_or("Couldn't find requested AOB")?;

    Ok(start_address + index)
}
