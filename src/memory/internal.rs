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

#[macro_export]
macro_rules! generate_aob_pattern {
    [$($val:tt),* ] => {
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

pub fn write_aob(ptr: usize, source: &[u8]) {
    let mut protection_bytes: u32 = 0x0;
    let size = source.len();

    unsafe {
        VirtualProtect(
            ptr as LPVOID,
            size,
            PAGE_EXECUTE_READWRITE,
            &mut protection_bytes,
        );

        copy_nonoverlapping(source.as_ptr(), ptr as *mut u8, size);

        VirtualProtect(ptr as LPVOID, size, protection_bytes, std::ptr::null_mut());
    }
}

pub fn hook_function(original_function: usize, new_function: usize, new_function_end: usize, len: usize) {
    use std::mem::transmute;

    assert!(len >= 12, "Not enough space to inject the shellcode");

    let mut o_function_prot: u32 = 0x0;
    let mut n_function_prot: u32 = 0x0;
    unsafe {
        VirtualProtect(
            original_function as LPVOID,
            len,
            PAGE_EXECUTE_READWRITE,
            &mut o_function_prot,
        );

        VirtualProtect(
            new_function_end as LPVOID,
            14,
            PAGE_EXECUTE_READWRITE,
            &mut n_function_prot,
        );
    }

    let nops = vec![0x90; len];
    write_aob(original_function, &nops);

    // Inject the jmp to the original function
    // address as an AoB
    let aob: [u8; 8] = unsafe { transmute(new_function.to_le()) };

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
    write_aob(original_function, &injection);

    // inject the jmp back to the end of the new function
    let aob: [u8; 8] = unsafe { transmute((original_function + 14).to_le()) };
    let mut injection = vec![0xff, 0x25, 0x00, 0x00, 0x00, 0x00];
    injection.extend_from_slice(&aob);
    write_aob(new_function_end, &injection);

    unsafe {
        VirtualProtect(
            original_function as LPVOID,
            len,
            o_function_prot,
            &mut o_function_prot,
        );

        VirtualProtect(
            new_function_end as LPVOID,
            14,
            n_function_prot,
            &mut n_function_prot,
        );
    }
}

pub fn scan_aob<F>(
    start_address: usize,
    len: usize,
    pattern_function: F,
    pattern_size: usize,
) -> Result<usize, &'static str>
where
    F: Fn(&[u8]) -> bool,
{
    for addr in start_address..(start_address + len - pattern_size) {
        let c_arr = unsafe { std::slice::from_raw_parts(addr as *mut u8, pattern_size) };
        if pattern_function(&c_arr) {
            return Ok(addr);
        }
    }

    Err("Couldn't find the requested AOB")
}
