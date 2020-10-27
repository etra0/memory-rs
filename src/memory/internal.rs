use std::ptr::copy_nonoverlapping;
use winapi::shared::minwindef::LPVOID;
use winapi::um::memoryapi::{
    VirtualProtect
};
use winapi::um::winnt::{
    HANDLE,
    MEM_COMMIT,
    MEM_RESERVE,
    PAGE_EXECUTE_READWRITE
};

#[macro_export]
macro_rules! main_dll {
    ($func:expr) => {
        #[no_mangle]
        #[allow(non_snake_case)]
        pub extern "system" fn DllMain(lib: winapi::shared::minwindef::HINSTANCE, reason: u32, _: usize) -> u32 {
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
    }
}

pub fn write_aob(ptr: usize, source: &Vec<u8>) -> usize {
    let mut protection_bytes: u32 = 0x0;
    let size = source.len();
    let mut written = 0;

    unsafe {
        VirtualProtect(
            ptr as LPVOID,
            size,
            PAGE_EXECUTE_READWRITE,
            &mut protection_bytes
        );

        copy_nonoverlapping(source.as_ptr(), ptr as *mut u8, size);

        VirtualProtect(
            ptr as LPVOID,
            size,
            protection_bytes,
            std::ptr::null_mut()
        );
    }

    return 0;
}
