use winapi::shared::minwindef::{DWORD};
use winapi::um::handleapi;
use winapi::shared::minwindef::{LPVOID, LPCVOID};
use winapi::um::winnt::{HANDLE};
use winapi::um::tlhelp32;
use winapi::um::memoryapi::{ReadProcessMemory, WriteProcessMemory};
use std::mem;

pub fn get_aob(h_process: HANDLE, ptr: DWORD, target: &mut Vec<u8>, n: i32) {
    let mut c_addr = ptr;
    let mut c_value: u8 = 0x0;
    for i in 0..n {
        unsafe {
            ReadProcessMemory(
                h_process,
                c_addr as LPCVOID,
                (&mut c_value as *mut u8) as LPVOID,
                mem::size_of::<u8>(),
                std::ptr::null_mut()
            );
        }
        target.push(c_value);
        c_addr += 1;
    }
}