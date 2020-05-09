use winapi::shared::minwindef::{DWORD};
use winapi::shared::basetsd::{DWORD_PTR};
use winapi::um::handleapi;
use winapi::um::tlhelp32;
use std::mem;
use std::ffi::{CStr};
use std::io::Error;

pub mod process_wrapper;

pub fn get_process_id(process_name: &str) -> Result<DWORD, Error> {
    let mut process_id: DWORD = 0;
    let h_snap = unsafe {
        tlhelp32::CreateToolhelp32Snapshot(tlhelp32::TH32CS_SNAPPROCESS, 0 ) };

    if h_snap == handleapi::INVALID_HANDLE_VALUE {
        return Err(Error::last_os_error())
    }

    let mut process_entry = tlhelp32::PROCESSENTRY32::default();
    process_entry.dwSize = mem::size_of::<tlhelp32::PROCESSENTRY32>() as u32;

    unsafe {
        match tlhelp32::Process32First(h_snap, &mut process_entry) {
            1 => {
                process_id = loop {
                    let current_name = CStr::from_ptr(
                        process_entry.szExeFile.as_ptr())
                    .to_str()
                    .expect("No string found");

                    if current_name == process_name {
                        break process_entry.th32ProcessID;
                    }

                    if tlhelp32::Process32Next(h_snap, &mut process_entry) == 0 {
                        break 0;
                    }
                }

            },
            _ => {},
        }

        handleapi::CloseHandle(h_snap);
    }

    if process_id == 0 {
        return Err(Error::last_os_error())
    }

    Ok(process_id)
}

pub fn get_module_base(
    process_id: DWORD,
    module_name: &str
) -> Result<DWORD_PTR, Error> {
    let mut module_base_address: DWORD_PTR = 0x0;
    let h_snap = unsafe {
        tlhelp32::CreateToolhelp32Snapshot(
            tlhelp32::TH32CS_SNAPMODULE | tlhelp32::TH32CS_SNAPMODULE32,
            process_id)
    };

    if h_snap == handleapi::INVALID_HANDLE_VALUE {
        return Err(Error::last_os_error())
    }

    let mut module_entry = tlhelp32::MODULEENTRY32::default();
    module_entry.dwSize = mem::size_of::<tlhelp32::MODULEENTRY32>() as u32;
     
    unsafe {
        match tlhelp32::Module32First(h_snap, &mut module_entry) {
            0 => {},
            _ => {
                module_base_address = loop {
                    let current_name = CStr::from_ptr(
                        module_entry.szModule.as_ptr())
                    .to_str()
                    .expect("No string found");

                    if current_name == module_name {
                        break module_entry.modBaseAddr as DWORD_PTR;
                    }

                    if tlhelp32::Module32Next(h_snap, &mut module_entry) == 0 {
                        break 0;
                    }
                }

            },
        }

        handleapi::CloseHandle(h_snap);
    }

    Ok(module_base_address)
}