use std::ffi::{CStr, c_void};
use std::io::Error;

use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE, CloseHandle};
use windows_sys::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, TH32CS_SNAPPROCESS, PROCESSENTRY32, Process32First, Process32Next, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, MODULEENTRY32, Module32First, Module32Next};
use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_ALL_ACCESS};

pub struct Process {
    pub h_process: HANDLE,
    pub module_base_address: usize,
}

impl Process {
    pub fn new(process_name: &str) -> Result<Process, Error> {
        let process_id = get_process_id(process_name)?;
        let module_base_address = get_module_base(process_id, process_name)?;

        let h_process = unsafe {
            OpenProcess(
                PROCESS_ALL_ACCESS,
                false as i32,
                process_id,
            )
        };

        if h_process == 0 {
            return Err(Error::last_os_error());
        }

        Ok(Process {
            h_process,
            module_base_address,
        })
    }

    /// Writes an array of bytes (as vectors) into the desired address.
    /// It can take relative or absolute values.
    pub fn write_aob(&self, ptr: usize, data: &[u8], absolute: bool) {
        let addr = if absolute {
            ptr as _
        } else {
            self.module_base_address + ptr
        };

        crate::external::memory::write_aob(self.h_process, addr as _, &data);
    }

    /// Writes `n` nops into the desired address
    /// It can take relative or absolute values.
    pub fn write_nops(&self, ptr: usize, n: usize, absolute: bool) {
        let addr = if absolute {
            ptr as _
        } else {
            self.module_base_address + ptr
        };

        crate::external::memory::write_nops(self.h_process, addr as _, n);
    }

    /// Reads `n` bytes from the desired address
    /// It can take relative or absolute values.
    pub fn get_aob(&self, ptr: usize, n: usize, absolute: bool) -> Vec<u8> {
        let addr = if absolute {
            ptr as _
        } else {
            self.module_base_address + ptr
        };

        let output: Vec<u8> = crate::external::memory::get_aob(self.h_process, addr as _, n);

        output
    }

    // TODO: Move this function out of process because it should be in
    // memory/mod.rs.
    pub fn read_value<OutputType>(&self, ptr: usize, absolute: bool) -> OutputType {
        let addr = if absolute {
            ptr as _
        } else {
            self.module_base_address + ptr
        };

        let mut buffer: OutputType = unsafe { std::mem::zeroed() };
        let s_buffer: usize = std::mem::size_of::<OutputType>();
        let mut read: usize = 0;

        unsafe {
            ReadProcessMemory(
                self.h_process,
                addr as *const c_void,
                &mut buffer as *mut OutputType as *mut c_void,
                s_buffer,
                &mut read,
            );
        };

        assert_eq!(read, s_buffer);
        buffer
    }

    pub fn write_value<InputType>(&self, ptr: usize, output: InputType, absolute: bool) {
        let addr = if absolute {
            ptr
        } else {
            self.module_base_address + ptr
        };

        let s: usize = std::mem::size_of::<InputType>();
        let mut written: usize = 0;

        unsafe {
            WriteProcessMemory(
                self.h_process,
                addr as *const c_void,
                (&output as *const InputType) as *mut c_void,
                s,
                &mut written,
            );
        };

        assert!(written != 0);
    }

    /// Inject an an ASM function which requires the labels start and
    /// end as an input, and an entry point where the position will
    /// be injected.
    /// # Safety
    /// This function is highly unsafe. It can fails for so many reasons
    /// that the user should be aware when using it. The function
    /// maybe could not find a code cave, it could not write the
    /// bytes correctly, or it could just simply fail because OS reasons.
    pub unsafe fn inject_shellcode(
        &self,
        entry_point: *const u32,
        instruction_size: usize,
        f_start: *const u8,
        f_end: *const u8,
    ) -> *const c_void {
        crate::external::memory::inject_shellcode(
            self.h_process,
            self.module_base_address as _,
            entry_point as _,
            instruction_size,
            f_start,
            f_end,
        )
    }

    // pub fn read_string_array(
    //     &self,
    //     address: *const u32,
    //     starting_index: usize,
    //     ending: &[u8],
    // ) -> Vec<(usize, String)> {
    //     let mut c_address = address;

    //     let mut data: Vec<(usize, String)> = vec![];

    //     let mut c_index = starting_index;

    //     let mut c_string = String::from("");
    //     loop {
    //         let current_read: Vec<u8> = self.get_aob(c_address, 2, true);

    //         if current_read[..] == *ending {
    //             break;
    //         }
    //         if current_read[0] == 0x00 {
    //             data.push((c_index, c_string));
    //             c_string = String::from("");
    //             c_index += 1;
    //             c_address += 1;
    //             continue;
    //         }

    //         c_string.push(current_read[0] as char);
    //         c_address += 1;
    //     }

    //     data
    // }
}

pub fn get_process_id(process_name: &str) -> Result<u32, Error> {
    let mut process_id: u32 = 0;
    let h_snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };

    if h_snap == INVALID_HANDLE_VALUE {
        return Err(Error::last_os_error());
    }

    let mut process_entry: PROCESSENTRY32 = unsafe { std::mem::zeroed() };
    process_entry.dwSize = std::mem::size_of::<PROCESSENTRY32> as _;

    unsafe {
        if Process32First(h_snap, &mut process_entry) == 1 {
            process_id = loop {
                let current_name = CStr::from_ptr(process_entry.szExeFile.as_ptr() as _)
                    .to_str()
                    .expect("No string found");

                if current_name == process_name {
                    break process_entry.th32ProcessID;
                }

                if Process32Next(h_snap, &mut process_entry) == 0 {
                    break 0;
                }
            }
        }

        CloseHandle(h_snap);
    }

    if process_id == 0 {
        return Err(Error::last_os_error());
    }

    Ok(process_id)
}

pub fn get_module_base(process_id: u32, module_name: &str) -> Result<usize, Error> {
    let mut module_base_address = 0;
    let h_snap = unsafe {
        CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
            process_id,
        )
    };

    if h_snap == INVALID_HANDLE_VALUE {
        return Err(Error::last_os_error());
    }

    let mut module_entry: MODULEENTRY32 = unsafe { std::mem::zeroed() };
    module_entry.dwSize = std::mem::size_of::<MODULEENTRY32> as _;

    unsafe {
        if Module32First(h_snap, &mut module_entry) != 0 {
            module_base_address = loop {
                let current_name = CStr::from_ptr(module_entry.szModule.as_ptr() as _)
                    .to_str()
                    .expect("No string found");

                if current_name == module_name {
                    break module_entry.modBaseAddr as usize;
                }

                if Module32Next(h_snap, &mut module_entry) == 0 {
                    break 0;
                }
            }
        }

        CloseHandle(h_snap);
    }

    if module_base_address == 0 {
        return Err(Error::last_os_error());
    }

    Ok(module_base_address)
}
