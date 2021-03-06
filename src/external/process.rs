use std::ffi::CStr;
use std::io::Error;
use std::mem;
use winapi::shared::basetsd::DWORD_PTR;
use winapi::shared::minwindef::DWORD;
use winapi::shared::minwindef::{LPCVOID, LPVOID};
use winapi::um::handleapi;
use winapi::um::memoryapi::{ReadProcessMemory, WriteProcessMemory};
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::tlhelp32;
use winapi::um::winnt::HANDLE;

pub struct Process {
    pub h_process: HANDLE,
    pub module_base_address: DWORD_PTR,
}

impl Process {
    pub fn new(process_name: &str) -> Result<Process, Error> {
        let process_id = get_process_id(process_name)?;
        let module_base_address = get_module_base(process_id, process_name)?;

        let h_process = unsafe {
            OpenProcess(
                winapi::um::winnt::PROCESS_ALL_ACCESS,
                false as i32,
                process_id,
            )
        };

        if h_process.is_null() {
            return Err(Error::last_os_error());
        }

        Ok(Process {
            h_process,
            module_base_address,
        })
    }

    /// Writes an array of bytes (as vectors) into the desired address.
    /// It can take relative or absolute values.
    pub fn write_aob(&self, ptr: DWORD_PTR, data: &[u8], absolute: bool) {
        let addr = if absolute {
            ptr
        } else {
            self.module_base_address + ptr
        };

        crate::external::memory::write_aob(self.h_process, addr, &data);
    }

    /// Writes `n` nops into the desired address
    /// It can take relative or absolute values.
    pub fn write_nops(&self, ptr: DWORD_PTR, n: usize, absolute: bool) {
        let addr = if absolute {
            ptr
        } else {
            self.module_base_address + ptr
        };

        crate::external::memory::write_nops(self.h_process, addr, n);
    }

    /// Reads `n` bytes from the desired address
    /// It can take relative or absolute values.
    pub fn get_aob(&self, ptr: DWORD_PTR, n: usize, absolute: bool) -> Vec<u8> {
        let addr = if absolute {
            ptr
        } else {
            self.module_base_address + ptr
        };

        let output: Vec<u8> =
            crate::external::memory::get_aob(self.h_process, addr, n);

        output
    }

    // TODO: Move this function out of process because it should be in
    // memory/mod.rs.
    pub fn read_value<OutputType>(
        &self,
        ptr: DWORD_PTR,
        absolute: bool,
    ) -> OutputType {
        let addr = if absolute {
            ptr
        } else {
            self.module_base_address + ptr
        };

        let mut buffer: OutputType = unsafe { std::mem::zeroed() };
        let s_buffer: usize = std::mem::size_of::<OutputType>();
        let mut read: usize = 0;

        unsafe {
            ReadProcessMemory(
                self.h_process,
                addr as LPCVOID,
                &mut buffer as *mut OutputType as LPVOID,
                s_buffer,
                &mut read,
            );
        };

        assert_eq!(read, s_buffer);
        buffer
    }

    pub fn write_value<InputType>(
        &self,
        ptr: DWORD_PTR,
        output: InputType,
        absolute: bool,
    ) {
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
                addr as LPVOID,
                (&output as *const InputType) as LPVOID,
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
        entry_point: DWORD_PTR,
        instruction_size: usize,
        f_start: *const u8,
        f_end: *const u8,
    ) -> DWORD_PTR {
        crate::external::memory::inject_shellcode(
            self.h_process,
            self.module_base_address,
            entry_point,
            instruction_size,
            f_start,
            f_end,
        )
    }

    pub fn read_string_array(
        &self,
        address: DWORD_PTR,
        starting_index: usize,
        ending: &[u8],
    ) -> Vec<(usize, String)> {
        let mut c_address = address;

        let mut data: Vec<(usize, String)> = vec![];

        let mut c_index = starting_index;

        let mut c_string = String::from("");
        loop {
            let current_read: Vec<u8> = self.get_aob(c_address, 2, true);

            if current_read[..] == *ending {
                break;
            }
            if current_read[0] == 0x00 {
                data.push((c_index, c_string));
                c_string = String::from("");
                c_index += 1;
                c_address += 1;
                continue;
            }

            c_string.push(current_read[0] as char);
            c_address += 1;
        }

        data
    }
}

pub fn get_process_id(process_name: &str) -> Result<DWORD, Error> {
    let mut process_id: DWORD = 0;
    let h_snap = unsafe {
        tlhelp32::CreateToolhelp32Snapshot(tlhelp32::TH32CS_SNAPPROCESS, 0)
    };

    if h_snap == handleapi::INVALID_HANDLE_VALUE {
        return Err(Error::last_os_error());
    }

    let mut process_entry = tlhelp32::PROCESSENTRY32 {
        dwSize: mem::size_of::<tlhelp32::PROCESSENTRY32>() as u32,
        ..Default::default()
    };

    unsafe {
        if tlhelp32::Process32First(h_snap, &mut process_entry) == 1 {
            process_id = loop {
                let current_name =
                    CStr::from_ptr(process_entry.szExeFile.as_ptr())
                        .to_str()
                        .expect("No string found");

                if current_name == process_name {
                    break process_entry.th32ProcessID;
                }

                if tlhelp32::Process32Next(h_snap, &mut process_entry) == 0 {
                    break 0;
                }
            }
        }

        handleapi::CloseHandle(h_snap);
    }

    if process_id == 0 {
        return Err(Error::last_os_error());
    }

    Ok(process_id)
}

pub fn get_module_base(
    process_id: DWORD,
    module_name: &str,
) -> Result<DWORD_PTR, Error> {
    let mut module_base_address: DWORD_PTR = 0x0;
    let h_snap = unsafe {
        tlhelp32::CreateToolhelp32Snapshot(
            tlhelp32::TH32CS_SNAPMODULE | tlhelp32::TH32CS_SNAPMODULE32,
            process_id,
        )
    };

    if h_snap == handleapi::INVALID_HANDLE_VALUE {
        return Err(Error::last_os_error());
    }

    let mut module_entry = tlhelp32::MODULEENTRY32 {
        dwSize: mem::size_of::<tlhelp32::MODULEENTRY32>() as u32,
        ..Default::default()
    };

    unsafe {
        if tlhelp32::Module32First(h_snap, &mut module_entry) != 0 {
            module_base_address = loop {
                let current_name =
                    CStr::from_ptr(module_entry.szModule.as_ptr())
                        .to_str()
                        .expect("No string found");

                if current_name == module_name {
                    break module_entry.modBaseAddr as DWORD_PTR;
                }

                if tlhelp32::Module32Next(h_snap, &mut module_entry) == 0 {
                    break 0;
                }
            }
        }

        handleapi::CloseHandle(h_snap);
    }

    if module_base_address == 0 {
        return Err(Error::last_os_error());
    }

    Ok(module_base_address)
}
