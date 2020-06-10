use std::io::Error;
use winapi::shared::basetsd::DWORD_PTR;
use winapi::shared::minwindef::{LPCVOID, LPVOID};
use winapi::um::memoryapi::{ReadProcessMemory, WriteProcessMemory};
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::winnt::HANDLE;

pub struct Process {
    pub h_process: HANDLE,
    pub module_base_address: DWORD_PTR,
}

impl Process {
    // this function takes offsets, *no absolute addresses*
    pub fn write_aob(&self, ptr: DWORD_PTR, data: &Vec<u8>, absolute: bool) {
        let addr = if absolute {
            ptr
        } else {
            self.module_base_address + ptr
        };

        crate::memory::write_aob(self.h_process, addr, &data);
    }

    pub fn write_nops(&self, ptr: DWORD_PTR, n: usize, absolute: bool) {
        let addr = if absolute {
            ptr
        } else {
            self.module_base_address + ptr
        };

        crate::memory::write_nops(self.h_process, addr, n);
    }

    pub fn get_aob(&self, ptr: DWORD_PTR, length: usize, absolute: bool) -> Vec<u8> {
        let addr = if absolute {
            ptr
        } else {
            self.module_base_address + ptr
        };

        let output: Vec<u8> = crate::memory::get_aob(self.h_process, addr, length);

        output
    }

    // TODO: Move this function out of process because it should be in
    // memory/mod.rs.
    pub fn read_value<OutputType>(&self, ptr: DWORD_PTR, absolute: bool) -> OutputType {
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

    pub fn write_value<InputType>(&self, ptr: DWORD_PTR, output: InputType, absolute: bool) {
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

    pub fn hook_function(&self, to_hook: DWORD_PTR, f: DWORD_PTR, len: usize) {
        crate::memory::hook_function(self.h_process, to_hook, f, len);
    }

    pub fn new(process_name: &str) -> Result<Process, Error> {
        let process_id = super::get_process_id(process_name)?;
        let module_base_address = super::get_module_base(process_id, process_name)?;

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

    pub fn inject_shellcode(
        &self,
        entry_point: DWORD_PTR,
        instruction_size: usize,
        f_start: *const u8,
        f_end: *const u8,
    ) -> DWORD_PTR {
        crate::memory::inject_shellcode(
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
        ending: &Vec<u8>,
    ) -> Vec<(usize, String)> {
        let mut c_address = address;

        let mut data: Vec<(usize, String)> = vec![];

        let mut c_index = starting_index;

        let mut c_string = String::from("");
        loop {
            let current_read: Vec<u8> = self.get_aob(c_address, 2, true);

            if current_read == *ending {
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
