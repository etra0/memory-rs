use winapi::um::winnt::{HANDLE};
use winapi::shared::basetsd::{DWORD_PTR};
use winapi::shared::minwindef::{LPVOID, LPCVOID};
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::memoryapi::{ReadProcessMemory, WriteProcessMemory};

pub struct Process {
    h_process: HANDLE,
    module_base_address: DWORD_PTR
}

impl Process {
    // this function takes offsets, *no absolute addresses*
    pub fn write_aob(&self, ptr: DWORD_PTR, data: &Vec<u8>) {
        super::super::memory::write_aob(self.h_process,
            self.module_base_address + ptr, &data);
    }

    pub fn get_aob(&self, ptr: DWORD_PTR, length: usize) -> Vec<u8> {
        let mut output: Vec<u8> = Vec::new();
        super::super::memory::get_aob(self.h_process,
            self.module_base_address + ptr, &mut output, length);

        output
    }

    pub fn read_value<OutputType>(&self, absolute_address: DWORD_PTR) -> OutputType {
        let mut buffer: OutputType = unsafe { std::mem::zeroed() };
        let s_buffer: usize = std::mem::size_of::<OutputType>();
        let mut read: usize = 0;

        unsafe {
            ReadProcessMemory(self.h_process, absolute_address as LPCVOID,
            &mut buffer as *mut OutputType as LPVOID, s_buffer,
            &mut read);
        };

        assert!(read != 0);
        buffer
    }

    pub fn write_value<InputType>(&self, absolute_address: DWORD_PTR, output: InputType) {
        let s: usize = std::mem::size_of::<InputType>();
        let mut written: usize = 0;

        unsafe {
            WriteProcessMemory(self.h_process, absolute_address as LPVOID, 
                (&output as *const InputType) as LPVOID, s, &mut written);
        };

        assert!(written != 0);
    }

    pub fn hook_function(&self, to_hook: DWORD_PTR, f: DWORD_PTR, len: usize) {
        super::super::memory::hook_function(self.h_process, to_hook, f, len);
    }

    pub fn new(process_name: &str) -> Process {
        let process_id = super::get_process_id(process_name)
            .expect("No process found");
        let module_base_address = super::get_module_base(process_id, process_name)
            .expect("No module found");
        
        let h_process = unsafe { OpenProcess(
            winapi::um::winnt::PROCESS_ALL_ACCESS,
            false as i32,
            process_id
        ) };

        assert!(!h_process.is_null());
        Process {
            h_process,
            module_base_address
        }
    }

    pub fn inject_shellcode(&self, entry_point: DWORD_PTR,
        instruction_size: usize, f: *const u8) -> DWORD_PTR {
        super::super::memory::inject_shellcode(self.h_process,
            self.module_base_address, entry_point,
            instruction_size, f)
    }
}
