use std::ffi::CString;
use winapi::shared::minwindef::HMODULE;

pub struct ProcessInfo {
    pub handle: HMODULE,
    pub addr: usize,
    pub size: usize,
}

impl ProcessInfo {
    pub fn new(name: &str) -> ProcessInfo {
        let name = CString::new(name).expect("String couldn't be allocated");

        let module = unsafe { winapi::um::libloaderapi::GetModuleHandleA(name.as_ptr()) };

        let module_addr = module as usize;

        let module_size: usize;
        unsafe {
            let process = winapi::um::processthreadsapi::GetCurrentProcess();
            let mut module_info = winapi::um::psapi::MODULEINFO::default();
            winapi::um::psapi::GetModuleInformation(
                process,
                module,
                &mut module_info,
                std::mem::size_of::<winapi::um::psapi::MODULEINFO>() as u32,
            );

            module_size = module_info.SizeOfImage as usize;
        }

        ProcessInfo {
            handle: module,
            addr: module_addr,
            size: module_size,
        }
    }
}
