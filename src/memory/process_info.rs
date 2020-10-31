use std::ffi::CString;
use winapi::shared::minwindef::HMODULE;
use std::io::Error;

pub struct ProcessInfo {
    pub handle: HMODULE,
    pub addr: usize,
    pub size: usize,
}

impl ProcessInfo {
    pub fn new(name: &str) -> Result<ProcessInfo, String> {
        let name = CString::new(name).map_err(|_| "String couldn't be allocated")?;

        let module = unsafe { winapi::um::libloaderapi::GetModuleHandleA(name.as_ptr()) };

        let module_addr = module as usize;

        let module_size: usize;
        let status = unsafe {
            let process = winapi::um::processthreadsapi::GetCurrentProcess();
            let mut module_info = winapi::um::psapi::MODULEINFO::default();
            let result = winapi::um::psapi::GetModuleInformation(
                process,
                module,
                &mut module_info,
                std::mem::size_of::<winapi::um::psapi::MODULEINFO>() as u32,
            );

            module_size = module_info.SizeOfImage as usize;
            result
        };
        
        if status == 0 {
            let err_msg = format!("Couldn't get GetModuleInformation, reason: {:?}", Error::last_os_error());
            return Err(err_msg.to_string());
        }

        Ok(ProcessInfo {
            handle: module,
            addr: module_addr,
            size: module_size,
        })
    }
}
