use crate::try_winapi;
use anyhow::Result;
use std::ffi::CString;
use winapi::shared::minwindef::HMODULE;

/// Struct that contains some very basic information of a executable or DLL.
#[derive(Debug)]
pub struct ProcessInfo {
    pub handle: HMODULE,
    pub addr: usize,
    pub size: usize,
}

impl ProcessInfo {
    /// Create the ProcessInfo. This function can fail in case where
    /// the `GetModuleInformation` fails.
    pub fn new(name: Option<&'static str>) -> Result<ProcessInfo> {
        let module = match name {
            Some(n) => {
                let name_ = CString::new(n)?;
                unsafe { winapi::um::libloaderapi::GetModuleHandleA(name_.as_ptr()) }
            },
            None => unsafe { winapi::um::libloaderapi::GetModuleHandleA(std::ptr::null()) }
        };

        let module_addr = module as usize;

        let module_size: usize;
        unsafe {
            let process = winapi::um::processthreadsapi::GetCurrentProcess();
            let mut module_info = winapi::um::psapi::MODULEINFO::default();
            try_winapi!(winapi::um::psapi::GetModuleInformation(
                process,
                module,
                &mut module_info,
                std::mem::size_of::<winapi::um::psapi::MODULEINFO>() as u32,
            ));

            module_size = module_info.SizeOfImage as usize;
        }

        Ok(ProcessInfo {
            handle: module,
            addr: module_addr,
            size: module_size,
        })
    }
}
