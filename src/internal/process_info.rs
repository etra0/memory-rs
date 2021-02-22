use crate::error::{Error, ErrorType};
use crate::internal::memory_region::*;
use crate::try_winapi;
use anyhow::Result;
use std::ffi::CString;
use winapi::shared::minwindef::HMODULE;
use winapi::um::{
    libloaderapi::GetModuleHandleA, processthreadsapi::GetCurrentProcess,
    psapi::GetModuleInformation,
};

/// Struct that contains some very basic information of a executable or DLL.
#[derive(Debug)]
pub struct ProcessInfo {
    pub handle: HMODULE,
    pub region: MemoryRegion,
}

impl ProcessInfo {
    /// Create the ProcessInfo. This function can fail in case where
    /// the `GetModuleInformation` fails.
    pub fn new(name: Option<&'static str>) -> Result<ProcessInfo> {
        let module = match name {
            Some(n) => {
                let name_ = CString::new(n)?;
                unsafe { GetModuleHandleA(name_.as_ptr()) }
            }
            None => unsafe { GetModuleHandleA(std::ptr::null()) },
        };

        let module_addr = module as usize;

        let module_size: usize;
        unsafe {
            let process = GetCurrentProcess();
            let mut module_info = winapi::um::psapi::MODULEINFO::default();
            try_winapi!(GetModuleInformation(
                process,
                module,
                &mut module_info,
                std::mem::size_of::<winapi::um::psapi::MODULEINFO>() as u32,
            ));

            module_size = module_info.SizeOfImage as usize;
        }

        if module_addr == 0x0 {
            return Err(Error::new(
                ErrorType::Internal,
                "Base address can't be 0".to_string(),
            )
            .into());
        }

        if module_size == 0x0 {
            return Err(Error::new(
                ErrorType::Internal,
                "Size of the module can't be 0".to_string(),
            )
            .into());
        }

        let region = MemoryRegion::new(module_addr, module_size, true)?;

        Ok(ProcessInfo {
            handle: module,
            region,
        })
    }
}
