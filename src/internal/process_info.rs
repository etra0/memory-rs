use crate::error::{Error, ErrorType};
use crate::internal::memory_region::*;
use crate::wrap_winapi;
use anyhow::Result;
use windows_sys::Win32::Foundation::HINSTANCE;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::ProcessStatus::{K32GetModuleInformation, MODULEINFO};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

/// Struct that contains some very basic information of a executable or DLL.
#[derive(Debug)]
pub struct ProcessInfo {
    pub handle: HINSTANCE,
    pub region: MemoryRegion,
}

impl ProcessInfo {
    /// Create the ProcessInfo. This function can fail in case where
    /// the `GetModuleInformation` fails.
    pub fn new(name: Option<&str>) -> Result<ProcessInfo> {
        let module = match name {
            Some(n) => {
                let mut name_ = n.to_string();
                name_.push('\0');
                let name_wide: Vec<u16> = name_.encode_utf16().collect();
                unsafe { wrap_winapi!(GetModuleHandleW(name_wide.as_ptr()), x == 0)? }
            }
            None => unsafe { wrap_winapi!(GetModuleHandleW(std::ptr::null()), x == 0)? },
        };

        let module_addr = module as usize;

        let module_size: usize;
        unsafe {
            let process = GetCurrentProcess();
            let mut module_info: MODULEINFO = std::mem::zeroed();
            wrap_winapi!(
                K32GetModuleInformation(
                    process,
                    module,
                    &mut module_info,
                    std::mem::size_of::<MODULEINFO>() as u32,
                ),
                x == 0
            )?;

            module_size = module_info.SizeOfImage as usize;
        }

        if module_addr == 0x0 {
            return Err(
                Error::new(ErrorType::Internal, "Base address can't be 0".to_string()).into(),
            );
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
