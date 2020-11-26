use crate::internal::memory::{hook_function, scan_aob, write_aob};
use crate::internal::process_info::ProcessInfo;
use anyhow::{Context, Result};

/// Trait specifically designed to extend the Vec<T> struct in order
/// to easily write something like `vec.inject()` when you have a vector
/// of structs that implements Inject.
pub trait Inject {
    fn inject(&mut self);
    fn remove_injection(&mut self);
}

/// Struct that contains its entry point and original bytes.
/// The purpose of this struct is that when it goes out of scope,
/// it automatically removes the modified bytes in order to do a clean
/// remove of the DLL.
pub struct Detour {
    /// Pointer where the detour will be injected.
    pub entry_point: usize,
    /// Original bytes where the entry_point points.
    f_orig: Vec<u8>,

    /// New function where the detour will redirect.
    new_function: usize,

    /// Optional pointer that will be written the jump back if what you
    /// inject isn't technically a function (i.e. doesn't return)
    function_end: Option<&'static mut usize>
}

impl Detour {
    pub fn new(
        entry_point: usize,
        size: usize,
        new_function: usize,
        function_end: Option<&'static mut usize>,
    ) -> Detour {
        let mut f_orig = vec![];

        unsafe {
            let slice_ = std::slice::from_raw_parts(entry_point as *mut u8, size);
            f_orig.extend_from_slice(slice_);
        }

        Detour {
            entry_point,
            f_orig,
            new_function,
            function_end
        }
    }

    /// Creates a Detour from scan_aob. This function can fail
    /// in the case when the scan_aob can't find it's target.
    pub fn new_from_aob<T>(
        scan: (usize, T),
        process_inf: &ProcessInfo,
        new_function: usize,
        function_end: Option<&'static mut usize>,
        size_injection: usize,
        offset: Option<isize>,
    ) -> Result<Detour>
    where
        T: Fn(&[u8]) -> bool,
    {
        let (size, func) = scan;
        let mut entry_point = scan_aob(process_inf.addr, process_inf.size, func, size)?
            .context("Couldn't find aob")?;

        if let Some(v) = offset {
            entry_point = ((entry_point as isize) + v) as usize;
        }

        Ok(Detour::new(
            entry_point,
            size_injection,
            new_function,
            function_end,
        ))
    }
}

impl Inject for Detour {
    fn inject(&mut self) {
        if let Some(function_end) = &mut self.function_end {
            unsafe {
                hook_function(
                    self.entry_point,
                    self.new_function,
                    Some(function_end),
                    self.f_orig.len()
                ).unwrap();
            }
        } else {
            unsafe {
                hook_function(
                    self.entry_point,
                    self.new_function,
                    None,
                    self.f_orig.len()
                ).unwrap();
            }
        }
    }

    fn remove_injection(&mut self) {
        unsafe {
            write_aob(self.entry_point, &self.f_orig)
                .unwrap();
        }
    }
}

impl Drop for Detour {
    fn drop(&mut self) {
        self.remove_injection();
    }
}

/// `Injection` is a simple structure that contains an address where
/// the instructions to be modified are, and the original bytes with
/// the new ones. This struct is intended to be injected and removed
/// easily.
pub struct Injection {
    /// Entry point relative to the executable
    pub entry_point: usize,
    /// Original bytes
    pub f_orig: Vec<u8>,
    /// Bytes to be injected
    pub f_rep: Vec<u8>,
}

impl Injection {
    pub fn new(entry_point: usize, f_rep: Vec<u8>) -> Injection {
        let aob_size = f_rep.len();
        let slice = unsafe { std::slice::from_raw_parts(entry_point as *const u8, aob_size) };
        let mut f_orig = Vec::new();
        f_orig.extend_from_slice(slice);

        Injection {
            entry_point,
            f_orig,
            f_rep,
        }
    }

    /// Creates a new injection using the `generate_aob_pattern` macro.
    /// # Example
    /// ```
    /// let injection = Injection::new_from_aob(proc_inf, vec![0x90; 4],
    ///     generate_aob_pattern![0xAA, _, 0xBB]).unwrap();
    /// // With this we nop the bytes (i.e. we write 0x90) where
    /// // generate_aob_pattern has a match.
    /// injection.inject()
    /// ```
    pub fn new_from_aob<T>(
        proc_inf: &ProcessInfo,
        f_rep: Vec<u8>,
        aob_tuple: (usize, T),
    ) -> Result<Injection>
    where
        T: Fn(&[u8]) -> bool,
    {
        let (size, func) = aob_tuple;
        let entry_point =
            scan_aob(proc_inf.addr, proc_inf.size, func, size)?.context("Couldn't find aob")?;
        Ok(Injection::new(entry_point, f_rep))
    }
}

impl Inject for Injection {
    fn inject(&mut self) {
        unsafe {
            write_aob(self.entry_point, &(self.f_rep)).unwrap();
        }
    }

    fn remove_injection(&mut self) {
        unsafe {
            write_aob(self.entry_point, &(self.f_orig)).unwrap();
        }
    }
}

impl Drop for Injection {
    fn drop(&mut self) {
        self.remove_injection();
    }
}

/// StaticElement are all the variables that aren't changed that often,
/// usually globals.
pub struct StaticElement {
    addr: usize,
    original_value: Option<u32>,
}

impl StaticElement {
    pub fn new(addr: usize) -> StaticElement {
        let original_value = unsafe { Some(*(addr as *mut u32)) };

        StaticElement {
            addr,
            original_value,
        }
    }
}

impl Inject for StaticElement {
    fn inject(&mut self) {
        unsafe {
            let ptr = self.addr as *mut u32;
            if self.original_value.is_none() {
                self.original_value = Some(*ptr);
            }
            *ptr = 0;
        }
    }

    fn remove_injection(&mut self) {
        if self.original_value.is_none() {
            return;
        }
        unsafe {
            let ptr = self.addr as *mut u32;
            *ptr = self.original_value.unwrap();
        }

        self.original_value = None;
    }
}

impl Drop for StaticElement {
    fn drop(&mut self) {
        self.remove_injection();
    }
}

impl<T> Inject for std::vec::Vec<T>
where
    T: Inject,
{
    fn inject(&mut self) {
        self.iter_mut().for_each(|x| (*x).inject());
    }
    fn remove_injection(&mut self) {
        self.iter_mut().for_each(|x| (*x).remove_injection());
    }
}
