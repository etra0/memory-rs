use std::slice::IterMut;
use std::marker::PhantomData;
use std::mem::MaybeUninit;
use std::ops::DerefMut;

use crate::internal::memory::{hook_function, write_aob, MemoryPattern};
use crate::internal::memory_region::*;
use anyhow::{Context, Result};
use winapi::um::memoryapi::VirtualProtect;
use winapi::um::winnt::PAGE_EXECUTE_READWRITE;

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
#[derive(Debug)]
pub struct Detour {
    /// Pointer where the detour will be injected.
    pub entry_point: usize,
    /// Original bytes where the entry_point points.
    f_orig: Vec<u8>,

    /// New function where the detour will redirect.
    new_function: usize,

    /// Optional pointer that will be written the jump back if what you
    /// inject isn't technically a function (i.e. doesn't return)
    function_end: Option<&'static mut usize>,
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
            let slice_ = std::slice::from_raw_parts(entry_point as *const u8, size);
            f_orig.extend_from_slice(slice_);
        }

        Detour {
            entry_point,
            f_orig,
            new_function,
            function_end,
        }
    }

    /// Creates a Detour from scan_aob. This function can fail
    /// in the case when the scan_aob can't find it's target.
    pub fn new_from_aob(
        scan: MemoryPattern,
        region: &MemoryRegion,
        new_function: usize,
        function_end: Option<&'static mut usize>,
        size_injection: usize,
        offset: Option<isize>,
    ) -> Result<Detour> {
        let mut entry_point = region.scan_aob(&scan)?.context("Couldn't find aob")?;

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
        unsafe {
            hook_function(
                self.entry_point,
                self.new_function,
                self.function_end.as_deref_mut(),
                self.f_orig.len(),
            )
            .unwrap();
        }
    }

    fn remove_injection(&mut self) {
        unsafe {
            write_aob(self.entry_point, &self.f_orig).unwrap();
        }
    }
}

#[cfg(feature = "impl-drop")]
impl Drop for Detour {
    fn drop(&mut self) {
        self.remove_injection();
    }
}

/// `Injection` is a simple structure that contains an address where
/// the instructions to be modified are, and the original bytes with
/// the new ones. This struct is intended to be injected and removed
/// easily.
#[derive(Debug)]
pub struct Injection {
    /// Entry point relative to the executable
    pub entry_point: usize,
    /// Original bytes
    pub f_orig: Vec<u8>,
    /// Bytes to be injected
    pub f_new: Vec<u8>,
}

impl Injection {
    pub fn new(entry_point: usize, f_new: Vec<u8>) -> Injection {
        let aob_size = f_new.len();
        let slice = unsafe { std::slice::from_raw_parts(entry_point as *const u8, aob_size) };
        let mut f_orig = Vec::new();
        f_orig.extend_from_slice(slice);

        Injection {
            entry_point,
            f_orig,
            f_new,
        }
    }

    /// Creates a new injection using the `generate_aob_pattern` macro.
    /// # Example
    /// ```
    /// # use memory_rs::internal::{injections::*, memory::MemoryPattern};
    /// # use memory_rs::internal::process_info::ProcessInfo;
    /// # use memory_rs::generate_aob_pattern;
    /// # #[allow(non_upper_case_globals)]
    /// static arr: [u8; 5] = [0xEE, 0xAA, 0xFF, 0xBB, 0xFF];
    /// # // avoid removal of arr at compilation
    /// # println!("{:x?}", arr);
    /// # let proc_inf = ProcessInfo::new(None).unwrap();
    /// let mut injection = Injection::new_from_aob(&proc_inf.region, vec![0x90; 3],
    ///     generate_aob_pattern![0xAA, _, 0xBB, 0xFF]).unwrap();
    /// // With this we nop the bytes (i.e. we write 0x90) where
    /// // generate_aob_pattern has a match.
    /// injection.inject();
    /// assert_eq!(&arr[1..4], &[0x90, 0x90, 0x90]);
    ///
    /// // If we remove the injection (or `injection` gets dropped) the original
    /// // array should be restored.
    /// injection.remove_injection();
    /// assert_eq!(&arr[1..4], &[0xAA, 0xFF, 0xBB]);
    ///
    /// ```
    pub fn new_from_aob(
        region: &MemoryRegion,
        f_new: Vec<u8>,
        memory_pattern: MemoryPattern,
    ) -> Result<Injection> {
        let entry_point = region
            .scan_aob(&memory_pattern)?
            .context("Couldn't find aob")?;
        Ok(Injection::new(entry_point, f_new))
    }
}

impl Inject for Injection {
    fn inject(&mut self) {
        unsafe {
            write_aob(self.entry_point, &(self.f_new)).unwrap();
        }
    }

    fn remove_injection(&mut self) {
        unsafe {
            write_aob(self.entry_point, &(self.f_orig)).unwrap();
        }
    }
}

#[cfg(feature = "impl-drop")]
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

#[cfg(feature = "impl-drop")]
impl Drop for StaticElement {
    fn drop(&mut self) {
        self.remove_injection();
    }
}

#[derive(Debug)]
pub struct Trampoline {
    // Address of the new function
    new_function: usize,
    // Address of the original function
    original_function: usize,

    // Injection size, to know how many bytes to copy.
    injection_size: usize,
    original_bytes: [u8; 64],
    shellcode_space: Box<[u8; 1024]>,
    detour: MaybeUninit<Detour>
}

impl Trampoline {
    pub fn new(new_function: usize, original_function: usize, injection_size: usize) -> Self {
        // First we backup the starting bytes of the original function. Usually, the injection size
        // is not that big so we can use a large-enough buffer.
        // We need to make sure we manually checked how many bytes we need in order to not break
        // any assembly instruction, so the injection size has to be carefully checked.
        // TODO: Check this is the correct way.
        let shellcode_space = Box::new([0_u8; 1024]);

        let mut result = Self {
            new_function,
            original_function,
            injection_size,
            original_bytes: [0_u8; 64],
            shellcode_space,
            detour: MaybeUninit::uninit()
        };

        unsafe { std::ptr::copy_nonoverlapping(original_function as *const u8,
            result.original_bytes.as_mut_ptr(), injection_size) };

        // Make sure we make the allocated space executable for the lulz.
        let mut old_prot = 0;
        unsafe { VirtualProtect(result.shellcode_space.as_mut_ptr() as _, 1024, PAGE_EXECUTE_READWRITE, &mut old_prot) };

        // extended jump is jmp [rip +0x0], which effectively jumps to the address next to the
        // instruction. This is useful for 8 bytes jump, this is not optimal but it's functional
        // because we can spare some bytes.
        let extended_jump = [0xff_u8, 0x25, 0x00, 0x00, 0x00, 0x00];

        // First we write the jump into our function, which effectively requires 14 bytes.
        let mut injection: Vec<u8> = Vec::with_capacity(1024);
        injection.extend_from_slice(&extended_jump);
        injection.extend_from_slice(&result.new_function.to_le_bytes());

        injection.extend_from_slice(&result.original_bytes[..injection_size]);
        injection.extend_from_slice(&extended_jump);
        let original_addr = result.original_function + result.injection_size;
        injection.extend_from_slice(&original_addr.to_le_bytes());

        result.shellcode_space[..injection.len()].copy_from_slice(&injection);
        // Initialize internal detour
        let detour: MaybeUninit<Detour> = MaybeUninit::new(Detour::new(result.original_function, result.injection_size, result.shellcode_space.as_ptr() as _, None));
        result.detour = detour;

        result
    }

    pub fn get_original_function_addr(&self) -> usize {
        self.shellcode_space.as_ptr() as usize + self.injection_size
    }

}

impl Inject for Trampoline {
    fn inject(&mut self) {
        let detour = unsafe { self.detour.assume_init_mut() };
        detour.inject();
    }

    fn remove_injection(&mut self) {
        let detour = unsafe { self.detour.assume_init_mut() };
        detour.remove_injection();
    }
}

impl Inject for Box<dyn Inject> {
    fn inject(&mut self) {
        self.deref_mut().inject();
    }

    fn remove_injection(&mut self) {
        self.deref_mut().remove_injection();
    }
}

impl<T: Inject> Inject for IterMut<'_, T> {
    fn inject(&mut self) {
        self.for_each(|x| x.inject());
    }

    fn remove_injection(&mut self) {
        self.for_each(|x| x.remove_injection());
    }
}
