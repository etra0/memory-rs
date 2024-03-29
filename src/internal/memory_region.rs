use crate::error::*;
use crate::internal::memory;
use anyhow::Result;

#[derive(Debug)]
pub struct MemoryRegion {
    pub start_address: usize,
    pub size: usize,
    is_safe: bool,
}

impl MemoryRegion {
    pub fn new(start_address: usize, size: usize, is_safe: bool) -> Result<Self> {
        let memory_region = Self {
            start_address,
            size,
            is_safe,
        };

        // Do at least one check if the memory is safe
        memory::check_valid_region(start_address, size)?;

        Ok(memory_region)
    }

    fn check_valid_region(&self) -> Result<()> {
        if !self.is_safe {
            memory::check_valid_region(self.start_address, self.size)?;
        }

        Ok(())
    }

    pub fn scan_aob(&self, pat: &memory::MemoryPattern) -> Result<Option<usize>> {
        self.check_valid_region()?;

        let data = unsafe { std::slice::from_raw_parts(self.start_address as *mut u8, self.size) };
        let index = data.windows(pat.size).position(pat.pattern);

        match index {
            Some(addr) => Ok(Some(self.start_address + addr)),
            None => Ok(None),
        }
    }

    pub fn scan_aob_all_matches(&self, pat: &memory::MemoryPattern) -> Result<Vec<usize>> {
        self.check_valid_region()?;
        let data = unsafe { std::slice::from_raw_parts(self.start_address as *mut u8, self.size) };
        let mut iter = data.windows(pat.size);
        let mut matches = Vec::new();

        loop {
            let val = iter.position(pat.pattern);
            if val.is_none() {
                break;
            }

            let val = val.unwrap();
            match matches.last() {
                Some(&last_val) => matches.push(val + last_val + 0x1),
                None => matches.push(self.start_address + val),
            };
        }

        Ok(matches)
    }

    /// Scan all aob matches aligned at `align`. If None is provided, it will align to 4 by default
    pub fn scan_aob_all_matches_aligned(
        &self,
        pat: &memory::MemoryPattern,
        align: Option<usize>,
    ) -> Result<Vec<usize>> {
        self.check_valid_region()?;
        let data = unsafe { std::slice::from_raw_parts(self.start_address as *mut u8, self.size) };
        let align = align.unwrap_or(4);
        let padding = (align - (pat.size % align)) % align;
        let chunk_size = pat.size + padding;
        let mut iter = data.chunks_exact(chunk_size);
        let mut matches = Vec::new();

        loop {
            let val = iter.position(|x| pat.scan(&x[..pat.size]));
            if val.is_none() {
                break;
            }

            let val = val.unwrap();
            match matches.last() {
                Some(&last_val) => matches.push((val + 0x1) * chunk_size + last_val),
                None => matches.push(self.start_address + val),
            };
        }

        Ok(matches)
    }

    pub fn scan_aligned_value<T>(&self, value: T) -> Result<Vec<usize>>
    where
        T: Copy + PartialEq,
    {
        self.check_valid_region()?;
        let size_type = std::mem::size_of::<T>();
        let mut matches = Vec::new();

        if self.size / size_type == 0 {
            return Err(Error::new(
                ErrorType::Internal,
                "The space to scan is smaller than the type size".into(),
            )
            .into());
        }

        let data = unsafe {
            std::slice::from_raw_parts(self.start_address as *mut T, self.size / size_type)
        };
        let mut iter = data.iter();

        let match_function = |&x| x == value;

        while let Some(val) = iter.position(match_function) {
            match matches.last() {
                Some(&last_val) => matches.push((val + 0x1) * size_type + last_val),
                None => matches.push((val * size_type) + self.start_address),
            };
        }

        Ok(matches)
    }
}
