pub mod memory;
pub mod process;

#[cfg(test)]
mod tests {
    #[test]
    fn test_yakuza() {
        use crate::process::process_wrapper;

        let process = process_wrapper::Process::new("Yakuza0.exe").unwrap();

        let offset = 0x18B1E5;
        let nops = vec![0x90, 0x90, 0x90, 0x90];

        let orig = process.get_aob(offset, 3, false);

        assert_eq!(
            orig,
            vec![0x0F, 0x29, 0x06],
            "get_aob isnt working properly"
        );

        process.write_aob(offset, &nops, false);

        let orig = process.get_aob(offset, 4, false);

        assert_eq!(orig, nops, "The memory was not written");

        // super::memory::hook_function(h_process, module_base_address,
        //     module_base_address + 0x100, 5);

        // super::memory::inject_shellcode(h_process, 0x14000000,
        //     dummy as usize as *const u8);
    }
}
