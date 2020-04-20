mod process;
mod memory;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }

    #[test]
    fn open_process_and_module() {
        let process_id = super::process::get_process_id("Code.exe")
            .expect("The process ID was not obtained");

        assert!(process_id != 0, "Couldn't find process");

        let module_base_address = super::process::get_module_base(
            process_id, "Code.exe")
            .expect("Couldn't obtain the module base address");

        assert!(module_base_address != 0);
    }

    #[test]
    fn test_yakuza() {
        let process_id = super::process::get_process_id("Yakuza0.exe")
            .expect("No process found");
        let module_base_address = super::process::get_module_base(process_id, "Yakuza0.exe")
            .expect("No module found");

        assert_eq!(module_base_address, 0x140000000);
        
        let offset = 0x18B1E5;

        let nops = vec![0x90, 0x90, 0x90];
        let mut orig: Vec<u8> = Vec::new();

        println!("Process id: {:x}, Module_base_address: {:x}", process_id, module_base_address);

        let h_process = unsafe { winapi::um::processthreadsapi::OpenProcess(winapi::um::winnt::PROCESS_ALL_ACCESS, false as i32, process_id) };
        assert!(!h_process.is_null());

        println!("hprocess: {:x?}", h_process);

        super::memory::get_aob(h_process, module_base_address + offset, &mut orig, 3);

        println!("vec: {:x?}", orig);

        super::memory::write_aob(h_process, module_base_address + offset, &nops);

        super::memory::get_aob(h_process, module_base_address + offset, &mut orig, 3);
        assert_eq!(orig, nops, "The memory was not written");

    }
}
