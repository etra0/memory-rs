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
            process_id, "win32u.dll")
            .expect("Couldn't obtain the module base address");

        assert!(module_base_address != 0);

    }
}
