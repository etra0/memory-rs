use winapi::shared::basetsd::{DWORD_PTR};
use winapi::shared::minwindef::{LPVOID, LPCVOID, DWORD, PDWORD};
use winapi::um::winnt::{HANDLE, PAGE_EXECUTE_READWRITE, MEM_RESERVE,
    MEM_COMMIT};
use winapi::um::memoryapi::{ReadProcessMemory, WriteProcessMemory,
    VirtualProtectEx, VirtualAllocEx};
use std::mem;

pub fn get_aob(h_process: HANDLE, ptr: DWORD_PTR, target: &mut Vec<u8>,
    n: usize) {

    let mut c_addr = ptr;
    let mut c_value: u8 = 0x0;
    for _ in 0..n {
        unsafe {
            ReadProcessMemory(
                h_process,
                c_addr as LPCVOID,
                (&mut c_value as *mut u8) as LPVOID,
                mem::size_of::<u8>(),
                std::ptr::null_mut()
            );
        }
        target.push(c_value);
        c_addr += 1;
    }
}

pub fn write_aob(h_process: HANDLE, ptr: DWORD_PTR, source: &Vec<u8>) -> usize {
    let mut protection_bytes: DWORD = 0x0;
    let c_addr = ptr;
    let size = source.len();
    let mut written = 0;

    unsafe { 
        VirtualProtectEx(
            h_process,
            c_addr as LPVOID,
            size,
            PAGE_EXECUTE_READWRITE,
            &mut protection_bytes as PDWORD
        );

        WriteProcessMemory(
            h_process,
            c_addr as LPVOID,
            source[..].as_ptr() as LPVOID,
            size,
            &mut written
        );

        VirtualProtectEx(
            h_process,
            c_addr as LPVOID,
            size,
            protection_bytes,
            &mut protection_bytes as PDWORD
        );
    }

    written
}

pub fn write_nops(h_process: HANDLE, ptr: DWORD_PTR, n: usize) {
    let nops: Vec<u8> = vec![0x90; n];
    write_aob(h_process, ptr, &nops);
}

pub fn hook_function(h_process: HANDLE, to_hook: DWORD_PTR,
    f: DWORD_PTR, len: usize) {
    use std::mem::transmute;

    if len < 5 {
        panic!("Not enough space to inject");
    }

    let mut current_protection: DWORD = 0x0;

    unsafe {
        VirtualProtectEx(h_process, to_hook as LPVOID, len,
            PAGE_EXECUTE_READWRITE, &mut current_protection as PDWORD);
    }

    // just in case, we nop the space where we are injecting stuff
    let nops = vec![0x90; len];
    write_aob(h_process, to_hook, &nops);

    let _diff = f as i64 - to_hook as i64;
    let relative_address: DWORD = (_diff as DWORD - 5) as DWORD;
    let relative_aob: [u8; 4] = unsafe { transmute::<DWORD, [u8; 4]>(
        relative_address.to_le()) };

    let mut instructions: Vec<u8> = Vec::new();
    instructions.push(0xE8);
    instructions.extend_from_slice(&relative_aob[..]);

    let written = write_aob(h_process, to_hook, &instructions);
    assert_eq!(written, 5);

    unsafe {
        VirtualProtectEx(h_process, to_hook as LPVOID, len,
            current_protection, &mut current_protection as PDWORD);
    }
}

pub fn inject_shellcode(h_process: HANDLE, module_base_address: DWORD_PTR,
    entry_point: DWORD_PTR, instruction_size: usize, f: *const u8) -> DWORD_PTR {

    // calc the size of the function
    let mut f_len: isize = 0;
    loop {
	if unsafe { std::slice::from_raw_parts(f.offset(f_len), 4) } ==
	    b"\x90\x90\x90\x90" {
		break;
	}

	f_len += 1
    }

    // get the aob of the function
    let shellcode_bytes: &'static [u8] = unsafe {
	std::slice::from_raw_parts(f, f_len as usize) };

    let mut shellcode_space: DWORD_PTR = 0x0;
    // try to allocate near module
    for i in 1..1000 {
        let current_address = module_base_address - (0x1000 * i);
        shellcode_space = unsafe {
            VirtualAllocEx(h_process, current_address as LPVOID,
                0x1000 as usize, MEM_RESERVE | MEM_COMMIT,
                PAGE_EXECUTE_READWRITE) as DWORD_PTR };

        if shellcode_space != 0 { break; }
    }

    let written = write_aob(h_process, shellcode_space,
        &shellcode_bytes.to_vec());
    assert_eq!(written, f_len as usize,
        "The size of the injection doesnt match");

    let module_injection_address = module_base_address + entry_point;
    hook_function(h_process, module_injection_address, shellcode_space, instruction_size);

    shellcode_space
}
