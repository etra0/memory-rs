# memory-rs
**This is a work in progress.**

A library written to facilitate game modding with Rust.

This library has the basics for making code injections, aobscan and code
patching.

# Usage
The example is a little bit extensive but hopefully makes it clear on how
to use it.

```rust
use memory_rs::generate_aob_pattern;
use memory_rs::internal::process_info::ProcessInfo;
use memory_rs::internal::injections::*;

memory_rs::scoped_no_mangle! {
    // In reality, this `my_function_in_assembly` should be an extern to  an
    // asm label which exposes the start of a shellcode, that you'd inject in
    // the future.
    my_function_in_assembly: u8 =  0x0;
    my_function_in_assembly_jmp_back_addr: usize = 0x0;
}


// function wrapper to be called by DllMain
pub unsafe extern "system" fn wrapper(lib: winapi::shared::minwindef::LPVOID) -> u32 {
  // ...
  match patch() {
    Ok(_) => println!("Everything is OK"),
    Err(e) => println!("Error: {}", e),
  };

  0
}

fn patch() -> Result<(), Box<dyn std::error::Error>> {
    // Get some basic information of the process (like base address and binary
    // size)
    let proc_inf = ProcessInfo::new(Some("RDR2.exe"))?;

    let mut enable_hots_addr = {
        // Scan for a pattern on the game's memory to get the address of
        // where you want to do some injections
        let memory_pattern = generate_aob_pattern![
            0xFF, 0x90, _, 0x01, 0x00, 0x00, 0x84, 0xC0, 0x74, 0x05, 0x4D,
            0x85, 0xE4
        ];
        let region = &proc_inf.region;
        region.scan_aob(&memory_pattern)?
            .ok_or("Couldn't find enable_hots_addr")? - 0xA
    };

    // We use Detour since it's scope sensitive (if it fails it will deinject
    // automatically
    let mut enable_hots_det = unsafe { Detour::new(
        enable_hots_addr,
        16,
        &my_function_in_assembly as *const u8 as usize,
        Some(&mut my_function_in_assembly_jmp_back_addr))
    };

    enable_hots_det.inject();

    let black_bars_addr = {
        let memory_pattern = generate_aob_pattern![
            0x0F, 0x86, _, _, 0xAA, 0xBB
        ];
        let region = &proc_inf.region;
        region.scan_aob(&memory_pattern)?
            .ok_or("Couldn't find black_bars_addr")?
    };

    // nop 5 bytes, when Injection goes out of scope, it will reinject
    // the original bytes.
    let mut remove_black_bars = Injection::new(black_bars_addr, vec![0x90; 5]);

    remove_black_bars.inject();

    loop {}
}

// This will generate the DllMain required to create a DLL in Windows.
memory_rs::main_dll!(wrapper);
```
