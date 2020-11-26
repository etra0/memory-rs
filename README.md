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
use memory_rs::memory::internal::{scan_aob, write_aob, hook_function};
use memory_rs::memory::process_info::ProcessInfo;

// Assuming you have a function in assembly where you want to jump to
// to change code's behavior
extern "C" {
  static my_function_in_assembly: u8;
  static my_function_in_assembly_jmp_back: u8;
}


// function wrapper to be called by DllMain
pub unsafe extern "system" fn wrapper(lib: winapi::shared::minwindef::LPVOID) -> u32 {
  // ...
  match patch() {
    Ok(_) => println!("Everything is OK"),
    Err(e) => println!("Error: {}", e)
  };

  0
}

fn patch() -> Result<(), Box<dyn std::error::Error>> {
    // Get some basic information of the process (like base address and binary
    // size)
    let proc_inf = ProcessInfo::new("RDR2.exe")?;
    Ok(())

    let enable_hots_addr = {
        // Scan for a pattern on the game's memory to get the address of
        // where you want to do some injections
        let (size, func) = generate_aob_pattern![
            0xFF, 0x90, _, 0x01, 0x00, 0x00, 0x84, 0xC0, 0x74, 0x05, 0x4D,
            0x85, 0xE4
        ];
        scan_aob(proc_inf.addr, proc_inf.size, func, size)?
            .ok_or("Couldn't find enable_hots_addr")? - 0xA
    };

    // We use Detour since it's scope sensitive (if it fails it will deinject
    // automatically
    let enable_hots_det = Detour::new(
        enable_hots_addr,
        &my_function_in_assembly as *const u8 as usize,
        Some(&my_function_in_assembly_jmp_back as *const u8 as usize)
        16)

    enable_hots_det.inject();

    let black_bars_addr = {
        let (size, func) = generate_aob_pattern![
            0x0F, 0x86, _, _, 0xAA, 0xBB
        ];
        scan_aob(proc_inf.addr, proc_inf.size, func, size)?
            .ok_or("Couldn't find black_bars_addr")?
    };

    // nop 5 bytes, when Injection goes out of scope, it will reinject
    // the original bytes.
    let remove_black_bars = Injection::new(black_bars_addr, [0x90; 5]);

    remove_black_bars.inject();

    loop {}
}

// This will generate the DllMain required to create a DLL in Windows.
memory_rs::main_dll!(wrapper);
```
