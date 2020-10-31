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

// The function that will receive the detouring (for example written in
// assembly)
extern "C" {
  static my_function_in_assembly: u8
  // The assembly function needs to have an ending label where
  // you align the 16 bytes
  static my_function_in_assembly_end: u8
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
    // Find the base address of the process to hack
    let proc_inf = ProcessInfo::new("RDR2.exe")?;

    // Search for a specific AOB
    let coord_range_addr = scan_aob(
        proc_inf.addr,
        proc_inf.size,
        // aobscan with pattern matching
        generate_aob_pattern![
            0xE8, _, 0xFF, 0xAA, 0xBB
        ],
        5, // size of the AOB
    ).map_err(|_| "Couldn't find the coordinates limiter AOB")?;

    // nop those bytes
    write_aob(coord_range_addr, &vec![0x90; 5]);

    let old_function = scan_aob(
        proc_inf.addr,
        proc_inf.size,
        // aobscan with pattern matching
        generate_aob_pattern![
            0xAA, _, _, 0xBB, 0xCC
        ],
        5, // size of the AOB
    ).map_err(|_| "Couldn't find the coordinates limiter AOB")?;

    unsafe { 
        hook_function(
            old_function,
            &my_function_in_assembly as *mut u8 as usize,
            &my_function_in_assembly_end as *mut u8 as usize,
            16, // space of the injection (12 bytes minimum since it uses far jmp)
        );
    }

    Ok(())
}

// This will generate the DllMain required to create a DLL in Windows.
memory_rs::main_dll!(wrapper);
```
