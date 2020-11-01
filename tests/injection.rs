#![cfg_attr(feature = "test_nightly", feature(asm))]
use memory_rs::memory::internal::*;

#[cfg(feature = "test_nightly")]
fn dummy_function() -> &'static str {
    println!("I'm `dummy_function`, I shouldn't be printed");

    return "I'm the original function";
}

#[allow(unreachable_code)]
#[cfg(feature = "test_nightly")]
fn injected_function() -> &'static str {
    println!("Im injected_function, the right function");
    return "I'm an imposter!";
    unsafe {
        asm!(
            "function_end:
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            nop
            "
        );
    };
}

#[test]
#[cfg(feature = "test_nightly")]
fn test_injection() {
    let original_function = dummy_function as *mut u8 as usize;
    let new_function = injected_function as *mut u8 as usize;

    let (size, func) = memory_rs::generate_aob_pattern![
        0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC
    ];

    let addr = scan_aob(new_function, 300, func, size).unwrap();

    let res = dummy_function();

    assert_eq!("I'm the original function", res);

    hook_function(original_function, new_function, addr, 14);

    let res = dummy_function();

    assert_eq!(res, "I'm an imposter!");
}
