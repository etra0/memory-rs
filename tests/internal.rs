use memory_rs::internal::memory::*;

static TO_BE_WRITTEN: [u8; 8] = [0xDE, 0xAD, 0xBE, 0xEF, 0xC0, 0xFF, 0xEE, 0x00];
static SEARCH_ARRAY: [u8; 10] = [0xDE, 0xAD, 0xBE, 0xEF, 0xC0, 0xFF, 0xEE, 0xC0, 0xCA, 0xDA];

#[test]
fn test_write_aob() {
    let new_array = vec![0xAA, 0xBB, 0xCC];
    let pointer = TO_BE_WRITTEN.as_ptr() as *const u8 as usize;

    unsafe { write_aob(pointer, &new_array).unwrap() };

    let result_array: [u8; 8] = [0xAA, 0xBB, 0xCC, 0xEF, 0xC0, 0xFF, 0xEE, 0x00];

    let equality = TO_BE_WRITTEN.iter().eq(result_array.iter());

    assert!(
        equality,
        "Left: {:x?}, Right: {:x?}",
        &TO_BE_WRITTEN[..],
        &result_array[..]
    );
}

#[test]
fn test_generate_aob_pattern() {
    let (size, func) = memory_rs::generate_aob_pattern![0xAA, _, 0xBB, _];
    let arr = [0xAA, 0xBB, 0xBB, 0xEE];

    assert_eq!(size, 4);
    assert!(func(&arr));
}

#[test]
fn test_scan_aob() {
    let p = &SEARCH_ARRAY as *const u8 as usize;
    let arr_len = SEARCH_ARRAY.len();
    let (size, func) = memory_rs::generate_aob_pattern![0xFF, _, 0xC0];

    let addr = scan_aob(p, arr_len, func, size).unwrap();

    assert_eq!(Some(p + 5), addr);
}

#[test]
fn test_scan_aob_not_valid_memory() {
    use memory_rs::error;

    let p = 0x1234_5678;
    let len = 0xFFFF;
    let (size, func) = memory_rs::generate_aob_pattern![0xAA, 0xBB, 0xCC, 0xDD];

    let addr = scan_aob(p, len, func, size);
    
    if let Err(e) = addr {
        let e: error::Error = e.downcast().unwrap();
        assert_eq!(e.kind(), error::ErrorType::Internal);
        assert_eq!(e.msg(), "The region to scan is invalid".to_string());
    } else {
        panic!("Should have get an error");
    }
}

#[test]
fn test_scan_aob_out_of_bounds() {
    use memory_rs::error;

    let p = &SEARCH_ARRAY as *const u8 as usize;
    let len = 0xFFFFFFFFFF;
    let (size, func) = memory_rs::generate_aob_pattern![0xAA, 0xBB, 0xCC, 0xDD];

    let addr = scan_aob(p, len, func, size);
    
    if let Err(e) = addr {
        let e: error::Error = e.downcast().unwrap();
        assert_eq!(e.kind(), error::ErrorType::Internal);
        assert_eq!(e.msg(), "The region to scan is invalid".to_string());
    } else {
        panic!("Should have get an error");
    }
}

fn dummy_function() -> &'static str {
    println!("I'm `dummy_function`");

    return "I'm the original function";
}

fn injected_function() -> &'static str {
    println!("I'm `injected_function`");
    return "I'm an imposter!";
}

#[test]
fn test_injection() {
    let original_function = dummy_function as *mut u8 as usize;
    let new_function = injected_function as *mut u8 as usize;

    let res = dummy_function();

    assert_eq!("I'm the original function", res);

    unsafe { hook_function(original_function, new_function, None, 14).unwrap() };

    let res = dummy_function();

    assert_eq!(res, "I'm an imposter!");
}
