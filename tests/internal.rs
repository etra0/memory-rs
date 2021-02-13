use memory_rs::internal::injections::*;
use memory_rs::internal::memory::*;

static TO_BE_WRITTEN: [u8; 8] =
    [0xDE, 0xAD, 0xBE, 0xEF, 0xC0, 0xFF, 0xEE, 0x00];
static SEARCH_ARRAY: [u8; 10] =
    [0xDE, 0xAD, 0xBE, 0xEF, 0xC0, 0xFF, 0xEE, 0xC0, 0xCA, 0xDA];

#[test]
fn test_write_aob() {
    let new_array = vec![0xAA, 0xBB, 0xCC];
    let pointer = TO_BE_WRITTEN.as_ptr() as *const u8 as usize;

    unsafe { write_aob(pointer, &new_array).unwrap() };

    let result_array: [u8; 8] =
        [0xAA, 0xBB, 0xCC, 0xEF, 0xC0, 0xFF, 0xEE, 0x00];

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
fn test_scan_aob_all_matches() {
    let p: [u8; 10] =
        [0xAA, 0xBB, 0xCC, 0xDD, 0xAA, 0xFF, 0xCC, 0xAA, 0xEE, 0xCC];
    let arr_len = p.len();
    let (size, func) = memory_rs::generate_aob_pattern![0xAA, _, 0xCC];

    let addr =
        scan_aob_all_matches(p.as_ptr() as usize, arr_len, func, size).unwrap();

    // Recreate the original array since the pattern repeats every 3 bytes.
    let mut v = vec![];
    for a in addr {
        let a_ = unsafe { std::slice::from_raw_parts(a as *const u8, 3) };
        v.extend_from_slice(a_);
    }

    assert_eq!(
        &[0xAA, 0xBB, 0xCC, 0xAA, 0xFF, 0xCC, 0xAA, 0xEE, 0xCC],
        &v[..]
    );
}

#[test]
fn test_scan_aob_not_valid_memory() {
    use memory_rs::error;

    let p = 0x12345678;
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
    let len = 0xFFFFF;
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

    let mut det = Detour::new(original_function, 14, new_function, None);
    det.inject();

    let res = dummy_function();

    assert_eq!(res, "I'm an imposter!");

    det.remove_injection();

    let res = dummy_function();

    assert_eq!(res, "I'm the original function");
}

#[test]
fn test_drop_injection() {
    #[allow(non_upper_case_globals)]
    static arr: [u8; 5] = [0xE7, 0x9A, 0x00, 0x9A, 0x9B];

    {
        let mut injection =
            Injection::new(arr.as_ptr() as usize + 1, vec![0xAA, 0xBB, 0xCC]);

        assert_eq!(&arr, &[0xE7, 0x9A, 0x00, 0x9A, 0x9B]);

        injection.inject();

        assert_eq!(&arr, &[0xE7, 0xAA, 0xBB, 0xCC, 0x9B]);
    }

    assert_eq!(&arr, &[0xE7, 0x9A, 0x00, 0x9A, 0x9B]);
}

#[test]
fn test_scan_aligned_value() {
    let vals: [u32; 4] = [0xC0FFEE, 0x1337, 0xB00BA, 0xC0FFEE];

    let result = scan_aligned_value(
        vals.as_ptr() as *const u32 as usize,
        16,
        0xC0FFEE_u32,
    )
    .unwrap();

    assert_eq!(
        &result,
        &[
            (&vals[0]) as *const u32 as usize,
            (&vals[3]) as *const u32 as usize
        ]
    );
}

// macro_rules! doctest {
//     ($x:expr) => {
//         #[doc = $x]
//         extern {}
//     }
// }
// doctest!(include_str!("../README.md"));
