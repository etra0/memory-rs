/// Macro that creates the MainDLL function.
/// This function has a special signature that needed by WinAPI to
/// create a DLL.
#[macro_export]
macro_rules! main_dll {
    ($func:expr) => {
        #[no_mangle]
        #[allow(non_snake_case)]
        pub extern "system" fn DllMain(
            lib: winapi::shared::minwindef::HINSTANCE,
            reason: u32,
            _: usize,
        ) -> u32 {
            unsafe {
                match reason {
                    winapi::um::winnt::DLL_PROCESS_ATTACH => {
                        winapi::um::processthreadsapi::CreateThread(
                            std::ptr::null_mut(),
                            0,
                            Some($func),
                            lib as winapi::shared::minwindef::LPVOID,
                            0,
                            std::ptr::null_mut(),
                        );
                    }
                    _ => (),
                };
            }

            return true as u32;
        }
    };
}

/// Macro created by t0mstone
/// You can check the original source at
/// https://github.com/T0mstone/tlibs/blob/master/some_macros/src/lib.rs#L23-L29
#[macro_export]
macro_rules! count_args {
    (@one $($t:tt)*) => { 1 };
    ($(($($x:tt)*)),*$(,)?) => {
        0 $(+ $crate::count_args!(@one $($x)*))*
    };
}

/// Map winapi error to lib error.
#[macro_export]
macro_rules! try_winapi {
    ($call:expr) => {{
        let res = $call;
        if res == 0 {
            let msg = format!(
                "{} failed with error code {}",
                std::stringify!($call),
                std::io::Error::last_os_error()
            );
            return Err($crate::error::Error::new($crate::error::ErrorType::WinAPI, msg).into());
        }
    }};
}

/// Wrap a function to a lambda which returns a Result<_, Error>
/// depending of the condition.
/// You should use it like
/// wrap_winapi!(MyFunction(), MyCondition) where
/// MyCondition **must** start with an x and the comparison.
/// For example
/// ```
/// # use memory_rs::wrap_winapi;
/// // This should fail since we are saying that
/// // when the return value equals to 0 it's an error.
/// assert!(wrap_winapi!((|| 0)(), x == 0).is_err());
/// ```
#[macro_export]
macro_rules! wrap_winapi {
    ($call:expr, x $($tt:tt)*) => {
        (|| -> Result<_, $crate::error::Error> {
            let res = $call;
            let x = res as usize;
            if x $($tt)* {
                let msg = format!(
                    "{} failed with error `{}`",
                    std::stringify!($call),
                    std::io::Error::last_os_error()
                );
                return Err($crate::error::Error::new(
                    $crate::error::ErrorType::WinAPI,
                    msg,
                )
                .into());
            }
            Ok(res)
        })()
    };
}

/// Scoped no mangle to avoid repetition
#[macro_export]
macro_rules! scoped_no_mangle {
    ($($name:ident: $v:ty = $val:expr;)*) => {
        $(#[no_mangle] pub static mut $name: $v = $val;)*
    }
}

/// Returns a MemoryPattern struct
#[macro_export]
macro_rules! generate_aob_pattern {
    [$($val:tt),* ] => {
        $crate::internal::memory::MemoryPattern::new(
            $crate::count_args!($(($val)),*),
        |slice: &[u8]| -> bool {
            matches!(slice, [$($val),*])
        }
        )
    }
}
