#[cfg(not(target_os = "windows"))]
fn panic() {
    compile_error!("This library only supports Windows for now");
}

#[macro_use]
#[cfg(target_os = "windows")]
pub mod internal;

#[cfg(target_os = "windows")]
pub mod error;

#[cfg(target_os = "windows")]
pub mod external;

