#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

use windows_sys::Win32::{Foundation::HMODULE, System::LibraryLoader::GetModuleHandleA};
mod FixedDateFormat;
mod FixedDriftScore;
mod ScopedUnprotect;
mod macros;
mod win_types;

#[unsafe(no_mangle)]
pub extern "C" fn OnInitializeHook() {
    unsafe {
        // Was const?
        let hModule: HMODULE = GetModuleHandleA(std::ptr::null());
        let Protect = ScopedUnprotect::unprotect_section_or_full_module(hModule, c".text".as_ptr());

        // Original comment:
        // Fix the drift score magazine taking a best lap score and dividing it by laps.
        // Also fix the high score in the menu displaying style points instead of the full score.
    }
}
