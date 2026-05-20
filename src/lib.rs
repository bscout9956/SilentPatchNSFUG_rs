#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

use std::ffi::c_void;

use windows_sys::Win32::{Foundation::HMODULE, System::LibraryLoader::GetModuleHandleA};

mod FixedDateFormat;
mod FixedDriftScore;
mod Patterns;
mod ScopedUnprotect;
mod macros;
mod win_types;

use Patterns::txn;

use crate::FixedDriftScore::GetTotalLapScore_Hook;

#[unsafe(no_mangle)]
pub extern "C" fn OnInitializeHook() {
    unsafe {
        // Was const?
        let hModule: HMODULE = GetModuleHandleA(std::ptr::null());
        let Protect = ScopedUnprotect::unprotect_section_or_full_module(hModule, c".text".as_ptr());

        // Original comment:
        // Fix the drift score magazine taking a best lap score and dividing it by laps.
        // Also fix the high score in the menu displaying style points instead of the full score.

        let getBestLapScore = txn::Pattern::new(b"E8 ? ? ? ? E8 ? ? ? ? 89 86").get_one();
        let beatingPresetDriftScore: *mut c_void =
            txn::get_pattern(b"57 E8 ? ? ? ? 83 C4 08 E8", 1);

        // InjectHook(getBestLapScore.get::<c_void>(), GetTotalLapScore_Hook);
    }
}
