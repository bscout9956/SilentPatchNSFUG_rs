#![allow(unsafe_op_in_unsafe_fn)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(unused)]

use std::ffi::{c_float, c_void};
use std::panic;
use windows_sys::Win32::Foundation::HWND;
#[cfg(feature = "debugprint")]
use windows_sys::Win32::System::Console::AllocConsole;
use windows_sys::Win32::UI::WindowsAndMessaging::{MB_OK, MessageBoxA, MessageBoxW};
use windows_sys::Win32::{Foundation::HMODULE, System::LibraryLoader::GetModuleHandleA};

mod FixedDateFormat;
mod FixedDriftScore;
mod HookInit;
mod MemoryMgr;
mod Patterns;
mod ScopedUnprotect;
mod macros;
mod win_types;

use crate::FixedDateFormat::pGetDateFormatA_SilentPatch;
use crate::FixedDriftScore::{
    CheckForMagazineTaskCompletion_BeatingPresetDriftScore_Hook,
    orgCheckForMagazineTaskCompletion_BeatingPresetDriftScore,
};
use crate::Patterns::txn::get_pattern;
use FixedDriftScore::GetTotalLapScore_Hook;
use MemoryMgr::Memory;
use Patterns::{TxnPattern, txn};

#[unsafe(no_mangle)]
pub unsafe extern "system" fn OnInitializeHook() {
    let drift_score_hook_result = panic::catch_unwind(|| {
        unsafe {
            #[cfg(feature = "debugprint")]
            {
                AllocConsole();
            }
            let hModule: HMODULE = GetModuleHandleA(std::ptr::null());
            let _Protect =
                ScopedUnprotect::unprotect_section_or_full_module(hModule, c".text".as_ptr());

            // Original comment:
            // Fix the drift score magazine taking a best lap score and dividing it by laps.
            // Also fix the high score in the menu displaying style points instead of the full score.
            let getBestLapScore = TxnPattern::new(b"E8 ? ? ? ? E8 ? ? ? ? 89 86").get_one();
            let beatingPresetDriftScore: *mut c_void =
                txn::get_pattern(b"57 E8 ? ? ? ? 83 C4 08 E8", 1);

            Memory::InjectHook(
                getBestLapScore.get::<c_void>(0),
                GetTotalLapScore_Hook as *const (),
            ); // Always cast to *const (), needs fixing later

            Memory::Nop(getBestLapScore.get::<c_void>(5), 5);
            Memory::PatchAddressList(
                getBestLapScore.get::<c_void>(10),
                &[0xD9u8, 0x9Eu8, 0xC4u8, 0x00u8, 0x00u8, 0x00u8],
            );

            Memory::InterceptCall(
                beatingPresetDriftScore,
                mut_ptr!(orgCheckForMagazineTaskCompletion_BeatingPresetDriftScore),
                CheckForMagazineTaskCompletion_BeatingPresetDriftScore_Hook as *const (),
            );

            let mut stylePointsLoad = TxnPattern::new(b"D9 85 BC 00 00 00").count(2);
            let stylePointsOffset = [
                get_pattern(b"D8 9D BC 00 00 00", 2),
                stylePointsLoad.get(0).get::<c_void>(2),
                stylePointsLoad.get(1).get::<c_void>(2),
            ];

            // Typed as c_float, is it tho?
            let addHalfPtr: *mut c_float =
                get_pattern(b"D8 05 ? ? ? ? E8 ? ? ? ? 5F 89 46 ? 8A 44 24", 2);

            for addr in stylePointsOffset {
                Memory::PatchAddressValue(addr, 0xC4);
            }

            static fZero: c_float = 0.0f32;
            Memory::PatchAddressValue(addHalfPtr, &fZero as *const f32);
        }
    });

    if drift_score_hook_result.is_err() {
        #[cfg(feature = "debugprint")]
        {
            println!("Panic detected, launching MSGB Box A");
        }
    }

}
