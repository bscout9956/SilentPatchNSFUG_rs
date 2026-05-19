use std::{arch::naked_asm, mem};

use crate::{NAKED_FUNC_EPILOG, NAKED_FUNC_PROLOG};

#[repr(C)]
struct RacingCar {
    // Not using char for field_0 as char in Rust is Unicode (4 bytes)
    pub field_0: [u8; 224],
    pub m_lapScores: [f32; 11],
    pub gap10C: [u8; 52],
}

impl RacingCar {
    // We only define this, this isn't meant to be called. It's a compile time check.
    fn _assert_size() {
        const {
            assert!(
                mem::size_of::<RacingCar>() == 0x140,
                "Wrong size: RacingCar"
            )
        };
    }

    pub fn GetTotalLapScore(&self) -> f32 {
        let mut total_score = 0.0;

        for lap_score in self.m_lapScores {
            total_score += lap_score;
        }
        total_score
    }
}

#[unsafe(no_mangle)]
#[unsafe(naked)]
pub unsafe extern "cdecl" fn GetTotalLapScore_Hook() -> f32 {
    naked_asm!(
        NAKED_FUNC_PROLOG!("8"),

        "mov [ebp - 4], eax",
        "mov ecx, [ebp - 4]",
        "call {get_score_fn}",

        NAKED_FUNC_EPILOG!(),

        get_score_fn = sym RacingCar::GetTotalLapScore,
    )
}

// Will I need the type?
type orgCheckForMagazineTaskCompletion_BeatingPresetDriftScore = fn();
static mut orgCheckForMagazineTaskCompletion_BeatingPresetDriftScore: *const () = std::ptr::null();

#[unsafe(no_mangle)]
#[unsafe(naked)]
pub unsafe extern "cdecl" fn CheckForMagazineTaskCompletion_BeatingPresetDriftScore_Hook() {
    naked_asm!(
        // Original comment: Convert the value in eax from float to int
        // movss prevents this from compiling, I'm not sure what to do, even the LLM says movd is the correct choice lol
        "movd xmm0, eax",
        "cvttss2si eax, xmm0",
        "jmp dword ptr [{x}]",
        x = sym orgCheckForMagazineTaskCompletion_BeatingPresetDriftScore,
    )
}
